use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{Mode, OFlags};

use crate::error::{Error, Result};

const MAX_READ: u64 = 512 * 1024;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicPoint {
    AfterTmpWrite,
    AfterFsyncFile,
    AfterRename,
    AfterFsyncDir,
}

/// An existing directory on a read-only mount is left as-is; the executor mounts `releases/` and `control/` read-only.
pub fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    let already = path.is_dir();
    if !already {
        fs::create_dir_all(path)?;
    }
    match set_mode(path, mode) {
        Ok(()) => Ok(()),
        Err(Error::Io(err)) if already && matches!(err.raw_os_error(), Some(1 | 30)) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Opens without following a final symlink or blocking on a FIFO, and requires a regular file.
pub fn open_regular(path: &Path) -> Result<(File, fs::Metadata)> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::msg(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok((file, meta))
}

pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let (file, meta) = open_regular(path)?;
    if meta.len() > max {
        return Err(Error::TooLarge {
            len: meta.len(),
            max,
        });
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(Error::TooLarge {
            len: bytes.len() as u64,
            max,
        });
    }
    Ok(bytes)
}

pub fn read_json_limited(path: &Path) -> Result<Vec<u8>> {
    read_limited(path, MAX_READ)
}

/// Files created without an explicit mode become `0640` and directories `0750`.
pub fn set_tight_umask() {
    #[cfg(unix)]
    {
        let _ = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o027));
    }
}

pub fn write_atomic(dest: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    write_atomic_inner(dest, bytes, mode, None, true)
}

/// Errors at `fail_at` without rolling back a completed rename, to prove a crash never tears the destination.
pub fn write_atomic_failpoint(
    dest: &Path,
    bytes: &[u8],
    mode: u32,
    fail_at: AtomicPoint,
) -> Result<()> {
    write_atomic_inner(dest, bytes, mode, Some(fail_at), false)
}

fn write_atomic_inner(
    dest: &Path,
    bytes: &[u8],
    mode: u32,
    fail_at: Option<AtomicPoint>,
    cleanup_tmp: bool,
) -> Result<()> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(Error::msg(format!(
            "atomic write parent missing: {}",
            parent.display()
        )));
    }
    let name = dest
        .file_name()
        .ok_or_else(|| Error::msg("atomic write needs a file name"))?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        ".{}.tmp.{}.{:x}",
        name.to_string_lossy(),
        std::process::id(),
        seq
    );
    let tmp_path = parent.join(&tmp_name);

    let write_result = (|| {
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(bytes)?;
            if fail_at == Some(AtomicPoint::AfterTmpWrite) {
                return Err(Error::msg("injected failure after tmp write"));
            }
            file.sync_all()?;
            set_mode(&tmp_path, mode)?;
            file.sync_all()?;
            if fail_at == Some(AtomicPoint::AfterFsyncFile) {
                return Err(Error::msg("injected failure after fsync"));
            }
        }
        // Test seam: the temp file is durable and `dest` is still the previous bytes.
        hold_during_desired_write(dest);
        fs::rename(&tmp_path, dest)?;
        if fail_at == Some(AtomicPoint::AfterRename) {
            return Err(Error::msg("injected failure after rename"));
        }
        File::open(parent)?.sync_all()?;
        if fail_at == Some(AtomicPoint::AfterFsyncDir) {
            return Err(Error::msg("injected failure after dir fsync"));
        }
        Ok(())
    })();

    if write_result.is_err() && cleanup_tmp && tmp_path.exists() && dest != tmp_path {
        // Only remove the temp file when rename has not consumed it.
        if tmp_path.is_file() && !dest.exists() || (dest.exists() && tmp_path.exists()) {
            let _ = fs::remove_file(&tmp_path);
        }
    }
    write_result.map_err(|err| match err {
        Error::Io(io) => Error::Io(std::io::Error::new(
            io.kind(),
            format!("atomic write of {}: {io}", dest.display()),
        )),
        other => other,
    })
}

fn hold_during_desired_write(dest: &Path) {
    if dest.file_name().and_then(|name| name.to_str()) != Some("desired.json") {
        return;
    }
    let Ok(raw) = std::env::var("CITE_FAULT_HOLD_DURING_ATOMIC_MS") else {
        return;
    };
    let Ok(ms) = raw.parse::<u64>() else {
        return;
    };
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn tight_umask_is_027_and_explicit_mode_wins() {
        let previous = rustix::process::umask(rustix::fs::Mode::empty());
        set_tight_umask();
        let applied = rustix::process::umask(previous);
        assert_eq!(applied.bits() & 0o777, 0o027);

        let dir = tempdir().unwrap();
        let dest = dir.path().join("state.json");
        write_atomic(&dest, b"{}", 0o640).unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn atomic_replace_is_old_or_new_at_every_failpoint() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("desired.json");
        write_atomic(&dest, b"OLD", 0o644).unwrap();
        for point in [
            AtomicPoint::AfterTmpWrite,
            AtomicPoint::AfterFsyncFile,
            AtomicPoint::AfterRename,
            AtomicPoint::AfterFsyncDir,
        ] {
            let err = write_atomic_failpoint(&dest, b"NEW", 0o644, point);
            assert!(err.is_err(), "{point:?}");
            let got = fs::read(&dest).unwrap();
            assert!(
                got == b"OLD" || got == b"NEW",
                "{point:?} left torn bytes {got:?}"
            );
            if matches!(
                point,
                AtomicPoint::AfterTmpWrite | AtomicPoint::AfterFsyncFile
            ) {
                assert_eq!(got, b"OLD");
            } else {
                assert_eq!(got, b"NEW");
            }
            write_atomic(&dest, b"OLD", 0o644).unwrap();
        }
        write_atomic(&dest, b"NEW", 0o644).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"NEW");
    }

    #[test]
    fn read_limited_rejects_oversize() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("big");
        fs::write(&path, vec![1u8; 64]).unwrap();
        let err = read_limited(&path, 16).unwrap_err();
        assert!(matches!(err, Error::TooLarge { .. }));
    }

    #[test]
    fn read_limited_refuses_symlinks_devices_and_fifos() {
        let dir = tempdir().unwrap();
        let link = dir.path().join("status.json");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_limited(&link, 1024).is_err());
        assert!(read_limited(Path::new("/dev/zero"), 1024).is_err());

        let real = dir.path().join("real");
        fs::write(&real, b"{}").unwrap();
        let to_file = dir.path().join("to_file");
        std::os::unix::fs::symlink(&real, &to_file).unwrap();
        assert!(read_limited(&to_file, 1024).is_err());
        assert_eq!(read_limited(&real, 1024).unwrap(), b"{}");

        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        assert!(read_limited(&fifo, 1024).is_err());
    }
}
