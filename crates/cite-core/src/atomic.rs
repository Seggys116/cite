use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::Mode;

use crate::confined::{FileName, TrustedDir, mode_bits};
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
    let applied = TrustedDir::open(path).and_then(|dir| dir.set_mode(mode));
    match applied {
        Ok(()) => Ok(()),
        Err(err) if already && matches!(err.raw_os_error(), Some(1 | 13 | 30)) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Opens without following a final symlink or blocking on a FIFO, and requires a regular file.
pub fn open_regular(path: &Path) -> Result<(File, fs::Metadata)> {
    let (dir, name) = TrustedDir::split(path).map_err(|e| at_path(e, path))?;
    dir.open_regular(&name).map_err(|e| at_path(e, path))
}

pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let (dir, name) = TrustedDir::split(path).map_err(|e| at_path(e, path))?;
    dir.read_limited(&name, max).map_err(|e| at_path(e, path))
}

// The handle-based calls only know a file name, so the path-based entry points put the full path back.
fn at_path(err: Error, path: &Path) -> Error {
    match err {
        Error::Io(io) => Error::Io(std::io::Error::new(
            io.kind(),
            format!("{}: {io}", path.display()),
        )),
        Error::Message(msg) => Error::Message(format!("{}: {msg}", path.display())),
        other => other,
    }
}

fn atomic_context(err: Error, what: &dyn std::fmt::Display) -> Error {
    match err {
        Error::Io(io) => Error::Io(std::io::Error::new(
            io.kind(),
            format!("atomic write of {what}: {io}"),
        )),
        other => other,
    }
}

pub fn read_json_limited(path: &Path) -> Result<Vec<u8>> {
    read_limited(path, MAX_READ)
}

/// Files created without an explicit mode become `0640` and directories `0750`.
pub fn set_tight_umask() {
    #[cfg(unix)]
    {
        let _ = rustix::process::umask(Mode::from_bits_truncate(0o027));
    }
}

pub fn write_atomic(dest: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let (dir, name) = split_dest(dest)?;
    write_atomic_inner(&dir, &name, bytes, mode, None, true)
        .map_err(|e| atomic_context(e, &dest.display()))
}

/// Errors at `fail_at` without rolling back a completed rename, to prove a crash never tears the destination.
pub fn write_atomic_failpoint(
    dest: &Path,
    bytes: &[u8],
    mode: u32,
    fail_at: AtomicPoint,
) -> Result<()> {
    let (dir, name) = split_dest(dest)?;
    write_atomic_inner(&dir, &name, bytes, mode, Some(fail_at), false)
        .map_err(|e| atomic_context(e, &dest.display()))
}

/// Same guarantees as `write_atomic`, for a directory handle and a name that are already validated.
pub fn write_atomic_in(dir: &TrustedDir, name: &FileName, bytes: &[u8], mode: u32) -> Result<()> {
    write_atomic_inner(dir, name, bytes, mode, None, true).map_err(|e| atomic_context(e, name))
}

fn split_dest(dest: &Path) -> Result<(TrustedDir, FileName)> {
    let name =
        FileName::from_path_tail(dest).map_err(|_| Error::msg("atomic write needs a file name"))?;
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = TrustedDir::open(parent).map_err(|err| {
        Error::msg(format!(
            "atomic write parent missing: {} ({err})",
            parent.display()
        ))
    })?;
    Ok((dir, name))
}

fn write_atomic_inner(
    dir: &TrustedDir,
    name: &FileName,
    bytes: &[u8],
    mode: u32,
    fail_at: Option<AtomicPoint>,
    cleanup_tmp: bool,
) -> Result<()> {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = name.hidden_tmp(std::process::id(), seq);

    let write_result = (|| {
        {
            let mut file = dir.create_new(&tmp, mode)?;
            file.write_all(bytes)?;
            if fail_at == Some(AtomicPoint::AfterTmpWrite) {
                return Err(Error::msg("injected failure after tmp write"));
            }
            file.sync_all()?;
            rustix::fs::fchmod(&file, mode_bits(mode)).map_err(std::io::Error::from)?;
            file.sync_all()?;
            if fail_at == Some(AtomicPoint::AfterFsyncFile) {
                return Err(Error::msg("injected failure after fsync"));
            }
        }
        // Test seam: the temp file is durable and `dest` is still the previous bytes.
        hold_during_desired_write(name);
        dir.rename(&tmp, name)?;
        if fail_at == Some(AtomicPoint::AfterRename) {
            return Err(Error::msg("injected failure after rename"));
        }
        dir.sync()?;
        if fail_at == Some(AtomicPoint::AfterFsyncDir) {
            return Err(Error::msg("injected failure after dir fsync"));
        }
        Ok(())
    })();

    if write_result.is_err() && cleanup_tmp {
        // The unique temp name is gone once the rename has consumed it, so a failed unlink is expected then.
        let _ = dir.unlink(&tmp);
    }
    write_result
}

fn hold_during_desired_write(name: &FileName) {
    if name.as_os_str() != "desired.json" {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
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
    fn tmp_file_is_created_with_requested_mode_under_open_umask() {
        let dir = tempdir().unwrap();
        let previous = rustix::process::umask(rustix::fs::Mode::empty());
        let path = dir.path().join("tmp-secret");
        let root = TrustedDir::open(dir.path()).unwrap();
        let opened = root.create_new(&FileName::new("tmp-secret").unwrap(), 0o600);
        rustix::process::umask(previous);
        opened.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
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
    fn write_atomic_refuses_traversal_empty_nul_and_long_names() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("sub");
        fs::create_dir(&base).unwrap();
        assert!(write_atomic(&base.join(".."), b"x", 0o600).is_err());
        assert!(write_atomic(Path::new("/"), b"x", 0o600).is_err());
        assert!(write_atomic(Path::new(""), b"x", 0o600).is_err());
        let nul = base.join(std::ffi::OsStr::from_bytes(b"a\0b"));
        assert!(write_atomic(&nul, b"x", 0o600).is_err());
        let long = base.join("x".repeat(crate::confined::NAME_MAX + 1));
        assert!(write_atomic(&long, b"x", 0o600).is_err());
        let missing = write_atomic(&base.join("missing/f"), b"x", 0o600).unwrap_err();
        assert!(missing.to_string().contains(&base.display().to_string()));
        let io_err = write_atomic(&base.join("nodir/f"), b"x", 0o600).unwrap_err();
        assert!(io_err.to_string().contains("nodir"));
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn write_atomic_replaces_a_symlink_instead_of_writing_through_it() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = dir.path().join("state.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        write_atomic(&link, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::read(&link).unwrap(), b"new");
        assert!(
            !fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn write_atomic_cleans_its_temp_file_on_failure() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("f.json");
        let (root, name) = TrustedDir::split(&dest).unwrap();
        let blocker = dir.path().join("f.json");
        fs::create_dir(&blocker).unwrap();
        assert!(write_atomic_in(&root, &name, b"x", 0o600).is_err());
        let left: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(left.len(), 1);
    }

    #[test]
    fn ensure_dir_sets_the_mode_and_tolerates_an_existing_directory() {
        let dir = tempdir().unwrap();
        let made = dir.path().join("a/b");
        ensure_dir(&made, 0o700).unwrap();
        let mode = fs::metadata(&made).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        ensure_dir(&made, 0o750).unwrap();
        let mode = fs::metadata(&made).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
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
        let refused = read_limited(&link, 1024).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains(&dir.path().display().to_string())
        );
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
