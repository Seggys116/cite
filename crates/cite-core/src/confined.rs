use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};

use crate::error::{Error, Result};

/// Leaves room under the usual 255 byte limit for the temp-file decoration added around a name.
pub const NAME_MAX: usize = 200;

/// Modification seconds, nanoseconds, size and inode: changes whenever the file is replaced or rewritten.
pub type FileKey = (i64, i64, u64, u64);

/// A single path component: never empty, `.`, `..`, over-long, or containing a separator or NUL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName(OsString);

impl FileName {
    pub fn new(raw: impl AsRef<OsStr>) -> Result<Self> {
        let raw = raw.as_ref();
        let bytes = raw.as_bytes();
        let bad = bytes.is_empty()
            || bytes.len() > NAME_MAX
            || bytes == b"."
            || bytes == b".."
            || bytes.iter().any(|b| matches!(b, b'/' | 0));
        if bad {
            return Err(Error::msg(format!("invalid file name {raw:?}")));
        }
        Ok(Self(raw.to_os_string()))
    }

    pub fn from_path_tail(path: &Path) -> Result<Self> {
        let tail = path
            .file_name()
            .ok_or_else(|| Error::msg(format!("{} has no file name", path.display())))?;
        Self::new(tail)
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    /// Built from an already validated name plus ASCII, so it cannot gain a separator.
    pub(crate) fn hidden_tmp(&self, pid: u32, seq: u64) -> Self {
        let mut bytes = Vec::with_capacity(self.0.len() + 40);
        bytes.push(b'.');
        bytes.extend_from_slice(self.0.as_bytes());
        bytes.extend_from_slice(format!(".tmp.{pid}.{seq:x}").as_bytes());
        Self(OsString::from_vec(bytes))
    }
}

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_string_lossy())
    }
}

/// An open directory whose operations take only validated single components, so no input can steer them elsewhere.
#[derive(Debug)]
pub struct TrustedDir {
    fd: OwnedFd,
}

impl TrustedDir {
    /// The one place an ambient path is used; the operator-chosen root may itself be a symlink.
    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { fd })
    }

    /// Splits a path into its containing directory handle and its validated final component.
    pub fn split(path: &Path) -> Result<(Self, FileName)> {
        let name = FileName::from_path_tail(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Ok((Self::open(parent)?, name))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }

    fn open_at(&self, name: &FileName, flags: OFlags, mode: u32) -> io::Result<File> {
        let fd = rustix::fs::openat(
            &self.fd,
            name.as_os_str(),
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode_bits(mode),
        )?;
        Ok(File::from(fd))
    }

    /// Opens without following a final symlink or blocking on a FIFO, and requires a regular file.
    pub fn open_regular(&self, name: &FileName) -> Result<(File, Metadata)> {
        let file = self.open_at(name, OFlags::RDONLY | OFlags::NONBLOCK, 0)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(Error::msg(format!("{name} is not a regular file")));
        }
        Ok((file, meta))
    }

    pub fn read_limited(&self, name: &FileName, max: u64) -> Result<Vec<u8>> {
        let (file, meta) = self.open_regular(name)?;
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

    /// Exclusive create, so a pre-planted file or symlink under the temp name is an error, not a target.
    pub fn create_new(&self, name: &FileName, mode: u32) -> io::Result<File> {
        self.open_at(name, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL, mode)
    }

    /// Takes an exclusive advisory lock that is held until the returned file is dropped.
    pub fn lock_file(&self, name: &FileName, mode: u32) -> io::Result<File> {
        let file = self.open_at(name, OFlags::WRONLY | OFlags::CREATE, mode)?;
        rustix::fs::flock(&file, FlockOperation::LockExclusive)?;
        Ok(file)
    }

    pub fn append(&self, name: &FileName, bytes: &[u8], mode: u32) -> io::Result<()> {
        let mut file =
            self.open_at(name, OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND, mode)?;
        file.write_all(bytes)
    }

    /// Size of the entry itself; a symlink is measured, never followed.
    pub fn len(&self, name: &FileName) -> io::Result<u64> {
        let st = rustix::fs::statat(&self.fd, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(convert(st.st_size))
    }

    pub fn key(&self, name: &FileName) -> Option<FileKey> {
        let st = rustix::fs::statat(&self.fd, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).ok()?;
        Some((
            convert(st.st_mtime),
            convert(st.st_mtime_nsec),
            convert(st.st_size),
            convert(st.st_ino),
        ))
    }

    pub fn rename(&self, from: &FileName, to: &FileName) -> io::Result<()> {
        rustix::fs::renameat(&self.fd, from.as_os_str(), &self.fd, to.as_os_str())?;
        Ok(())
    }

    pub fn unlink(&self, name: &FileName) -> io::Result<()> {
        rustix::fs::unlinkat(&self.fd, name.as_os_str(), AtFlags::empty())?;
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        rustix::fs::fsync(&self.fd)?;
        Ok(())
    }

    pub fn set_mode(&self, mode: u32) -> io::Result<()> {
        rustix::fs::fchmod(&self.fd, mode_bits(mode))?;
        Ok(())
    }
}

pub(crate) fn mode_bits(mode: u32) -> Mode {
    Mode::from_bits_truncate(convert(mode & 0o7777))
}

// Stat field widths differ between platforms; a value that does not fit becomes zero rather than wrapping.
fn convert<S: TryInto<D>, D: Default>(value: S) -> D {
    value.try_into().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn name(s: &str) -> FileName {
        FileName::new(s).unwrap()
    }

    #[test]
    fn file_name_rejects_traversal_separators_nul_empty_and_long() {
        for bad in ["", ".", "..", "a/b", "/abs", "../x", "x/..", "a\0b", "\0"] {
            assert!(FileName::new(bad).is_err(), "{bad:?}");
        }
        assert!(FileName::new(OsStr::from_bytes(b"a\xffb/c")).is_err());
        assert!(FileName::new("x".repeat(NAME_MAX + 1)).is_err());
        assert!(FileName::new("x".repeat(NAME_MAX)).is_ok());
        assert!(FileName::new("desired.json").is_ok());
        assert!(FileName::new("..hidden").is_ok());
        assert!(FileName::new(OsStr::from_bytes(b"caf\xe9")).is_ok());
    }

    #[test]
    fn from_path_tail_takes_only_the_last_component() {
        assert_eq!(
            FileName::from_path_tail(Path::new("/a/b/c.json")).unwrap(),
            name("c.json")
        );
        assert!(FileName::from_path_tail(Path::new("/a/b/..")).is_err());
        assert!(FileName::from_path_tail(Path::new("/")).is_err());
        assert!(FileName::from_path_tail(Path::new("")).is_err());
    }

    #[test]
    fn hidden_tmp_stays_a_single_component_within_limits() {
        let tmp = name(&"x".repeat(NAME_MAX)).hidden_tmp(u32::MAX, u64::MAX);
        assert!(tmp.as_os_str().len() <= 255);
        assert!(!tmp.as_os_str().as_bytes().contains(&b'/'));
        assert!(tmp.as_os_str().as_bytes().starts_with(b"."));
    }

    #[test]
    fn open_requires_an_existing_directory() {
        let dir = tempdir().unwrap();
        assert!(TrustedDir::open(&dir.path().join("missing")).is_err());
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(TrustedDir::open(&file).is_err());
        assert!(TrustedDir::open(dir.path()).is_ok());
    }

    #[test]
    fn split_rejects_paths_without_a_usable_tail() {
        let dir = tempdir().unwrap();
        assert!(TrustedDir::split(&dir.path().join("..")).is_err());
        assert!(TrustedDir::split(Path::new("/")).is_err());
        let (_, tail) = TrustedDir::split(&dir.path().join("ok.json")).unwrap();
        assert_eq!(tail, name("ok.json"));
    }

    #[test]
    fn reads_refuse_a_symlink_even_to_a_regular_file() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"top").unwrap();
        symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        let root = TrustedDir::open(dir.path()).unwrap();
        assert!(root.read_limited(&name("link"), 1024).is_err());
        assert!(root.open_regular(&name("link")).is_err());
    }

    #[test]
    fn create_new_lock_and_append_refuse_a_planted_symlink() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("victim");
        std::fs::write(&target, b"keep").unwrap();
        for link in ["tmp", "lock", "log"] {
            symlink(&target, dir.path().join(link)).unwrap();
        }
        let root = TrustedDir::open(dir.path()).unwrap();
        assert!(root.create_new(&name("tmp"), 0o600).is_err());
        assert!(root.lock_file(&name("lock"), 0o600).is_err());
        assert!(root.append(&name("log"), b"more", 0o600).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn create_new_applies_the_mode_and_refuses_an_existing_file() {
        let dir = tempdir().unwrap();
        let root = TrustedDir::open(dir.path()).unwrap();
        root.create_new(&name("a"), 0o600).unwrap();
        let mode = std::fs::metadata(dir.path().join("a"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(root.create_new(&name("a"), 0o600).is_err());
    }

    #[test]
    fn len_and_key_report_the_entry_and_track_changes() {
        let dir = tempdir().unwrap();
        let root = TrustedDir::open(dir.path()).unwrap();
        assert!(root.key(&name("f")).is_none());
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        assert_eq!(root.len(&name("f")).unwrap(), 3);
        let before = root.key(&name("f")).unwrap();
        std::fs::write(dir.path().join("f"), b"abcdef").unwrap();
        assert_ne!(root.key(&name("f")).unwrap(), before);
    }

    #[test]
    fn rename_and_unlink_stay_inside_the_directory() {
        let dir = tempdir().unwrap();
        let root = TrustedDir::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("a"), b"1").unwrap();
        root.rename(&name("a"), &name("b")).unwrap();
        assert!(!dir.path().join("a").exists());
        root.unlink(&name("b")).unwrap();
        assert!(root.unlink(&name("b")).is_err());
    }
}
