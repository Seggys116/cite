use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

const LOCK_MODE: u32 = 0o600;

// Modification time, size and inode: enough to notice that another process replaced the file.
pub type FileKey = (i64, i64, u64, u64);

pub fn file_key(path: &Path) -> Option<FileKey> {
    let meta = fs::symlink_metadata(path).ok()?;
    Some((meta.mtime(), meta.mtime_nsec(), meta.size(), meta.ino()))
}

fn lock_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    config_path.with_file_name(name)
}

// Advisory exclusive lock held for the life of the value; the CLI and the server take it around read-generation and write.
pub struct ConfigLock {
    _file: File,
}

impl ConfigLock {
    pub fn acquire(config_path: &Path) -> io::Result<Self> {
        if let Some(parent) = config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(LOCK_MODE)
            .open(lock_path(config_path))?;
        flock(&file, FlockOperation::LockExclusive).map_err(io::Error::from)?;
        Ok(Self { _file: file })
    }
}
