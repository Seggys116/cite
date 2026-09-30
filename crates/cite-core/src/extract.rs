use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::PermissionsExt;
use cap_std::fs::{Dir, OpenOptions, Permissions};
use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use crate::error::{Error, Result};
use crate::pack::normalized_mode;

#[derive(Debug, Clone)]
pub struct ExtractLimits {
    pub max_compressed_bytes: u64,
    pub max_extracted_bytes: u64,
    pub max_entries: u64,
    pub max_file_bytes: u64,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: 1024 * 1024 * 1024,
            max_extracted_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 300_000,
            max_file_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractReport {
    pub bytes: u64,
    pub file_count: u64,
}

struct CountingReader<R> {
    inner: R,
    count: u64,
    limit: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count = self.count.saturating_add(n as u64);
        if self.count > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed size limit exceeded",
            ));
        }
        Ok(n)
    }
}

/// Symlinks and hardlinks are kept only when their target stays inside `dest`.
pub fn extract_archive<R: Read>(
    reader: R,
    dest: &Path,
    limits: &ExtractLimits,
    strip_components: usize,
) -> Result<ExtractReport> {
    Dir::create_ambient_dir_all(dest, ambient_authority())?;
    let mut counter = CountingReader {
        inner: reader,
        count: 0,
        limit: limits.max_compressed_bytes,
    };
    let mut magic = [0u8; 2];
    let n = counter.read(&mut magic).map_err(map_io)?;
    let gzip = n == 2 && magic == [0x1f, 0x8b];
    let chained = io::Cursor::new(magic[..n].to_vec()).chain(counter);
    let report = if gzip {
        extract_tar(GzDecoder::new(chained), dest, limits, strip_components)?
    } else {
        extract_tar(chained, dest, limits, strip_components)?
    };
    let _ = std::fs::File::open(dest).and_then(|file| file.sync_all());
    Ok(report)
}

fn extract_tar<R: Read>(
    reader: R,
    dest: &Path,
    limits: &ExtractLimits,
    strip_components: usize,
) -> Result<ExtractReport> {
    let root = Dir::open_ambient_dir(dest, ambient_authority())?;
    let mut archive = Archive::new(reader);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);
    let mut entries = 0u64;
    let mut extracted = 0u64;
    let mut file_count = 0u64;
    for entry in archive.entries().map_err(map_io)? {
        let mut entry = entry.map_err(map_io)?;
        entries += 1;
        if entries > limits.max_entries {
            return Err(Error::TooLarge {
                len: entries,
                max: limits.max_entries,
            });
        }
        let raw = entry.path_bytes();
        let raw =
            std::str::from_utf8(&raw).map_err(|_| Error::Archive("path is not utf-8".into()))?;
        let Some(rel) = normalize_entry_path(raw, strip_components)? else {
            continue;
        };
        let kind = entry.header().entry_type();
        match kind {
            EntryType::Directory => {
                root.create_dir_all(&rel)?;
                root.set_permissions(&rel, Permissions::from_mode(0o755))?;
            }
            EntryType::Regular => {
                let declared = entry.header().size().map_err(map_io)?;
                if declared > limits.max_file_bytes
                    || extracted.saturating_add(declared) > limits.max_extracted_bytes
                {
                    return Err(Error::TooLarge {
                        len: declared,
                        max: limits.max_extracted_bytes,
                    });
                }
                ensure_parent(&root, &rel)?;
                let mut file = root.open_with(
                    &rel,
                    OpenOptions::new().write(true).create(true).truncate(true),
                )?;
                let mut taken = 0u64;
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = entry.read(&mut buf).map_err(map_io)?;
                    if n == 0 {
                        break;
                    }
                    taken += n as u64;
                    if taken > declared || taken > limits.max_file_bytes {
                        return Err(Error::TooLarge {
                            len: taken,
                            max: limits.max_file_bytes,
                        });
                    }
                    file.write_all(&buf[..n])?;
                }
                extracted += taken;
                let mode = normalized_mode(false, entry.header().mode().unwrap_or(0o644));
                file.set_permissions(Permissions::from_mode(mode))?;
                file.sync_all()?;
                file_count += 1;
            }
            EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(map_io)?
                    .ok_or_else(|| Error::Archive("symlink missing target".into()))?;
                let target = target
                    .to_str()
                    .ok_or_else(|| Error::Archive("symlink target is not utf-8".into()))?;
                let parent = rel.parent().unwrap_or(Path::new(""));
                crate::pathsafe::resolve_lex(parent, Path::new(target))?;
                ensure_parent(&root, &rel)?;
                if root.try_exists(&rel).unwrap_or(false) {
                    let _ = root.remove_file(&rel);
                }
                root.symlink(target, &rel)?;
                file_count += 1;
            }
            EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(map_io)?
                    .ok_or_else(|| Error::Archive("hardlink missing target".into()))?;
                let target = target
                    .to_str()
                    .ok_or_else(|| Error::Archive("hardlink target is not utf-8".into()))?;
                let Some(target_rel) = normalize_entry_path(target, strip_components)? else {
                    return Err(Error::PathEscape(target.to_string()));
                };
                let meta = root
                    .symlink_metadata(&target_rel)
                    .map_err(|_| Error::PathEscape(target.to_string()))?;
                if !meta.file_type().is_file() {
                    return Err(Error::Archive(
                        "hardlink target is not a regular file".into(),
                    ));
                }
                ensure_parent(&root, &rel)?;
                root.hard_link(&target_rel, &root, &rel)?;
                file_count += 1;
            }
            EntryType::XGlobalHeader
            | EntryType::XHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => {}
            _ => {
                return Err(Error::Archive(format!(
                    "refusing special entry {raw} ({kind:?})"
                )));
            }
        }
    }
    Ok(ExtractReport {
        bytes: extracted,
        file_count,
    })
}

fn ensure_parent(root: &Dir, rel: &Path) -> Result<()> {
    if let Some(parent) = rel.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        root.create_dir_all(parent)?;
    }
    Ok(())
}

fn normalize_entry_path(raw: &str, strip: usize) -> Result<Option<PathBuf>> {
    if raw.contains('\0') {
        return Err(Error::Archive("NUL in path".into()));
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(Error::PathEscape(raw.to_string()));
    }
    let mut comps = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| Error::Archive("non-utf8 path".into()))?;
                if name.contains('\0') || name.len() > 255 {
                    return Err(Error::Archive(format!("bad path component {name}")));
                }
                comps.push(name.to_string());
            }
            Component::CurDir => {}
            _ => return Err(Error::PathEscape(raw.to_string())),
        }
    }
    if strip > comps.len() {
        return Ok(None);
    }
    let comps = &comps[strip..];
    if comps.is_empty() {
        return Ok(None);
    }
    if comps.len() > 128 {
        return Err(Error::Archive("path too deep".into()));
    }
    let mut out = PathBuf::new();
    for component in comps {
        out.push(component);
    }
    Ok(Some(out))
}

fn map_io(err: io::Error) -> Error {
    let text = err.to_string();
    if text.contains("compressed size limit") {
        Error::TooLarge { len: 0, max: 0 }
    } else {
        Error::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use proptest::prelude::*;
    use std::fs;
    use tar::{Builder, Header};
    use tempfile::tempdir;

    fn raw_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");
        header[263] = b'0';
        header[264] = b'0';
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let cksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(cksum.as_bytes());
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0, pad));
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    fn tar_with(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, data) in files {
            let mut header = Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn extracts_and_strips_prefix() {
        let bytes = tar_with(&[("repo/hello.txt", b"hi")]);
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        let report =
            extract_archive(bytes.as_slice(), &dest, &ExtractLimits::default(), 1).unwrap();
        assert_eq!(report.file_count, 1);
        assert_eq!(fs::read(dest.join("hello.txt")).unwrap(), b"hi");
    }

    #[test]
    fn rejects_escape_and_leaves_parent_untouched() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("canary"), b"safe").unwrap();
        let dest = dir.path().join("out");
        let bytes = raw_tar("../canary", b"pwned");
        assert!(extract_archive(bytes.as_slice(), &dest, &ExtractLimits::default(), 0).is_err());
        assert_eq!(fs::read(dir.path().join("canary")).unwrap(), b"safe");
        let bytes = raw_tar("/tmp/cite-escaped", b"pwned");
        assert!(extract_archive(bytes.as_slice(), &dest, &ExtractLimits::default(), 0).is_err());
    }

    #[test]
    fn rejects_symlink_to_absolute_path() {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Symlink);
        header.set_size(0);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_path("evil").unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
        let bytes = builder.into_inner().unwrap();
        let dir = tempdir().unwrap();
        assert!(
            extract_archive(
                bytes.as_slice(),
                &dir.path().join("out"),
                &ExtractLimits::default(),
                0
            )
            .is_err()
        );
    }

    #[test]
    fn gzip_roundtrip() {
        let raw = tar_with(&[("a.txt", b"abc")]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw).unwrap();
        let gz = encoder.finish().unwrap();
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        extract_archive(gz.as_slice(), &dest, &ExtractLimits::default(), 0).unwrap();
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"abc");
    }

    #[test]
    fn default_limits_are_one_gigabyte_two_gigabytes_and_300k_entries() {
        let limits = ExtractLimits::default();
        assert_eq!(limits.max_compressed_bytes, 1024 * 1024 * 1024);
        assert_eq!(limits.max_extracted_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_entries, 300_000);
    }

    #[test]
    fn enforces_entry_limit() {
        let bytes = tar_with(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let dir = tempdir().unwrap();
        let limits = ExtractLimits {
            max_entries: 1,
            ..ExtractLimits::default()
        };
        assert!(extract_archive(bytes.as_slice(), &dir.path().join("out"), &limits, 0).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn random_files_stay_inside(
            files in prop::collection::vec(("[a-z]{1,6}", prop::collection::vec(any::<u8>(), 0..24usize)), 0..5)
        ) {
            let mut builder = Builder::new(Vec::new());
            for (name, data) in &files {
                let mut header = Header::new_gnu();
                header.set_path(format!("top/{name}.txt")).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, data.as_slice()).unwrap();
            }
            let bytes = builder.into_inner().unwrap();
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("canary"), b"safe").unwrap();
            let dest = dir.path().join("out");
            let result = extract_archive(bytes.as_slice(), &dest, &ExtractLimits::default(), 1);
            prop_assert!(result.is_ok());
            prop_assert_eq!(fs::read(dir.path().join("canary")).unwrap(), b"safe");
            let expected: std::collections::BTreeMap<_, _> = files.iter().cloned().collect();
            for (name, data) in &expected {
                prop_assert_eq!(fs::read(dest.join(format!("{name}.txt"))).unwrap(), data.as_slice());
            }
        }
    }
}
