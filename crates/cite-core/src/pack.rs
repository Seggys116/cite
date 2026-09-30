use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, PermissionsExt};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};

use crate::error::{Error, Result};
use crate::pathsafe::resolve_lex;

#[derive(Debug, Clone)]
pub struct PackLimits {
    pub max_bytes: u64,
    pub max_files: u64,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_bytes: (1.5 * 1024.0 * 1024.0 * 1024.0) as u64,
            max_files: 300_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackReport {
    pub bytes: u64,
    pub file_count: u64,
    pub tree_sha256: String,
}

#[derive(Clone)]
struct Node {
    rel: PathBuf,
    kind: Kind,
    mode: u32,
    link: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Symlink,
}

pub fn normalized_mode(is_dir: bool, raw: u32) -> u32 {
    if is_dir || raw & 0o111 != 0 {
        0o755
    } else {
        0o644
    }
}

/// Walk `src` with no-follow directory handles and write a tar of regular files, directories, and in-root symlinks.
pub fn pack_dir<W: Write>(src: &Path, writer: W, limits: &PackLimits) -> Result<PackReport> {
    let (report, nodes, root) = scan(src, limits)?;
    write_tar(&root, &nodes, writer)?;
    Ok(report)
}

/// Hash the same normalized tree [`pack_dir`] would emit.
pub fn hash_tree(src: &Path) -> Result<PackReport> {
    let limits = PackLimits {
        max_bytes: u64::MAX / 4,
        max_files: u64::MAX / 4,
    };
    let (report, _, _) = scan(src, &limits)?;
    Ok(report)
}

fn scan(src: &Path, limits: &PackLimits) -> Result<(PackReport, Vec<Node>, Dir)> {
    if !src.is_dir() {
        return Err(Error::msg(format!(
            "pack source is not a directory: {}",
            src.display()
        )));
    }
    let root = Dir::open_ambient_dir(src, ambient_authority())?;
    let mut nodes = Vec::new();
    let mut bytes = 0u64;
    let mut files = 0u64;
    collect(
        &root,
        Path::new(""),
        &mut nodes,
        limits,
        &mut bytes,
        &mut files,
    )?;
    assert_symlink_chains(&nodes)?;
    let tree_sha256 = hash_nodes(&root, &nodes)?;
    Ok((
        PackReport {
            bytes,
            file_count: files,
            tree_sha256,
        },
        nodes,
        root,
    ))
}

fn collect(
    dir: &Dir,
    rel: &Path,
    nodes: &mut Vec<Node>,
    limits: &PackLimits,
    bytes: &mut u64,
    files: &mut u64,
) -> Result<()> {
    let mut names = Vec::new();
    for entry in dir.entries()? {
        names.push(entry?.file_name());
    }
    names.sort();
    for name in names {
        let name_str = name
            .to_str()
            .ok_or_else(|| Error::Archive("non-utf8 filename".into()))?;
        if excluded(name_str) {
            continue;
        }
        let meta = dir.symlink_metadata(&name)?;
        let file_type = meta.file_type();
        let child = if rel.as_os_str().is_empty() {
            PathBuf::from(name_str)
        } else {
            rel.join(name_str)
        };
        if file_type.is_symlink() {
            *files += 1;
            if *files > limits.max_files {
                return Err(Error::TooLarge {
                    len: *files,
                    max: limits.max_files,
                });
            }
            let target = dir.read_link(&name)?;
            resolve_lex(rel, &target)?;
            nodes.push(Node {
                rel: child,
                kind: Kind::Symlink,
                mode: 0o777,
                link: Some(target),
            });
        } else if file_type.is_dir() {
            nodes.push(Node {
                rel: child.clone(),
                kind: Kind::Dir,
                mode: 0o755,
                link: None,
            });
            let sub = dir.open_dir(&name)?;
            collect(&sub, &child, nodes, limits, bytes, files)?;
        } else if file_type.is_file() {
            let len = meta.len();
            *bytes = bytes.saturating_add(len);
            *files += 1;
            if *bytes > limits.max_bytes || *files > limits.max_files {
                return Err(Error::TooLarge {
                    len: *bytes,
                    max: limits.max_bytes,
                });
            }
            let mode = normalized_mode(false, meta.permissions().mode());
            nodes.push(Node {
                rel: child,
                kind: Kind::File,
                mode,
                link: None,
            });
        } else {
            return Err(Error::Archive(format!("refusing special file {name_str}")));
        }
    }
    Ok(())
}

fn assert_symlink_chains(nodes: &[Node]) -> Result<()> {
    let map: HashMap<&Path, &Node> = nodes
        .iter()
        .map(|node| (node.rel.as_path(), node))
        .collect();
    for node in nodes {
        if node.kind != Kind::Symlink {
            continue;
        }
        let target = node.link.as_ref().expect("symlink node");
        let mut current = resolve_lex(node.rel.parent().unwrap_or(Path::new("")), target)?;
        let mut seen = HashSet::new();
        for _ in 0..32 {
            if !seen.insert(current.clone()) {
                return Err(Error::PathEscape(format!(
                    "symlink loop at {}",
                    node.rel.display()
                )));
            }
            match map.get(current.as_path()) {
                Some(next) if next.kind == Kind::Symlink => {
                    let next_target = next.link.as_ref().expect("symlink");
                    current = resolve_lex(next.rel.parent().unwrap_or(Path::new("")), next_target)?;
                }
                _ => break,
            }
        }
    }
    Ok(())
}

fn hash_nodes(root: &Dir, nodes: &[Node]) -> Result<String> {
    let mut ordered = nodes.to_vec();
    ordered.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut hasher = Sha256::new();
    hasher.update(b"cite-tree-v1\n");
    for node in &ordered {
        match node.kind {
            Kind::Dir => {
                hasher.update(format!("d {}\n", node.rel.display()).as_bytes());
            }
            Kind::Symlink => {
                let target = node.link.as_ref().expect("symlink");
                hasher.update(
                    format!("l {} -> {}\n", node.rel.display(), target.display()).as_bytes(),
                );
            }
            Kind::File => {
                let data = root.read(&node.rel)?;
                hasher.update(
                    format!("f {} {:o} {}\n", node.rel.display(), node.mode, data.len()).as_bytes(),
                );
                hasher.update(&data);
            }
        }
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn write_tar<W: Write>(root: &Dir, nodes: &[Node], writer: W) -> Result<()> {
    let mut ordered = nodes.to_vec();
    ordered.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut builder = Builder::new(writer);
    for node in &ordered {
        let mut header = Header::new_gnu();
        header.set_mode(node.mode);
        header.set_uid(0);
        header.set_gid(0);
        match node.kind {
            Kind::Dir => {
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                header.set_path(format!("{}/", node.rel.display()))?;
                header.set_cksum();
                builder.append(&header, io::empty())?;
            }
            Kind::Symlink => {
                header.set_entry_type(EntryType::Symlink);
                header.set_size(0);
                header.set_path(node.rel.display().to_string())?;
                header.set_link_name(node.link.as_ref().expect("symlink"))?;
                header.set_cksum();
                builder.append(&header, io::empty())?;
            }
            Kind::File => {
                let data = root.read(&node.rel)?;
                header.set_entry_type(EntryType::Regular);
                header.set_size(data.len() as u64);
                header.set_path(node.rel.display().to_string())?;
                header.set_cksum();
                builder.append(&header, data.as_slice())?;
            }
        }
    }
    builder.finish()?;
    Ok(())
}

fn excluded(name: &str) -> bool {
    name == ".git" || name == ".github" || name == ".env" || name.starts_with(".env.")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{ExtractLimits, extract_archive};
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn modes_drop_setuid_and_keep_exec() {
        assert_eq!(normalized_mode(true, 0o4755), 0o755);
        assert_eq!(normalized_mode(false, 0o4755), 0o755);
        assert_eq!(normalized_mode(false, 0o644), 0o644);
        assert_eq!(normalized_mode(false, 0o666), 0o644);
    }

    #[test]
    fn pack_extract_roundtrip_and_rejects_outside_symlink() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/a.txt"), b"hello").unwrap();
        fs::write(src.join(".env"), b"SECRET=1").unwrap();
        symlink("sub/a.txt", src.join("link")).unwrap();
        let mut tar_bytes = Vec::new();
        let report = pack_dir(&src, &mut tar_bytes, &PackLimits::default()).unwrap();
        assert!(!tar_bytes.is_empty());
        let dest = dir.path().join("dest");
        extract_archive(tar_bytes.as_slice(), &dest, &ExtractLimits::default(), 0).unwrap();
        let again = hash_tree(&dest).unwrap();
        assert_eq!(again.tree_sha256, report.tree_sha256);
        assert!(!dest.join(".env").exists());

        symlink("/etc/passwd", src.join("bad")).unwrap();
        let mut sink = Vec::new();
        assert!(pack_dir(&src, &mut sink, &PackLimits::default()).is_err());
    }
}
