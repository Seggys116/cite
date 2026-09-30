use std::path::{Component, Path, PathBuf};

use cap_std::fs::{Dir, File};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPath {
    pub rel: PathBuf,
    pub trailing_slash: bool,
}

pub enum ContainedOpen {
    File { rel: PathBuf, file: File, len: u64 },
    Directory { rel: PathBuf },
}

/// Empty allow-list accepts any host. Otherwise the header, or the name before the first `:`, must match.
pub fn host_allowed(allowed: &[String], host_header: &str) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let host_only = host_header.split(':').next().unwrap_or(host_header);
    allowed
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host_only) || h.eq_ignore_ascii_case(host_header))
}

/// Percent-decode a URL path and reject `..`, absolute paths, NULs, backslashes, and dotfiles.
pub fn request_path(raw: &str) -> Result<UrlPath> {
    let raw = raw.split('?').next().unwrap_or(raw);
    let raw = raw.split('#').next().unwrap_or(raw);
    let decoded = percent_decode(raw)?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return Err(Error::PathEscape(raw.to_string()));
    }
    let trailing_slash = decoded.ends_with('/') && decoded != "/";
    let mut rel = PathBuf::new();
    for component in decoded.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".."
            || component.starts_with('.')
            || component.len() > 255
            || component.contains('\0')
        {
            return Err(Error::PathEscape(component.to_string()));
        }
        rel.push(component);
    }
    if rel.components().count() > 64 {
        return Err(Error::PathEscape("path too deep".into()));
    }
    Ok(UrlPath {
        rel,
        trailing_slash,
    })
}

/// Open `url_path` under `root`. Symlinks are followed only when the resolved path stays inside `root`.
pub fn open_contained(root: &Dir, url_path: &str) -> Result<ContainedOpen> {
    let url = request_path(url_path)?;
    open_rel(root, &url.rel, 0)
}

fn open_rel(root: &Dir, rel: &Path, depth: u32) -> Result<ContainedOpen> {
    if depth > 16 {
        return Err(Error::PathEscape("symlink loop".into()));
    }
    if rel.as_os_str().is_empty() {
        return Ok(ContainedOpen::Directory {
            rel: PathBuf::new(),
        });
    }
    let comps: Vec<String> = rel
        .components()
        .map(|component| match component {
            Component::Normal(name) => name
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| Error::PathEscape("non-utf8 path".into())),
            _ => Err(Error::PathEscape(rel.display().to_string())),
        })
        .collect::<Result<Vec<_>>>()?;

    let mut current = root.try_clone()?;
    let mut virtual_path = PathBuf::new();
    for (idx, name) in comps.iter().enumerate() {
        if name.starts_with('.') || name.contains('\0') {
            return Err(Error::PathEscape(name.clone()));
        }
        let meta = match current.symlink_metadata(name) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound(rel.display().to_string()));
            }
            Err(err) => return Err(err.into()),
        };
        let file_type = meta.file_type();
        let last = idx + 1 == comps.len();
        if file_type.is_symlink() {
            let target = current.read_link(name)?;
            let resolved = resolve_lex(&virtual_path, &target)?;
            let mut rest = resolved;
            for next in &comps[idx + 1..] {
                rest.push(next);
            }
            return open_rel(root, &rest, depth + 1);
        }
        virtual_path.push(name);
        if last {
            if file_type.is_dir() {
                return Ok(ContainedOpen::Directory { rel: virtual_path });
            }
            if !file_type.is_file() {
                return Err(Error::PathEscape(format!("special file {name}")));
            }
            let file = current.open(name)?;
            return Ok(ContainedOpen::File {
                rel: virtual_path,
                file,
                len: meta.len(),
            });
        } else if file_type.is_dir() {
            current = current.open_dir(name)?;
        } else {
            return Err(Error::NotFound(rel.display().to_string()));
        }
    }
    Err(Error::NotFound(rel.display().to_string()))
}

pub(crate) fn resolve_lex(parent: &Path, target: &Path) -> Result<PathBuf> {
    if target.is_absolute() || target.as_os_str().is_empty() {
        return Err(Error::PathEscape(target.display().to_string()));
    }
    let joined = parent.join(target);
    let mut norm = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| Error::PathEscape("non-utf8 symlink".into()))?;
                if name.contains('\0') {
                    return Err(Error::PathEscape(name.to_string()));
                }
                norm.push(name);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !norm.pop() {
                    return Err(Error::PathEscape(target.display().to_string()));
                }
            }
            _ => return Err(Error::PathEscape(target.display().to_string())),
        }
    }
    Ok(norm)
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Error::PathEscape("bad percent-encoding".into()));
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::PathEscape("path is not utf-8".into()))
}

fn hex_val(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::PathEscape("bad percent-encoding".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;
    use proptest::prelude::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn host_allow_list() {
        assert!(host_allowed(&[], "evil.example"));
        let allowed = vec!["app.example".into()];
        assert!(host_allowed(&allowed, "app.example"));
        assert!(host_allowed(&allowed, "APP.example:8080"));
        assert!(!host_allowed(&allowed, "evil.example"));
    }

    #[test]
    fn rejects_traversal_and_dotfiles() {
        assert!(request_path("/../etc/passwd").is_err());
        assert!(request_path("/%2e%2e/secret").is_err());
        assert!(request_path("/.env").is_err());
        assert!(request_path("/foo/.git/config").is_err());
        let ok = request_path("/a/b/index.html").unwrap();
        assert_eq!(ok.rel, PathBuf::from("a/b/index.html"));
    }

    #[test]
    fn symlink_escape_is_rejected_and_inside_link_is_served() {
        let dir = tempdir().unwrap();
        let root_path = dir.path().join("root");
        fs::create_dir_all(root_path.join("public")).unwrap();
        fs::write(root_path.join("secret.txt"), b"secret").unwrap();
        fs::write(root_path.join("public/ok.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink("../secret.txt", root_path.join("public/inside")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root_path.join("public/outside")).unwrap();
        let root = Dir::open_ambient_dir(&root_path, ambient_authority()).unwrap();
        match open_contained(&root, "/public/inside").unwrap() {
            ContainedOpen::File { len, .. } => assert_eq!(len, 6),
            ContainedOpen::Directory { .. } => panic!("expected file"),
        }
        assert!(open_contained(&root, "/public/outside").is_err());
        assert!(open_contained(&root, "/nope").is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn resolved_request_stays_relative(raw in "(/[A-Za-z0-9._~-]{0,12}){0,6}") {
            if let Ok(url) = request_path(&raw) {
                for component in url.rel.components() {
                    match component {
                        Component::Normal(name) => {
                            let name = name.to_str().unwrap();
                            prop_assert!(!name.is_empty());
                            prop_assert!(!name.starts_with('.'));
                            prop_assert_ne!(name, "..");
                        }
                        _ => prop_assert!(false),
                    }
                }
            }
        }
    }
}
