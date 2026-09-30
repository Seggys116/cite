use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

/// Atomic-write temp names are allowed; site bytes may exist only under `releases/{blue,green}/app`.
pub fn layout_violations(cite_data: &Path) -> Result<Vec<String>> {
    if !cite_data.exists() {
        return Ok(Vec::new());
    }
    let mut violations = Vec::new();
    for entry in fs::read_dir(cite_data)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !matches!(name.as_str(), "releases" | "control" | "status" | "state") {
            violations.push(format!("unexpected top-level path {name}"));
        }
    }
    check_files(&cite_data.join("control"), "desired.json", &mut violations)?;
    check_files(&cite_data.join("status"), "executor.json", &mut violations)?;
    check_files(&cite_data.join("state"), "state.json", &mut violations)?;
    let releases = cite_data.join("releases");
    if releases.exists() {
        for entry in fs::read_dir(&releases)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "blue" && name != "green" {
                violations.push(format!("unexpected release path {name}"));
                continue;
            }
            if !entry.path().is_dir() {
                violations.push(format!("{name} is not a directory"));
                continue;
            }
            for child in fs::read_dir(entry.path())? {
                let child_name = child?.file_name().to_string_lossy().into_owned();
                if child_name != "app"
                    && child_name != "release.json"
                    && !is_atomic_tmp(&child_name)
                {
                    violations.push(format!("unexpected path in {name}: {child_name}"));
                }
            }
        }
    }
    Ok(violations)
}

pub fn slot_is_sealed(slot_dir: &Path) -> bool {
    slot_dir.join("release.json").is_file()
}

pub fn sweep_dir(dir: &Path) -> Result<()> {
    remove_dir_contents(dir)
}

/// A temp file left at startup means rename never happened, so the destination is still the previous complete file.
pub fn sweep_atomic_temps(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_atomic_tmp(&name) {
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

pub fn remove_dir_contents(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

pub fn filesystem_free_bytes(path: &Path) -> Result<u64> {
    let probe = if path.exists() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };
    let stat = rustix::fs::statvfs(&probe).map_err(|err| Error::Io(err.into()))?;
    let block = stat.f_frsize.max(1);
    let avail = stat.f_bavail;
    Ok(avail.saturating_mul(block))
}

fn check_files(dir: &Path, allowed: &str, violations: &mut Vec<String>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let label = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string());
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != allowed && !is_atomic_tmp(&name) {
            violations.push(format!("unexpected path {label}/{name}"));
        }
        if entry.path().is_dir() {
            violations.push(format!("unexpected directory {label}/{name}"));
        }
    }
    Ok(())
}

fn is_atomic_tmp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((base, tail)) = rest.split_once(".tmp.") else {
        return false;
    };
    !base.is_empty()
        && tail.split_once('.').is_some_and(|(pid, seq)| {
            !pid.is_empty()
                && pid.chars().all(|c| c.is_ascii_digit())
                && !seq.is_empty()
                && seq.chars().all(|c| c.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn layout_allows_two_slots_only() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("cite_data");
        for sub in [
            "releases/blue/app",
            "releases/green/app",
            "control",
            "status",
            "state",
        ] {
            fs::create_dir_all(data.join(sub)).unwrap();
        }
        fs::write(data.join("releases/blue/release.json"), b"{}").unwrap();
        fs::write(data.join("control/desired.json"), b"{}").unwrap();
        assert!(layout_violations(&data).unwrap().is_empty());
        fs::create_dir_all(data.join("releases/staging")).unwrap();
        let violations = layout_violations(&data).unwrap();
        assert!(violations.iter().any(|v| v.contains("staging")));
    }

    #[test]
    fn sweep_atomic_temps_keeps_the_destination_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("desired.json"), b"{\"ok\":true}").unwrap();
        fs::write(dir.path().join(".desired.json.tmp.12.ab"), b"partial").unwrap();
        fs::create_dir(dir.path().join("app")).unwrap();
        sweep_atomic_temps(dir.path()).unwrap();
        assert_eq!(
            fs::read(dir.path().join("desired.json")).unwrap(),
            b"{\"ok\":true}"
        );
        assert!(!dir.path().join(".desired.json.tmp.12.ab").exists());
        assert!(dir.path().join("app").is_dir());
    }

    #[test]
    fn sweep_empties_work_dir() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("job-1")).unwrap();
        fs::write(dir.path().join("job-1/file"), b"x").unwrap();
        sweep_dir(dir.path()).unwrap();
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
