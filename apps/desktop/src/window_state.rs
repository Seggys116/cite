use std::path::{Path, PathBuf};

use cite_client::fsio::{read_limited, write_atomic};
use serde::{Deserialize, Serialize};

use crate::theme::layout::{WINDOW_MIN_H, WINDOW_MIN_W};

const MAX_BYTES: u64 = 16 * 1024;
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Frame {
    // A frame smaller than the minimum or with non-finite numbers is not worth restoring.
    pub fn usable(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.width >= WINDOW_MIN_W
            && self.height >= WINDOW_MIN_H
    }
}

// Window and sidebar state sit beside desktop.json, so the node config never changes for a resize.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowState {
    pub frame: Option<Frame>,
    pub maximized: bool,
    pub sidebar_collapsed: bool,
}

impl WindowState {
    pub fn load(path: &Path) -> Self {
        read_limited(path, MAX_BYTES)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        write_atomic(path, &bytes, FILE_MODE)
    }

    pub fn restorable_frame(&self) -> Option<Frame> {
        self.frame.filter(Frame::usable)
    }
}

pub fn window_state_path() -> PathBuf {
    crate::config::config_path().with_file_name("window.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("window.json");
        let state = WindowState {
            frame: Some(Frame {
                x: 40.0,
                y: 60.0,
                width: 1200.0,
                height: 800.0,
            }),
            maximized: false,
            sidebar_collapsed: true,
        };
        state.save(&path).expect("save");
        assert_eq!(WindowState::load(&path), state);
    }

    #[test]
    fn missing_or_broken_files_load_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("window.json");
        assert_eq!(WindowState::load(&path), WindowState::default());
        std::fs::write(&path, "not json").expect("write");
        assert_eq!(WindowState::load(&path), WindowState::default());
    }

    #[test]
    fn tiny_or_invalid_frames_are_not_restored() {
        let mut state = WindowState {
            frame: Some(Frame {
                x: 0.0,
                y: 0.0,
                width: 200.0,
                height: 100.0,
            }),
            ..WindowState::default()
        };
        assert!(state.restorable_frame().is_none());
        state.frame = Some(Frame {
            x: f32::NAN,
            y: 0.0,
            width: 1200.0,
            height: 800.0,
        });
        assert!(state.restorable_frame().is_none());
        state.frame = Some(Frame {
            x: 10.0,
            y: 10.0,
            width: 1200.0,
            height: 800.0,
        });
        assert!(state.restorable_frame().is_some());
    }
}
