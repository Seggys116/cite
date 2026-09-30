#![forbid(unsafe_code)]

use cite_core::Slot;
use cite_core::schema::ReleaseManifest;

/// What the public listener routes to. Switched atomically via [`arc_swap::ArcSwap`].
#[derive(Debug, Clone)]
pub struct RouteTarget {
    pub slot: Option<Slot>,
    #[allow(dead_code)]
    pub release_id: Option<String>,
    pub kind: RouteKind,
}

#[derive(Debug, Clone)]
pub enum RouteKind {
    None,
    Static {
        app_root: std::path::PathBuf,
        spa_fallback: Option<String>,
    },
    Proxy {
        port: u16,
    },
}

impl RouteTarget {
    pub fn empty() -> Self {
        Self {
            slot: None,
            release_id: None,
            kind: RouteKind::None,
        }
    }

    pub fn static_from(manifest: &ReleaseManifest, app_root: std::path::PathBuf) -> Self {
        Self {
            slot: Some(manifest.slot),
            release_id: Some(manifest.release_id.clone()),
            kind: RouteKind::Static {
                app_root,
                spa_fallback: manifest.spa_fallback.clone(),
            },
        }
    }

    pub fn proxy_from(manifest: &ReleaseManifest, port: u16) -> Self {
        Self {
            slot: Some(manifest.slot),
            release_id: Some(manifest.release_id.clone()),
            kind: RouteKind::Proxy { port },
        }
    }
}
