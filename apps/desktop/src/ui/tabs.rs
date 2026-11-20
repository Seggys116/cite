use std::collections::HashMap;

use gpui::{AnyElement, Context, div, prelude::*, px};

use crate::app::Console;
use crate::theme::{ACCENT, c};
use crate::ui::widgets::{id, tab_bar, tab_item};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SiteTab {
    Overview,
    Build,
    Environment,
    Volumes,
    Data,
    Logs,
    Domains,
    Access,
    Danger,
}

impl SiteTab {
    pub const ALL: [SiteTab; 9] = [
        SiteTab::Overview,
        SiteTab::Build,
        SiteTab::Environment,
        SiteTab::Volumes,
        SiteTab::Data,
        SiteTab::Logs,
        SiteTab::Domains,
        SiteTab::Access,
        SiteTab::Danger,
    ];

    // A site that is not built from a repository has no build: its second tab holds the health check only.
    pub fn label(self, source: bool) -> &'static str {
        match self {
            SiteTab::Overview => "Overview",
            SiteTab::Build if source => "Build",
            SiteTab::Build => "Health check",
            SiteTab::Environment => "Environment",
            SiteTab::Volumes => "Volumes",
            SiteTab::Data => "Data",
            SiteTab::Logs => "Logs",
            SiteTab::Domains => "Domains and routing",
            SiteTab::Access => "Access",
            SiteTab::Danger => "Danger zone",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            SiteTab::Overview => "overview",
            SiteTab::Build => "build",
            SiteTab::Environment => "env",
            SiteTab::Volumes => "volumes",
            SiteTab::Data => "data",
            SiteTab::Logs => "logs",
            SiteTab::Domains => "domains",
            SiteTab::Access => "access",
            SiteTab::Danger => "danger",
        }
    }

    pub fn has_form(self) -> bool {
        matches!(
            self,
            SiteTab::Build | SiteTab::Volumes | SiteTab::Domains | SiteTab::Access
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TabOffer {
    pub source: bool,
    pub env: bool,
    pub logs: bool,
    // The site runs as a server and the node offers volumes.
    pub volumes: bool,
    // The site runs as a server and the node offers a data service (Postgres, external Postgres or S3).
    pub data: bool,
}

pub fn visible_tabs(offer: TabOffer) -> Vec<SiteTab> {
    SiteTab::ALL
        .into_iter()
        .filter(|t| match t {
            SiteTab::Environment => offer.source && offer.env,
            SiteTab::Volumes => offer.source && offer.volumes,
            SiteTab::Data => offer.source && offer.data,
            SiteTab::Logs => offer.source && offer.logs,
            _ => true,
        })
        .collect()
}

pub fn shown_tab(remembered: Option<SiteTab>, visible: &[SiteTab]) -> SiteTab {
    remembered
        .filter(|t| visible.contains(t))
        .unwrap_or(SiteTab::Overview)
}

// The tab chosen on each site, kept for the session so returning to a site reopens it.
#[derive(Default)]
pub struct TabMemory {
    chosen: HashMap<(String, String), SiteTab>,
}

impl TabMemory {
    pub fn get(&self, node: &str, site: &str) -> Option<SiteTab> {
        self.chosen
            .get(&(node.to_string(), site.to_string()))
            .copied()
    }

    pub fn set(&mut self, node: &str, site: &str, tab: SiteTab) {
        self.chosen
            .insert((node.to_string(), site.to_string()), tab);
    }
}

impl Console {
    // Form tabs carry a dot while the form has unsaved edits.
    pub(crate) fn tab_strip(
        &self,
        tabs: &[SiteTab],
        current: SiteTab,
        source: bool,
        unsaved: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut items = Vec::new();
        for tab in tabs.iter().copied() {
            let mut item =
                tab_item(id("site-tab", tab.key()), tab.label(source), tab == current).gap(px(6.));
            if unsaved && tab.has_form() {
                item = item.child(div().size(px(6.)).rounded_full().bg(c(ACCENT)));
            }
            items.push(
                item.on_click(cx.listener(move |this, _, _, cx| {
                    this.select_tab(tab, cx);
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        tab_bar(items).into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_tabs_need_a_repository_and_the_node_features() {
        let all = visible_tabs(TabOffer {
            source: true,
            env: true,
            logs: true,
            volumes: true,
            data: true,
        });
        assert_eq!(all, SiteTab::ALL.to_vec());
        let plain = visible_tabs(TabOffer {
            source: false,
            env: true,
            logs: true,
            volumes: true,
            data: true,
        });
        assert!(!plain.contains(&SiteTab::Environment) && !plain.contains(&SiteTab::Logs));
        assert!(!plain.contains(&SiteTab::Volumes) && !plain.contains(&SiteTab::Data));
        assert!(plain.contains(&SiteTab::Build) && plain.contains(&SiteTab::Danger));
        let old = visible_tabs(TabOffer {
            source: true,
            env: false,
            logs: false,
            volumes: false,
            data: false,
        });
        assert_eq!(old.len(), 5);
        let order = visible_tabs(TabOffer {
            source: true,
            env: true,
            logs: true,
            volumes: true,
            data: true,
        });
        let at = |t| order.iter().position(|x| *x == t).unwrap();
        assert!(
            at(SiteTab::Environment) < at(SiteTab::Volumes)
                && at(SiteTab::Volumes) < at(SiteTab::Data)
                && at(SiteTab::Data) < at(SiteTab::Logs)
        );
        assert_eq!(SiteTab::Build.label(false), "Health check");
        assert_eq!(SiteTab::Build.label(true), "Build");
    }

    #[test]
    fn the_data_tab_appears_only_with_the_data_capabilities_on_a_built_site() {
        let offer = |source, data| TabOffer {
            source,
            env: true,
            logs: true,
            volumes: true,
            data,
        };
        assert!(visible_tabs(offer(true, true)).contains(&SiteTab::Data));
        // The node offers no data service, or the site is not built from a repository.
        assert!(!visible_tabs(offer(true, false)).contains(&SiteTab::Data));
        assert!(!visible_tabs(offer(false, true)).contains(&SiteTab::Data));
        // The offer is derived from the node's capabilities.
        let caps = |list: &[&str]| list.iter().map(|c| c.to_string()).collect::<Vec<_>>();
        assert!(!crate::ui::dataview::data_tab_offered(&caps(&["volumes"])));
        assert!(crate::ui::dataview::data_tab_offered(&caps(&["data-s3"])));
        assert_eq!(SiteTab::Data.label(true), "Data");
        assert_eq!(SiteTab::Data.key(), "data");
        assert!(!SiteTab::Data.has_form());
        assert_eq!(SiteTab::ALL.len(), 9);
    }

    #[test]
    fn a_remembered_tab_is_reopened_only_while_it_exists() {
        let tabs = visible_tabs(TabOffer {
            source: false,
            ..TabOffer::default()
        });
        assert_eq!(shown_tab(Some(SiteTab::Access), &tabs), SiteTab::Access);
        assert_eq!(shown_tab(Some(SiteTab::Logs), &tabs), SiteTab::Overview);
        assert_eq!(shown_tab(None, &tabs), SiteTab::Overview);
        let mut memory = TabMemory::default();
        memory.set("edge-1", "docs", SiteTab::Logs);
        memory.set("edge-2", "docs", SiteTab::Access);
        assert_eq!(memory.get("edge-1", "docs"), Some(SiteTab::Logs));
        assert_eq!(memory.get("edge-2", "docs"), Some(SiteTab::Access));
        assert_eq!(memory.get("edge-1", "shop"), None);
        memory.set("edge-1", "docs", SiteTab::Build);
        assert_eq!(memory.get("edge-1", "docs"), Some(SiteTab::Build));
        assert!(SiteTab::Build.has_form() && !SiteTab::Logs.has_form());
    }
}
