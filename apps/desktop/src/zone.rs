use std::fmt;

use crate::certs::{date_text, short_fingerprint};

pub use cite_edge::presets::ZONE_HEADER;

pub const CLOUDFLARE_STEPS: [&str; 4] = [
    "In Cloudflare, open Rules, then Transform Rules, then Modify Request Header.",
    "Create a rule that matches this site's hostname.",
    "Under Modify request header choose Set static.",
    "Use the header name shown here and paste the secret as its value, then deploy the rule.",
];

// What the node reports about a site's secret; the secret itself never comes back from this call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneStatus {
    pub configured: bool,
    pub readable: bool,
    pub header: String,
    pub created_at: Option<String>,
    pub fingerprint: Option<String>,
}

// A freshly rotated secret, kept only until the user dismisses it; Debug hides it and Drop overwrites it.
#[derive(Clone, PartialEq, Eq)]
pub struct ZoneReveal {
    pub node: String,
    pub site: String,
    pub header: String,
    pub created_at: Option<String>,
    pub fingerprint: Option<String>,
    secret: String,
}

impl ZoneReveal {
    pub fn new(
        node: impl Into<String>,
        site: impl Into<String>,
        secret: impl Into<String>,
        header: impl Into<String>,
        created_at: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        let header = header.into();
        Self {
            node: node.into(),
            site: site.into(),
            header: if header.trim().is_empty() {
                ZONE_HEADER.to_string()
            } else {
                header
            },
            created_at,
            fingerprint,
            secret: secret.into(),
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn is_for(&self, node: &str, site: &str) -> bool {
        self.node == node && self.site == site
    }
}

impl fmt::Debug for ZoneReveal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneReveal")
            .field("node", &self.node)
            .field("site", &self.site)
            .field("header", &self.header)
            .field("created_at", &self.created_at)
            .field("fingerprint", &self.fingerprint)
            .field("secret", &"[redacted]")
            .finish()
    }
}

// Zeroing the bytes before the buffer is freed keeps the secret out of reused memory, as far as safe Rust can.
impl Drop for ZoneReveal {
    fn drop(&mut self) {
        crate::certs::wipe(&mut self.secret);
    }
}

pub const UNREADABLE_TEXT: &str = "The secret store could not be read on this node; the lock state is unknown. Fix the file or rotate after restoring it.";

pub fn status_text(status: &ZoneStatus) -> String {
    if !status.readable {
        return UNREADABLE_TEXT.to_string();
    }
    if !status.configured {
        return "No zone secret is set for this site yet.".to_string();
    }
    let mut parts = Vec::new();
    if let Some(at) = &status.created_at {
        parts.push(format!("created {}", date_text(at)));
    }
    if let Some(fp) = &status.fingerprint {
        parts.push(format!("fingerprint {}", short_fingerprint(fp)));
    }
    if parts.is_empty() {
        "A zone secret is set.".to_string()
    } else {
        format!("A zone secret is set: {}.", parts.join(", "))
    }
}

pub fn reveal_meta(reveal: &ZoneReveal) -> String {
    let mut parts = vec![format!("node {}", reveal.node)];
    if let Some(at) = &reveal.created_at {
        parts.push(format!("created {}", date_text(at)));
    }
    if let Some(fp) = &reveal.fingerprint {
        parts.push(format!("fingerprint {}", short_fingerprint(fp)));
    }
    parts.join(", ")
}

pub const NOT_SHOWN_AGAIN: &str =
    "This secret is shown once. It cannot be retrieved later, only replaced by rotating it.";

pub const ROTATE_WARNING: &str = "Rotating makes the current secret stop working at once. Requests through Cloudflare are refused with 403 until you paste the new secret into the Transform Rule.";

// A rotation that failed after the site was saved must say so, or the user would think the lock has a visible secret.
pub fn rotation_failed(error: &str) -> String {
    format!(
        "The site was saved, but its zone secret could not be shown: {error}. Use Rotate zone secret to get one."
    )
}

// A reveal is shown only by the page of its own node and site.
pub fn reveals_for<'a>(reveals: &'a [ZoneReveal], node: &str, site: &str) -> Vec<&'a ZoneReveal> {
    reveals.iter().filter(|r| r.is_for(node, site)).collect()
}

// Nodes other than this one that still hold a secret for the same site, so the page can point to them.
pub fn reveal_nodes_elsewhere(reveals: &[ZoneReveal], node: &str, site: &str) -> Vec<String> {
    reveals
        .iter()
        .filter(|r| r.site == site && r.node != node)
        .map(|r| r.node.clone())
        .collect()
}

// Leaving a site page drops every secret except those of the site being opened, whatever node they belong to.
pub fn keep_for_site(reveals: &mut Vec<ZoneReveal>, opening: Option<&str>) {
    reveals.retain(|r| opening == Some(r.site.as_str()));
}

// What the create form does once every node has answered: a toast, an error that keeps the form, or a jump to the site page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateVerdict {
    pub toast: Option<(String, bool)>,
    pub error: Option<String>,
    pub open_node: Option<String>,
}

// Secrets that were rotated are never thrown away because another node failed: the site page is opened to show them.
pub fn create_verdict(
    site_name: &str,
    created: usize,
    failed: &[String],
    problems: &[String],
    reveal_nodes: &[String],
) -> CreateVerdict {
    let open_node = reveal_nodes.first().cloned();
    let mut hints = Vec::new();
    if !problems.is_empty() {
        hints.push(rotation_failed(&problems.join("; ")));
    }
    if failed.is_empty() {
        let mut text = format!("Site {site_name} created on {created} node(s)");
        for hint in &hints {
            text.push_str(&format!(". {hint}"));
        }
        return CreateVerdict {
            toast: Some((text, hints.is_empty())),
            error: None,
            open_node,
        };
    }
    let mut text = failed.join("; ");
    if open_node.is_some() {
        text.push_str(&format!(
            ". The zone secret for {} was kept on the site page.",
            reveal_nodes.join(", ")
        ));
    }
    for hint in &hints {
        text.push_str(&format!(" {hint}"));
    }
    if open_node.is_some() {
        CreateVerdict {
            toast: Some((text, false)),
            error: None,
            open_node,
        }
    } else {
        CreateVerdict {
            toast: None,
            error: Some(text),
            open_node: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::zone_value;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| (*i).to_string()).collect()
    }

    #[test]
    fn a_clean_create_toasts_and_opens_the_first_secret() {
        let v = create_verdict("Shop", 2, &[], &[], &s(&["a", "b"]));
        assert_eq!(
            v.toast,
            Some(("Site Shop created on 2 node(s)".to_string(), true))
        );
        assert_eq!((v.error, v.open_node), (None, Some("a".to_string())));
        let plain = create_verdict("Shop", 1, &[], &[], &[]);
        assert_eq!(plain.open_node, None);
        assert!(plain.toast.is_some_and(|(_, ok)| ok));
    }

    #[test]
    fn a_failed_rotation_warns_without_losing_the_site() {
        let v = create_verdict("Shop", 2, &[], &s(&["b: boom"]), &s(&["a"]));
        let (text, ok) = v.toast.expect("toast");
        assert!(!ok && text.contains("b: boom") && text.contains("could not be shown"));
        assert_eq!(v.open_node.as_deref(), Some("a"));
    }

    #[test]
    fn a_node_failure_keeps_the_secrets_of_the_nodes_that_succeeded() {
        let v = create_verdict("Shop", 1, &s(&["b: refused"]), &[], &s(&["a"]));
        assert_eq!(v.error, None);
        assert_eq!(v.open_node.as_deref(), Some("a"));
        let (text, ok) = v.toast.expect("toast");
        assert!(!ok && text.contains("b: refused") && text.contains("zone secret for a was kept"));
    }

    #[test]
    fn a_failure_with_nothing_to_show_stays_on_the_form() {
        let v = create_verdict("Shop", 0, &s(&["a: no", "b: no"]), &[], &[]);
        assert_eq!(v.error.as_deref(), Some("a: no; b: no"));
        assert!(v.toast.is_none() && v.open_node.is_none());
        let with_problem = create_verdict("Shop", 1, &s(&["b: no"]), &s(&["a: boom"]), &[]);
        let err = with_problem.error.expect("error");
        assert!(err.contains("b: no") && err.contains("a: boom"));
    }

    fn reveal() -> ZoneReveal {
        ZoneReveal::new(
            "edge-fra",
            "shop",
            zone_value(),
            "",
            Some("2026-11-06T10:00:00Z".into()),
            Some("AB12CD34EF56".into()),
        )
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let r = reveal();
        let value = zone_value();
        let shown = format!("{r:?}");
        assert!(!shown.contains(value.as_str()));
        assert!(shown.contains("[redacted]") && shown.contains("edge-fra"));
        let batch = format!("{:?}", vec![r.clone(), r]);
        assert!(!batch.contains(value.as_str()));
    }

    fn on(node: &str, site: &str) -> ZoneReveal {
        ZoneReveal::new(node, site, zone_value(), "", None, None)
    }

    #[test]
    fn the_same_site_on_two_nodes_keeps_separate_secrets() {
        let all = vec![
            on("edge-fra", "shop"),
            on("edge-iad", "shop"),
            on("edge-fra", "api"),
        ];
        let fra = reveals_for(&all, "edge-fra", "shop");
        assert_eq!(fra.len(), 1);
        assert!(fra[0].is_for("edge-fra", "shop"));
        assert_eq!(reveals_for(&all, "edge-iad", "shop").len(), 1);
        assert!(reveals_for(&all, "edge-sin", "shop").is_empty());
        assert!(reveals_for(&all, "edge-iad", "api").is_empty());
        assert_eq!(
            reveal_nodes_elsewhere(&all, "edge-fra", "shop"),
            vec!["edge-iad"]
        );
        assert!(reveal_nodes_elsewhere(&all, "edge-fra", "api").is_empty());
    }

    #[test]
    fn leaving_for_another_site_drops_every_secret() {
        let mut all = vec![
            on("edge-fra", "shop"),
            on("edge-iad", "shop"),
            on("edge-fra", "api"),
        ];
        keep_for_site(&mut all, Some("shop"));
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|r| r.site == "shop"));
        keep_for_site(&mut all, None);
        assert!(all.is_empty());
    }

    #[test]
    fn the_header_defaults_to_the_documented_name() {
        assert_eq!(reveal().header, "X-Cite-Origin-Secret");
        let named = ZoneReveal::new("n", "s", "x", "X-Other", None, None);
        assert_eq!(named.header, "X-Other");
        assert_eq!(ZONE_HEADER, "X-Cite-Origin-Secret");
    }

    #[test]
    fn reveals_belong_to_one_node_and_site() {
        let r = reveal();
        assert!(r.is_for("edge-fra", "shop"));
        assert!(!r.is_for("edge-iad", "shop"));
        assert!(!r.is_for("edge-fra", "api"));
        assert!(r.secret() == zone_value(), "values differ");
    }

    #[test]
    fn an_unreadable_secret_store_is_not_reported_as_missing() {
        let unreadable = ZoneStatus {
            configured: false,
            readable: false,
            header: ZONE_HEADER.into(),
            created_at: None,
            fingerprint: None,
        };
        let text = status_text(&unreadable);
        assert_eq!(text, UNREADABLE_TEXT);
        assert!(text.contains("could not be read") && text.contains("unknown"));
        assert!(!text.contains("No zone secret"));
        let configured_but_unreadable = ZoneStatus {
            configured: true,
            ..unreadable
        };
        assert_eq!(status_text(&configured_but_unreadable), UNREADABLE_TEXT);
    }

    #[test]
    fn status_and_reveal_text_use_dates_and_short_fingerprints() {
        let configured = ZoneStatus {
            configured: true,
            readable: true,
            header: ZONE_HEADER.into(),
            created_at: Some("2026-11-06T10:00:00Z".into()),
            fingerprint: Some("AB12CD34EF56AA".into()),
        };
        assert_eq!(
            status_text(&configured),
            "A zone secret is set: created 2026-11-06, fingerprint ab12cd34ef56."
        );
        let bare = ZoneStatus {
            created_at: None,
            fingerprint: None,
            ..configured.clone()
        };
        assert_eq!(status_text(&bare), "A zone secret is set.");
        let none = ZoneStatus {
            configured: false,
            ..configured
        };
        assert!(status_text(&none).starts_with("No zone secret"));
        assert_eq!(
            reveal_meta(&reveal()),
            "node edge-fra, created 2026-11-06, fingerprint ab12cd34ef56"
        );
    }

    #[test]
    fn the_cloudflare_steps_name_the_transform_rule_path() {
        let all = CLOUDFLARE_STEPS.join(" ");
        assert!(all.contains("Transform Rules") && all.contains("Modify Request Header"));
        assert!(all.contains("Set static"));
        assert!(NOT_SHOWN_AGAIN.contains("once"));
        assert!(ROTATE_WARNING.contains("403"));
        assert!(rotation_failed("boom").contains("boom"));
    }
}
