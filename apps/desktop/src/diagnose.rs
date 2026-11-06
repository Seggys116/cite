use cite_edge::model::{DeployAction, Deployment, Site, Slot};
use serde_json::Value;

pub const LOG_TAIL: u32 = 200;

// The node reports only a status per target, never why a probe failed, and has no log endpoint yet.
pub const NO_REASON_NOTE: &str = "The node reports only whether each target passes its health check, not why a check fails, and it has no log endpoint yet. The commands below read the logs on the node itself.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogCommand {
    pub label: &'static str,
    pub explains: &'static str,
    pub slot: Slot,
    pub command: String,
}

// Containers are named cite-<site>-<slot>-<role> by the node's orchestrator.
pub fn container_name(site_id: &str, slot: Slot, role: &str) -> String {
    format!("cite-{site_id}-{}-{role}", slot.as_str())
}

pub fn log_commands(site_id: &str, slot: Slot) -> Vec<LogCommand> {
    let line = |role: &str| {
        format!(
            "docker logs --tail {LOG_TAIL} {}",
            container_name(site_id, slot, role)
        )
    };
    vec![
        LogCommand {
            label: "Build and fetch log",
            explains: "Cloning, installing and building the repository",
            slot,
            command: line("manager"),
        },
        LogCommand {
            label: "Runtime log",
            explains: "The running site's own output",
            slot,
            command: line("executor"),
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetHealth {
    pub addr: String,
    pub status: String,
}

// Reads one slot of the live block GET /sites/{id} returns.
pub fn slot_targets(live: Option<&Value>, slot: Slot) -> Vec<TargetHealth> {
    live.and_then(|l| l.get(slot.as_str()))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|t| TargetHealth {
                    addr: t
                        .get("addr")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_string(),
                    status: t
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("UNKNOWN")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    NoTargets,
    Healthy,
    Degraded,
    Down,
    Unknown,
}

fn is_up(status: &str) -> bool {
    status.to_ascii_uppercase().starts_with("UP")
}

pub fn slot_state(targets: &[TargetHealth]) -> SlotState {
    if targets.is_empty() {
        return SlotState::NoTargets;
    }
    let up = targets.iter().filter(|t| is_up(&t.status)).count();
    if up == targets.len() {
        SlotState::Healthy
    } else if targets
        .iter()
        .all(|t| t.status.eq_ignore_ascii_case("UNKNOWN"))
    {
        SlotState::Unknown
    } else if up == 0 {
        SlotState::Down
    } else {
        SlotState::Degraded
    }
}

impl SlotState {
    pub fn label(self) -> &'static str {
        match self {
            SlotState::NoTargets => "no targets",
            SlotState::Healthy => "healthy",
            SlotState::Degraded => "partly down",
            SlotState::Down => "down",
            SlotState::Unknown => "no health data yet",
        }
    }

    pub fn is_bad(self) -> bool {
        matches!(self, SlotState::Degraded | SlotState::Down)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotLine {
    pub slot: Slot,
    pub active: bool,
    pub state: SlotState,
    pub targets: Vec<TargetHealth>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureNote {
    pub at: String,
    pub slot: Slot,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Banner {
    pub headline: String,
    pub failure: Option<FailureNote>,
    pub slots: Vec<SlotLine>,
    pub commands: Vec<LogCommand>,
    pub checks: Vec<String>,
}

// The newest Failed entry; history is stored oldest first.
pub fn newest_failure(history: &[Deployment]) -> Option<&Deployment> {
    history
        .iter()
        .rev()
        .find(|d| d.action == DeployAction::Failed)
}

// A failure only counts while nothing newer has happened, so a later successful deploy clears it.
pub fn last_deploy_failed(history: &[Deployment]) -> bool {
    history
        .last()
        .is_some_and(|d| d.action == DeployAction::Failed)
}

fn slot_line(site: &Site, live: Option<&Value>, slot: Slot) -> SlotLine {
    let targets = slot_targets(live, slot);
    SlotLine {
        slot,
        active: site.active == slot,
        state: slot_state(&targets),
        targets,
    }
}

fn checks_for(site: &Site, failure: Option<&FailureNote>) -> Vec<String> {
    let mut out = Vec::new();
    let note = failure.map(|f| f.note.to_lowercase()).unwrap_or_default();
    if site.source.is_some() {
        out.push(
            "Read the build and fetch log of the slot that failed: it shows the clone, install and build output."
                .to_string(),
        );
        out.push(
            "If the build succeeded but the site did not come up, read the runtime log."
                .to_string(),
        );
        out.push(
            "Check that the repository, branch, runtime and Node version below match your project, then Save and redeploy."
                .to_string(),
        );
        if note.contains("stack could not be started") {
            out.push(
                "The node could not start the containers; the message above comes from Docker. Check the node's disk space, the images and registry access."
                    .to_string(),
            );
        }
    } else {
        out.push(
            "Check that every target accepts connections from the node and is listed as host:port."
                .to_string(),
        );
    }
    if note.contains("health check") || note.is_empty() {
        out.push(format!(
            "The site must answer {} with a success status; check the health check path below.",
            site.health.path
        ));
    }
    out
}

// What the banner at the top of the site page says, or None when nothing is wrong.
pub fn banner(site: &Site, live: Option<&Value>) -> Option<Banner> {
    let slots = vec![
        slot_line(site, live, Slot::Blue),
        slot_line(site, live, Slot::Green),
    ];
    let active = slots.iter().find(|s| s.active).map(|s| s.state);
    let failed = last_deploy_failed(&site.history);
    let unhealthy = active.is_some_and(SlotState::is_bad);
    if !failed && !unhealthy {
        return None;
    }
    let failure = failed
        .then(|| newest_failure(&site.history))
        .flatten()
        .map(|d| FailureNote {
            at: d.at.clone(),
            slot: d.slot,
            note: d.note.clone(),
        });
    let headline = match (&failure, unhealthy) {
        (Some(f), true) => format!(
            "The last deployment to {} failed and the active slot is unhealthy",
            f.slot.as_str()
        ),
        (Some(f), false) => format!("The last deployment to {} failed", f.slot.as_str()),
        (None, _) => format!("The active {} slot is not healthy", site.active.as_str()),
    };
    let mut commands = Vec::new();
    if site.source.is_some() {
        let mut covered: Vec<Slot> = Vec::new();
        if let Some(f) = &failure {
            covered.push(f.slot);
        }
        if unhealthy && !covered.contains(&site.active) {
            covered.push(site.active);
        }
        for slot in covered {
            commands.extend(log_commands(&site.id, slot));
        }
    }
    let checks = checks_for(site, failure.as_ref());
    Some(Banner {
        headline,
        failure,
        slots,
        commands,
        checks,
    })
}

// What a finished deploy means for the owner, with the node's own note kept in full when it failed.
pub fn deploy_outcome(d: &Deployment) -> Result<String, String> {
    if d.action == DeployAction::Failed {
        Err(if d.note.is_empty() {
            "The deploy failed. The active slot was left untouched.".to_string()
        } else {
            format!(
                "The deploy failed: {}. The active slot was left untouched.",
                d.note
            )
        })
    } else {
        Ok(format!(
            "Deployed. The {} slot is now active.",
            d.slot.as_str()
        ))
    }
}

// The message after Save, with or without the redeploy that follows it.
pub fn save_outcome(deploy: Option<&Result<Deployment, String>>) -> Result<String, String> {
    match deploy {
        None => Ok("Saved".to_string()),
        Some(Ok(d)) => match deploy_outcome(d) {
            Ok(_) => Ok(format!(
                "Saved and redeployed. The {} slot is now active.",
                d.slot.as_str()
            )),
            Err(e) => Err(format!("Saved, but the redeploy failed. {e}")),
        },
        Some(Err(e)) => Err(format!("Saved, but the redeploy failed: {e}")),
    }
}

// The text the Copy button puts on the clipboard for a failure.
pub fn failure_text(f: &FailureNote) -> String {
    format!("{} ({} slot): {}", f.at, f.slot.as_str(), f.note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::{HealthCheck, Maintenance, SiteAccess, SiteKind, Source, Upstream};
    use serde_json::json;

    fn dep(action: DeployAction, slot: Slot, note: &str, at: &str) -> Deployment {
        Deployment {
            id: format!("d-{at}"),
            at: at.into(),
            slot,
            action,
            note: note.into(),
        }
    }

    fn site(source: bool, history: Vec<Deployment>) -> Site {
        Site {
            id: "docs".into(),
            name: "Docs".into(),
            hosts: vec!["docs.example.com".into()],
            path_prefixes: Vec::new(),
            path_regexes: Vec::new(),
            kind: SiteKind::Site,
            blue: Upstream {
                targets: Vec::new(),
                label: None,
            },
            green: Upstream {
                targets: Vec::new(),
                label: None,
            },
            active: Slot::Blue,
            maintenance: Maintenance::default(),
            health: HealthCheck::default(),
            source: source.then(|| Source {
                repo: "acme/docs".into(),
                ..Default::default()
            }),
            history,
            access: SiteAccess::default(),
        }
    }

    fn live(blue: &[(&str, &str)], green: &[(&str, &str)]) -> Value {
        let list = |items: &[(&str, &str)]| {
            items
                .iter()
                .map(|(a, s)| json!({"addr": a, "status": s}))
                .collect::<Vec<_>>()
        };
        json!({"blue": list(blue), "green": list(green)})
    }

    #[test]
    fn container_names_follow_the_orchestrator() {
        assert_eq!(
            container_name("docs", Slot::Green, "manager"),
            "cite-docs-green-manager"
        );
        assert_eq!(
            container_name("my-shop-2", Slot::Blue, "executor"),
            "cite-my-shop-2-blue-executor"
        );
        let cmds = log_commands("docs", Slot::Green);
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0].command,
            "docker logs --tail 200 cite-docs-green-manager"
        );
        assert_eq!(
            cmds[1].command,
            "docker logs --tail 200 cite-docs-green-executor"
        );
        assert!(cmds[0].label.contains("Build") && cmds[1].label.contains("Runtime"));
        assert!(
            cmds.iter()
                .all(|c| c.slot == Slot::Green && !c.explains.is_empty())
        );
    }

    #[test]
    fn slot_health_is_read_from_the_live_block() {
        let l = live(&[("10.0.0.1:80", "UP"), ("10.0.0.2:80", "DOWN")], &[]);
        let t = slot_targets(Some(&l), Slot::Blue);
        assert_eq!(t.len(), 2);
        assert_eq!(
            t[1],
            TargetHealth {
                addr: "10.0.0.2:80".into(),
                status: "DOWN".into()
            }
        );
        assert!(slot_targets(Some(&l), Slot::Green).is_empty());
        assert!(slot_targets(None, Slot::Blue).is_empty());
        assert!(slot_targets(Some(&json!({"blue": "nope"})), Slot::Blue).is_empty());
        let odd = json!({"blue": [{"addr": 5}, {"status": "UP"}]});
        let t = slot_targets(Some(&odd), Slot::Blue);
        assert_eq!((t[0].addr.as_str(), t[0].status.as_str()), ("?", "UNKNOWN"));
    }

    #[test]
    fn slot_states_cover_every_mix() {
        let t = |s: &[&str]| -> Vec<TargetHealth> {
            s.iter()
                .map(|x| TargetHealth {
                    addr: "a:1".into(),
                    status: (*x).into(),
                })
                .collect()
        };
        assert_eq!(slot_state(&[]), SlotState::NoTargets);
        assert_eq!(slot_state(&t(&["UP", "UP"])), SlotState::Healthy);
        assert_eq!(slot_state(&t(&["UP 1/3", "up"])), SlotState::Healthy);
        assert_eq!(slot_state(&t(&["UP", "DOWN"])), SlotState::Degraded);
        assert_eq!(slot_state(&t(&["DOWN", "DOWN"])), SlotState::Down);
        assert_eq!(slot_state(&t(&["DOWN", "UNKNOWN"])), SlotState::Down);
        assert_eq!(slot_state(&t(&["UNKNOWN"])), SlotState::Unknown);
        assert_eq!(slot_state(&t(&["MAINT"])), SlotState::Down);
        assert!(SlotState::Down.is_bad() && SlotState::Degraded.is_bad());
        assert!(
            !SlotState::Healthy.is_bad()
                && !SlotState::Unknown.is_bad()
                && !SlotState::NoTargets.is_bad()
        );
        for s in [
            SlotState::NoTargets,
            SlotState::Healthy,
            SlotState::Degraded,
            SlotState::Down,
            SlotState::Unknown,
        ] {
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn the_newest_failure_is_found_and_a_later_success_clears_it() {
        let h = vec![
            dep(
                DeployAction::Promote,
                Slot::Blue,
                "first",
                "2025-01-01T00:00:00Z",
            ),
            dep(
                DeployAction::Failed,
                Slot::Green,
                "old failure",
                "2025-01-02T00:00:00Z",
            ),
            dep(
                DeployAction::Failed,
                Slot::Green,
                "new failure",
                "2025-01-03T00:00:00Z",
            ),
        ];
        assert_eq!(newest_failure(&h).unwrap().note, "new failure");
        assert!(last_deploy_failed(&h));
        let mut healed = h.clone();
        healed.push(dep(
            DeployAction::Promote,
            Slot::Green,
            "fixed",
            "2025-01-04T00:00:00Z",
        ));
        assert!(!last_deploy_failed(&healed));
        assert_eq!(newest_failure(&healed).unwrap().note, "new failure");
        assert!(newest_failure(&[]).is_none() && !last_deploy_failed(&[]));
    }

    #[test]
    fn a_failed_deploy_shows_the_full_note_the_commands_and_what_to_check() {
        let note = "green slot did not pass health checks within 120s (Release 4.2.0)";
        let s = site(
            true,
            vec![
                dep(
                    DeployAction::Promote,
                    Slot::Blue,
                    "Initial",
                    "2025-01-01T00:00:00Z",
                ),
                dep(
                    DeployAction::Failed,
                    Slot::Green,
                    note,
                    "2025-01-02T00:00:00Z",
                ),
            ],
        );
        let b = banner(&s, Some(&live(&[("127.0.0.1:3100", "UP")], &[]))).expect("banner");
        assert_eq!(b.headline, "The last deployment to green failed");
        let f = b.failure.clone().expect("failure");
        assert_eq!(f.note, note);
        assert_eq!(f.slot, Slot::Green);
        assert_eq!(
            failure_text(&f),
            format!("2025-01-02T00:00:00Z (green slot): {note}")
        );
        assert_eq!(b.commands.len(), 2);
        assert!(b.commands[0].command.ends_with("cite-docs-green-manager"));
        assert_eq!(b.slots.len(), 2);
        assert!(b.slots[0].active && b.slots[0].state == SlotState::Healthy);
        assert_eq!(b.slots[1].state, SlotState::NoTargets);
        assert!(b.checks.iter().any(|c| c.contains("build and fetch log")));
        assert!(b.checks.iter().any(|c| c.contains("health check path")));
        assert!(NO_REASON_NOTE.contains("no log endpoint"));
    }

    #[test]
    fn a_start_failure_points_at_docker_and_a_healthy_site_has_no_banner() {
        let s = site(
            true,
            vec![dep(
                DeployAction::Failed,
                Slot::Green,
                "stack could not be started: pull access denied",
                "2025-01-02T00:00:00Z",
            )],
        );
        let b = banner(&s, None).expect("banner");
        assert!(b.checks.iter().any(|c| c.contains("disk space")));
        assert!(!b.checks.iter().any(|c| c.contains("health check path")));
        let ok = site(
            true,
            vec![dep(
                DeployAction::Promote,
                Slot::Blue,
                "fine",
                "2025-01-01T00:00:00Z",
            )],
        );
        assert!(banner(&ok, Some(&live(&[("a:1", "UP")], &[]))).is_none());
        assert!(banner(&ok, None).is_none());
        assert!(banner(&site(true, Vec::new()), None).is_none());
    }

    #[test]
    fn an_unhealthy_active_slot_alone_raises_the_banner() {
        let s = site(
            true,
            vec![dep(
                DeployAction::Promote,
                Slot::Blue,
                "ok",
                "2025-01-01T00:00:00Z",
            )],
        );
        let l = live(&[("a:1", "DOWN"), ("b:1", "UP")], &[]);
        let b = banner(&s, Some(&l)).expect("banner");
        assert_eq!(b.headline, "The active blue slot is not healthy");
        assert!(b.failure.is_none());
        assert_eq!(b.commands.len(), 2);
        assert!(b.commands[0].command.contains("cite-docs-blue-manager"));
        assert_eq!(b.slots[0].state, SlotState::Degraded);
    }

    #[test]
    fn both_a_failure_and_a_down_slot_cover_both_slots_once() {
        let mut s = site(
            true,
            vec![dep(
                DeployAction::Failed,
                Slot::Green,
                "boom",
                "2025-01-02T00:00:00Z",
            )],
        );
        let l = live(&[("a:1", "DOWN")], &[]);
        let b = banner(&s, Some(&l)).expect("banner");
        assert_eq!(
            b.headline,
            "The last deployment to green failed and the active slot is unhealthy"
        );
        assert_eq!(b.commands.len(), 4);
        s.history[0].slot = Slot::Blue;
        let same = banner(&s, Some(&l)).expect("banner");
        assert_eq!(same.commands.len(), 2);
    }

    #[test]
    fn deploy_and_save_outcomes_keep_the_nodes_words() {
        let ok = dep(
            DeployAction::Promote,
            Slot::Green,
            "Release 2",
            "2025-01-01T00:00:00Z",
        );
        assert_eq!(
            deploy_outcome(&ok).unwrap(),
            "Deployed. The green slot is now active."
        );
        let bad = dep(
            DeployAction::Failed,
            Slot::Green,
            "green slot did not pass health checks within 120s",
            "2025-01-01T00:00:00Z",
        );
        let err = deploy_outcome(&bad).unwrap_err();
        assert!(
            err.contains("did not pass health checks within 120s") && err.contains("untouched")
        );
        let quiet = dep(DeployAction::Failed, Slot::Blue, "", "2025-01-01T00:00:00Z");
        assert!(deploy_outcome(&quiet).unwrap_err().contains("untouched"));

        assert_eq!(save_outcome(None).unwrap(), "Saved");
        let promoted: Result<Deployment, String> = Ok(ok);
        assert!(
            save_outcome(Some(&promoted))
                .unwrap()
                .starts_with("Saved and redeployed")
        );
        let failed: Result<Deployment, String> = Ok(bad);
        let msg = save_outcome(Some(&failed)).unwrap_err();
        assert!(msg.starts_with("Saved, but the redeploy failed.") && msg.contains("120s"));
        let refused: Result<Deployment, String> =
            Err("409: deploy failed health checks: the green slot of docs never came up".into());
        let msg = save_outcome(Some(&refused)).unwrap_err();
        assert!(msg.contains("never came up") && msg.starts_with("Saved, but"));
    }

    #[test]
    fn server_sites_get_no_container_commands() {
        let s = site(
            false,
            vec![dep(
                DeployAction::Failed,
                Slot::Green,
                "Health check timed out",
                "2025-01-02T00:00:00Z",
            )],
        );
        let b = banner(&s, None).expect("banner");
        assert!(b.commands.is_empty());
        assert!(b.checks.iter().any(|c| c.contains("accepts connections")));
        assert!(!b.checks.iter().any(|c| c.contains("build and fetch log")));
    }
}
