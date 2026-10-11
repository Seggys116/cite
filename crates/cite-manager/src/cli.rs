use cite_core::{ControlRequest, ManagerConfig};

use crate::socket;
use crate::{ManagerError, Result};

fn load_cfg() -> Result<ManagerConfig> {
    Ok(ManagerConfig::load()?)
}

pub fn send(req: ControlRequest) -> Result<()> {
    let cfg = load_cfg()?;
    let resp = socket::request(&cfg.socket_path, &req)?;
    if resp.ok {
        if let Some(data) = resp.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Ok(())
    } else {
        Err(ManagerError::new(
            resp.error.unwrap_or_else(|| "request failed".into()),
        ))
    }
}

pub fn healthcheck() -> Result<()> {
    let cfg = load_cfg()?;
    let resp = socket::request(&cfg.socket_path, &ControlRequest::Healthcheck)?;
    if resp.ok {
        Ok(())
    } else {
        Err(ManagerError::new(
            resp.error.unwrap_or_else(|| "unhealthy".into()),
        ))
    }
}

pub fn status(json: bool) -> Result<()> {
    let cfg = load_cfg()?;
    let resp = socket::request(&cfg.socket_path, &ControlRequest::Status)?;
    if !resp.ok {
        return Err(ManagerError::new(
            resp.error.unwrap_or_else(|| "status failed".into()),
        ));
    }
    let data = resp.data.unwrap_or(serde_json::Value::Null);
    if json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        print!("{}", format_status_human(&data));
    }
    Ok(())
}

pub fn format_status_human(data: &serde_json::Value) -> String {
    let text = |key: &str| {
        data.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("none")
            .to_string()
    };
    let executor = data.get("executor");
    let live_sha = text("last_deployed_sha");
    let reported = data
        .get("executor_reported")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let slot = match executor
        .and_then(|e| e.get("active_slot"))
        .and_then(|v| v.as_str())
    {
        Some(slot) => slot,
        None if live_sha != "none" && !reported => "pending (executor not reported)",
        None => "none",
    };
    let heartbeat = executor
        .and_then(|e| e.get("updated_at"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let requests = executor
        .and_then(|e| e.get("requests"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let responsive = if data
        .get("executor_unresponsive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        "unresponsive"
    } else {
        "ok"
    };
    let disk = data
        .get("disk_free_bytes")
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".into());
    format!(
        "live sha: {}\nslot: {slot}\nprevious failure: {} ({})\nlast observed: {}\nnext poll: {}\nexecutor: {responsive} (heartbeat {heartbeat}, requests {requests})\ndisk free bytes: {disk}\ntoken invalid: {}\ntoken expires: {}\n",
        live_sha,
        text("last_failed_sha"),
        text("last_failed_reason"),
        text("last_observed_sha"),
        text("next_poll_at"),
        data.get("token_invalid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        text("token_expires_at"),
    )
}

pub fn config_check() -> Result<()> {
    let cfg = load_cfg()?;
    println!("{}", cfg.redacted_display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::format_status_human;

    #[test]
    fn human_status_is_not_json() {
        let data = serde_json::json!({
            "last_deployed_sha": "abc",
            "last_failed_sha": null,
            "last_failed_reason": "",
            "last_observed_sha": "abc",
            "next_poll_at": "2026-01-01T00:00:00Z",
            "token_invalid": false,
            "token_expires_at": null,
            "executor_unresponsive": false,
            "disk_free_bytes": 10,
            "executor": {"active_slot": "blue", "updated_at": "2026-01-01T00:00:00Z", "requests": 3}
        });
        let text = format_status_human(&data);
        assert!(text.contains("live sha: abc"));
        assert!(text.contains("slot: blue"));
        assert!(text.contains("executor: ok"));
        assert!(text.contains("requests 3"));
        assert!(!text.trim_start().starts_with('{'));
    }

    fn restart_status(reported: bool, sha: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "last_deployed_sha": sha,
            "executor_unresponsive": true,
            "executor_reported": reported,
            "executor": null
        })
    }

    #[test]
    fn slot_is_pending_when_a_live_sha_has_no_executor_report() {
        let text = format_status_human(&restart_status(false, "abc".into()));
        assert!(text.contains("live sha: abc"));
        assert!(text.contains("slot: pending (executor not reported)"));
    }

    #[test]
    fn slot_stays_none_without_a_live_sha() {
        let text = format_status_human(&restart_status(false, serde_json::Value::Null));
        assert!(text.contains("slot: none"));
        assert!(!text.contains("pending"));
    }

    #[test]
    fn a_reported_executor_shows_its_slot_not_pending() {
        let mut data = restart_status(true, "abc".into());
        data["executor"] = serde_json::json!({"active_slot": "green"});
        let text = format_status_human(&data);
        assert!(text.contains("slot: green"));
        assert!(!text.contains("pending"));
    }
}
