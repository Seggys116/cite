use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cite_client::{ClientError, CloudflareToken};
use serde_json::{Value, json};

use crate::alertcfg::{
    AlertsConfig, AlertsRequest, TestResult, demo_alerts, demo_save, demo_test, parse_alerts,
    parse_test_result,
};
use crate::api::{NodeHandle, Res};
use crate::certissue::{
    AcmeListing, IssueOutcome, IssueRequest, Mode, demo_acme_job_id, demo_acme_listing,
    demo_issue_outcome, json_strings, json_text, parse_acme_listing, parse_issue_outcome,
    parse_job_id,
};
use crate::certs::wipe;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// What the node answered to an issue request: a finished certificate, or a Let's Encrypt job to follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueReply {
    Saved(IssueOutcome),
    Job(String),
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn scrub_token(body: &mut Value) {
    if let Some(Value::String(token)) = body.get_mut("cloudflare_token") {
        wipe(token);
    }
}

pub fn error_text(status: u16, body: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let message = parsed.as_ref().and_then(|v| {
        let e = v.get("error").or_else(|| v.get("message"))?;
        e.as_str()
            .or_else(|| e.get("message").and_then(Value::as_str))
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(|m| m.chars().take(300).collect::<String>())
    });
    message.unwrap_or_else(|| format!("the request failed with status {status}"))
}

impl NodeHandle {
    pub async fn tools_issue(&self, mut req: IssueRequest) -> Res<IssueReply> {
        let mode = req.mode;
        let (mut body, mut token) = req.take_parts();
        let c = match self {
            Self::Live(c) => c,
            Self::Demo(..) => {
                wipe(&mut token);
                return Ok(match mode {
                    Mode::Acme => IssueReply::Job(demo_acme_job_id(now_secs())),
                    _ => IssueReply::Saved(demo_issue_outcome(
                        mode,
                        &json_strings(&body, "hosts"),
                        &json_text(&body, "name"),
                    )),
                });
            }
        };
        let answer = match mode {
            Mode::Generate => c.certificate_issue("generate", &body).await,
            Mode::OriginCa => {
                let wrapped = CloudflareToken::new(&token);
                wipe(&mut token);
                match wrapped {
                    Ok(t) => c.certificate_origin_ca(&t, &body).await,
                    Err(e) => Err(e),
                }
            }
            Mode::Acme => {
                if let Some(map) = body.as_object_mut() {
                    map.insert(
                        "cloudflare_token".into(),
                        Value::String(std::mem::take(&mut token)),
                    );
                }
                let out = c.certificate_issue("acme", &body).await;
                scrub_token(&mut body);
                out
            }
        }?;
        match mode {
            Mode::Acme => parse_job_id(&answer)
                .map(IssueReply::Job)
                .map_err(ClientError::Decode),
            _ => Ok(IssueReply::Saved(parse_issue_outcome(&answer))),
        }
    }

    // job_hint only matters in demo mode, where it stands in for the job the node would have remembered.
    pub async fn tools_acme_listing(&self, job_hint: Option<&str>) -> Res<AcmeListing> {
        match self {
            Self::Live(c) => {
                let v = c.acme_jobs().await?;
                parse_acme_listing(&v).map_err(ClientError::Decode)
            }
            Self::Demo(..) => Ok(demo_acme_listing(job_hint, now_secs())),
        }
    }

    pub async fn tools_alerts_load(&self) -> Res<AlertsConfig> {
        match self {
            Self::Live(c) => {
                let v = c.alerts_get().await?;
                parse_alerts(&v).map_err(ClientError::Decode)
            }
            Self::Demo(..) => Ok(demo_alerts()),
        }
    }

    pub async fn tools_alerts_save(&self, req: AlertsRequest) -> Res<AlertsConfig> {
        match self {
            Self::Live(c) => {
                let v = c.alerts_put(req.body()).await?;
                parse_alerts(&v).map_err(ClientError::Decode)
            }
            Self::Demo(..) => Ok(demo_save(&req)),
        }
    }

    // The client's own test call sends no target, so this goes through the generic forwarder to name one.
    pub async fn tools_alerts_test(&self, target: &str) -> Res<TestResult> {
        let c = match self {
            Self::Live(c) => c,
            Self::Demo(..) => return Ok(demo_test(target)),
        };
        let method = match "POST".parse() {
            Ok(m) => m,
            Err(_) => return Err(ClientError::Config("cannot build the request".into())),
        };
        let body = serde_json::to_vec(&json!({ "target": target }))
            .map_err(|_| ClientError::Config("cannot build the request".into()))?;
        let sent = c
            .forward(method, "alerts/test", None, body, TEST_TIMEOUT)
            .await?;
        if !(200..300).contains(&sent.status) {
            return Err(ClientError::Status {
                code: sent.status,
                message: error_text(sent.status, &sent.body),
            });
        }
        let v: Value = serde_json::from_slice(&sent.body)
            .map_err(|_| ClientError::Decode("malformed test answer".into()))?;
        Ok(parse_test_result(&v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_error_bodies_give_their_message() {
        assert_eq!(error_text(400, br#"{"error":"bad hosts"}"#), "bad hosts");
        assert_eq!(error_text(400, br#"{"message":" nope "}"#), "nope");
        assert_eq!(error_text(400, br#"{"error":{"message":"deep"}}"#), "deep");
    }

    #[test]
    fn unreadable_error_bodies_fall_back_to_the_status() {
        for body in [&b""[..], b"<html>", br#"{"error":""}"#, br#"{"x":1}"#] {
            assert_eq!(error_text(502, body), "the request failed with status 502");
        }
    }

    #[test]
    fn long_error_messages_are_cut() {
        let body = format!(r#"{{"error":"{}"}}"#, "e".repeat(1000));
        assert_eq!(error_text(500, body.as_bytes()).chars().count(), 300);
    }

    #[test]
    fn the_token_is_wiped_from_a_request_tree() {
        let mut body =
            json!({ "cloudflare_token": "secret-token-value", "hosts": ["a.example.com"] });
        scrub_token(&mut body);
        assert_eq!(body["cloudflare_token"], "");
        assert_eq!(body["hosts"][0], "a.example.com");
    }
}
