use std::sync::Arc;

use cite_edge::model::EdgeConfig;
use cite_edge::validate::validate_config;

use crate::haproxy::{Haproxy, needs_live_haproxy};
use crate::store::Store;
use crate::{ConnectorError, Result};

// What became of the attempt to undo a change that HAProxy did not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rollback {
    Done,
    // The previous configuration could not be written back to the store.
    StoreFailed,
    // The store is back, but HAProxy did not confirm loading it.
    NotConfirmed,
}

impl Rollback {
    pub(crate) fn failed(self) -> bool {
        self != Rollback::Done
    }

    pub(crate) fn phrase(self) -> &'static str {
        match self {
            Rollback::Done => "which was rolled back",
            Rollback::StoreFailed => {
                "and the rollback FAILED: the stored configuration could not be restored"
            }
            Rollback::NotConfirmed => {
                "and the rollback FAILED: haproxy did not confirm the restored configuration"
            }
        }
    }
}

// Writes the previous config back and loads it again; every outcome except success is audited under its own name.
pub(crate) async fn roll_back(
    store: &Store,
    haproxy: &Haproxy,
    actor: &str,
    action: &str,
    previous: Arc<EdgeConfig>,
) -> Rollback {
    let snapshot = Arc::clone(&previous);
    let restored = store
        .update_detailed(actor, "config.rollback", action, move |cfg| {
            *cfg = (*snapshot).clone();
            Ok(())
        })
        .await;
    if let Err(e) = restored {
        tracing::error!(error = %e, "could not restore the previous configuration");
        store.audit(actor, "config.rollback_failed", action).await;
        return Rollback::StoreFailed;
    }
    match haproxy
        .apply(&previous)
        .await
        .and_then(|applied| applied.require_loaded())
    {
        Ok(()) => Rollback::Done,
        Err(e) => {
            tracing::warn!(error = %e, "haproxy could not re-apply the restored configuration");
            store
                .audit(actor, "config.rollback_unconfirmed", action)
                .await;
            Rollback::NotConfirmed
        }
    }
}

// The error a caller returns when a change was refused: the original reason, and plainly whether the undo worked.
pub(crate) fn failure(err: ConnectorError, strict: bool, rollback: Rollback) -> ConnectorError {
    match err {
        ConnectorError::BadRequest(msg) if rollback.failed() => {
            ConnectorError::BadRequest(format!("{msg} ({})", rollback.phrase()))
        }
        ConnectorError::BadRequest(msg) => ConnectorError::BadRequest(msg),
        other if strict => ConnectorError::Unavailable(format!(
            "haproxy must be running to apply this protection change, {}: {}",
            rollback.phrase(),
            reason(&other)
        )),
        other if rollback.failed() => ConnectorError::Unavailable(format!(
            "haproxy could not apply the change, {}: {}",
            rollback.phrase(),
            reason(&other)
        )),
        other => ConnectorError::Unavailable(format!(
            "haproxy could not apply the change: {}",
            reason(&other)
        )),
    }
}

// Internal errors carry paths and I/O detail that stay in the log; HAProxy's own (already scrubbed) replies pass through.
pub(crate) fn reason(err: &ConnectorError) -> String {
    match err {
        ConnectorError::Internal(detail) => {
            tracing::warn!(error = %detail, "applying a configuration change failed");
            "the node could not apply it, see the connector log".to_string()
        }
        other => other.to_string(),
    }
}

// The one way a configuration change is stored and applied: validated and dry-rendered first, applied with the strict or tolerant rule, undone and re-applied when HAProxy does not take it. The caller holds the config lock.
pub(crate) async fn mutate_and_apply<T>(
    store: &Store,
    haproxy: &Haproxy,
    actor: &str,
    action: &str,
    detail: &str,
    change: impl FnOnce(&mut EdgeConfig) -> Result<T>,
) -> Result<T> {
    let previous = store.config();
    let out = store
        .update_detailed(actor, action, detail, |cfg| {
            let value = change(cfg)?;
            validate_config(cfg)?;
            haproxy.check_render(cfg)?;
            Ok(value)
        })
        .await?;
    let applied = haproxy.apply(&store.config()).await;
    let strict = needs_live_haproxy(&previous, &store.config());
    let pending = applied.as_ref().is_ok_and(|o| !o.running);
    match applied.and_then(|o| o.require(strict)) {
        Ok(()) => {
            if pending {
                store.audit(actor, "config.pending", action).await;
            }
            Ok(out)
        }
        Err(err) => {
            let rollback = roll_back(store, haproxy, actor, action, previous).await;
            Err(failure(err, strict, rollback))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_detail_stays_out_of_the_client_message() {
        let err = ConnectorError::Internal("cannot write /conf/haproxy/x.cfg: disk full".into());
        for strict in [false, true] {
            for rollback in [Rollback::Done, Rollback::StoreFailed] {
                let text = failure(
                    ConnectorError::Internal("cannot write /conf/x: disk full".into()),
                    strict,
                    rollback,
                )
                .to_string();
                assert!(
                    !text.contains("/conf") && !text.contains("disk full"),
                    "{text}"
                );
                assert!(text.contains("haproxy"), "{text}");
            }
        }
        let text = failure(err, false, Rollback::StoreFailed).to_string();
        assert!(text.contains("rollback FAILED"), "{text}");
    }

    #[test]
    fn haproxy_own_replies_still_reach_the_client() {
        let text = failure(
            ConnectorError::Unavailable("haproxy reload refused: bad bind".into()),
            false,
            Rollback::Done,
        )
        .to_string();
        assert!(text.contains("bad bind"), "{text}");
    }
}
