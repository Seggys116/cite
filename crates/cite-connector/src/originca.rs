use crate::certs::{self, Generated};
use crate::cfapi::{CfToken, Cloudflare, Http};
use crate::{ConnectorError, Result};

// The validity periods Cloudflare's Origin CA accepts, in days.
pub const VALIDITY_DAYS: [u32; 7] = [7, 30, 90, 365, 730, 1095, 5475];
pub const DEFAULT_VALIDITY_DAYS: u32 = 5475;

pub fn check_validity(days: u32) -> Result<()> {
    if VALIDITY_DAYS.contains(&days) {
        Ok(())
    } else {
        Err(ConnectorError::BadRequest(format!(
            "validity_days must be one of {}",
            VALIDITY_DAYS.map(|d| d.to_string()).join(", ")
        )))
    }
}

// The key is made here and only the signing request leaves the node; Cloudflare signs it with its Origin CA.
pub async fn issue(http: &Http, token: &CfToken, hosts: &[String], days: u32) -> Result<Generated> {
    check_validity(days)?;
    let request = certs::key_and_csr(hosts)?;
    let chain_pem = Cloudflare::new(http, token)
        .origin_ca(&request.csr_pem, hosts, days)
        .await?;
    Ok(Generated {
        chain_pem,
        key_pem: request.key_pem,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::acme::mock;

    fn names(hosts: &[&str]) -> Vec<String> {
        hosts.iter().map(|h| h.to_string()).collect()
    }

    #[test]
    fn only_cloudflare_validity_periods_are_accepted() {
        for days in VALIDITY_DAYS {
            assert!(check_validity(days).is_ok(), "{days}");
        }
        for days in [0, 1, 8, 366, 5474, 5476] {
            assert!(check_validity(days).is_err(), "{days}");
        }
        assert!(VALIDITY_DAYS.contains(&DEFAULT_VALIDITY_DAYS));
    }

    #[tokio::test]
    async fn a_bearer_token_gets_a_certificate_for_our_own_key() {
        let server = mock::start().await;
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        let token = CfToken::parse(mock::TOKEN).expect("token");
        let hosts = names(&["shop.example.com", "*.shop.example.com"]);
        let generated = issue(&http, &token, &hosts, 365).await.expect("issued");
        let now = i64::try_from(crate::store::now_unix()).expect("clock");
        let prepared = generated
            .prepare(now, &hosts, None)
            .expect("the certificate matches the key made on the node");
        assert!(prepared.info.issuer.contains(mock::CA_NAME));
        let call = server
            .with(|s| s.origin_calls.last().cloned())
            .expect("one call");
        assert_eq!(call.auth, "bearer");
        assert_eq!(call.request_type, "origin-ecc");
        assert_eq!(call.validity, 365);
        assert_eq!(call.hostnames, hosts);
        assert_eq!(call.csr.sans, hosts);
        assert_eq!(call.csr.key_len, 65);
        assert_eq!(call.csr.common_name.as_deref(), Some("shop.example.com"));
    }

    #[tokio::test]
    async fn a_legacy_origin_ca_key_uses_its_own_header() {
        let server = mock::start().await;
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        let token = CfToken::parse(mock::SERVICE_KEY).expect("token");
        issue(&http, &token, &names(&["shop.example.com"]), 7)
            .await
            .expect("issued");
        let call = server
            .with(|s| s.origin_calls.last().cloned())
            .expect("one call");
        assert_eq!(call.auth, "service-key");
        assert_eq!(call.validity, 7);
    }

    #[tokio::test]
    async fn cloudflare_errors_never_echo_the_token() {
        let server = mock::start().await;
        server.with(|s| s.script.fail_origin = true);
        let http = Http::new(Arc::new(server.endpoints())).expect("client");
        for raw in [mock::TOKEN, mock::SERVICE_KEY] {
            let token = CfToken::parse(raw).expect("token");
            let err = issue(&http, &token, &names(&["shop.example.com"]), 90)
                .await
                .unwrap_err();
            let text = err.to_string();
            assert!(matches!(err, ConnectorError::BadRequest(_)), "{text}");
            assert!(text.contains("Cloudflare refused"), "{text}");
            assert!(text.contains("[redacted]"), "{text}");
            assert!(!text.contains(raw), "{text}");
        }
        let wrong = CfToken::parse("wrong-token").expect("token");
        let err = issue(&http, &wrong, &names(&["shop.example.com"]), 90)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 403"), "{err}");
        assert!(server.with(|s| s.origin_calls.is_empty()));
    }
}
