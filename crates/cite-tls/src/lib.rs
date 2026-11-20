//! Shared TLS setup for every outbound HTTPS client in Cite.
//!
//! reqwest is built with `rustls-no-provider`, so the crypto provider (ring) is installed here once
//! per process and trust comes from the bundled Mozilla roots, never the host's CA store.

use std::sync::Once;

use reqwest::{Certificate, ClientBuilder};

static PROVIDER: Once = Once::new();

/// Installs ring as the process-wide rustls provider. Safe to call repeatedly; a provider that
/// another component installed first is kept.
pub fn install_ring_provider() {
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The bundled public roots as reqwest certificates.
fn bundled_roots() -> impl Iterator<Item = Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| Certificate::from_der(der.as_ref()).ok())
}

/// A client builder that trusts only the bundled public roots, with the ring provider installed.
pub fn client_builder() -> ClientBuilder {
    install_ring_provider();
    reqwest::Client::builder().tls_certs_only(bundled_roots())
}

/// A client builder that trusts only the given certificates (for example a node's private CA), with
/// the ring provider installed. No public roots are included.
pub fn client_builder_with_roots(roots: impl IntoIterator<Item = Certificate>) -> ClientBuilder {
    install_ring_provider();
    reqwest::Client::builder().tls_certs_only(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_roots_all_parse() {
        let total = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len();
        assert!(total > 100);
        assert_eq!(bundled_roots().count(), total);
    }

    #[test]
    fn client_builds_with_ring_provider_and_bundled_roots() {
        let client = client_builder().build();
        assert!(client.is_ok());
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "ring provider installed as process default"
        );
    }

    #[test]
    fn install_is_idempotent() {
        install_ring_provider();
        install_ring_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn private_root_builder_builds_without_public_roots() {
        assert!(client_builder_with_roots(Vec::new()).build().is_ok());
    }
}
