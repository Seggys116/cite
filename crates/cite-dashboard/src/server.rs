use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::ConnectInfo;
use cite_client::{ConfigFile, JsonTokenStore, TokenStore};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::api;
use crate::error::{Error, Result};
use crate::settings::{DEFAULT_PORT, Settings, TlsFiles};
use crate::state::AppState;

fn tls_err(msg: impl Into<String>) -> Error {
    Error::Setup(msg.into())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| tls_err(format!("cannot read {}: {e}", path.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| tls_err(format!("invalid certificate in {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(tls_err(format!(
            "no certificate found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| tls_err(format!("no usable private key in {}: {e}", path.display())))
}

pub fn tls_acceptor(files: &TlsFiles) -> Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| tls_err(format!("tls protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(load_certs(&files.cert)?, load_key(&files.key)?)
        .map_err(|e| tls_err(format!("invalid tls certificate or key: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

async fn serve_tls(listener: TcpListener, app: Router, acceptor: TlsAcceptor) {
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!("accept failed: {err}");
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };
        let acceptor = acceptor.clone();
        // Plain axum::serve injects the peer address itself; the manual accept loop must do it.
        let app = app
            .clone()
            .layer(axum::Extension(ConnectInfo::<SocketAddr>(peer)));
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let mut app = app.clone();
                async move { app.call(req).await }
            });
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
            if let Err(err) = served {
                tracing::debug!("connection ended: {err}");
            }
        });
    }
}

// Printed outside the structured log so the token is easy to spot in `docker compose logs`.
fn announce_setup_token(token: &str) {
    eprintln!("==============================================================");
    eprintln!("Cite dashboard is not set up yet.");
    eprintln!("Open the console and enter this one-time setup token:");
    eprintln!();
    eprintln!("    {token}");
    eprintln!();
    eprintln!("A new token is generated each time the dashboard starts until setup is complete.");
    eprintln!("==============================================================");
}

// An explicit CITE_DASHBOARD_LISTEN wins over the listen address stored in the config file.
pub async fn run(settings: Settings) -> Result<()> {
    let config = ConfigFile::load_or_default(&settings.config_path)?;
    let listen = match settings.listen {
        Some(addr) => addr,
        None => config
            .listen
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))),
    };
    let tokens: Arc<dyn TokenStore> = Arc::new(JsonTokenStore::beside(&settings.config_path));
    let acceptor = settings.tls.as_ref().map(tls_acceptor).transpose()?;
    let onboarding = config.admin.is_none();
    let state = AppState::new(settings, config, tokens);
    if onboarding {
        let token = state
            .issue_setup_token()
            .map_err(|e| Error::Setup(e.message().to_string()))?;
        announce_setup_token(&token);
    }
    let app = api::router(state);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(
        listen = %listen,
        tls = acceptor.is_some(),
        needs_onboarding = onboarding,
        "dashboard listening"
    );
    match acceptor {
        Some(acceptor) => serve_tls(listener, app, acceptor).await,
        None => {
            let service = app.into_make_service_with_connect_info::<SocketAddr>();
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    tracing::info!("dashboard stopped");
    Ok(())
}
