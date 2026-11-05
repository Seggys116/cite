use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use cite_core::atomic::read_limited;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::ConnectorConfig;
use crate::tls::{TlsPaths, client_config_for_ca};
use crate::{ConnectorError, Result};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CA_BYTES: u64 = 256 * 1024;
const MAX_STATUS_LINE: usize = 4096;
const REQUEST: &[u8] =
    b"GET /api/v1/healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

fn unavailable(msg: impl std::fmt::Display) -> ConnectorError {
    ConnectorError::Unavailable(format!("healthcheck failed: {msg}"))
}

// A wildcard listen address is probed on loopback, which the server admits for /healthz only.
fn probe_addr(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, listen.port())
}

async fn read_status_line<S: AsyncRead + Unpin>(io: &mut S) -> Vec<u8> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 512];
    while !got.windows(2).any(|w| w == b"\r\n") && got.len() < MAX_STATUS_LINE {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
        }
    }
    got
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) -> Result<()> {
    io.write_all(REQUEST).await.map_err(unavailable)?;
    let reply = read_status_line(io).await;
    if reply.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(unavailable("unexpected response"))
    }
}

async fn probe(cfg: &ConnectorConfig) -> Result<()> {
    let mut stream = TcpStream::connect(probe_addr(cfg.listen))
        .await
        .map_err(unavailable)?;
    if !cfg.tls {
        return exchange(&mut stream).await;
    }
    let ca_path = TlsPaths::new(&cfg.tls_dir).ca_pem;
    let ca = read_limited(&ca_path, MAX_CA_BYTES).map_err(unavailable)?;
    let connector = TlsConnector::from(client_config_for_ca(&ca)?);
    let name = rustls::pki_types::ServerName::try_from("localhost").map_err(unavailable)?;
    let mut secured = connector.connect(name, stream).await.map_err(unavailable)?;
    exchange(&mut secured).await
}

pub async fn healthcheck(cfg: &ConnectorConfig) -> Result<()> {
    match tokio::time::timeout(PROBE_TIMEOUT, probe(cfg)).await {
        Ok(result) => result,
        Err(_) => Err(unavailable("timed out")),
    }
}
