#![forbid(unsafe_code)]

use cite_mock_github::MockGithub;

#[tokio::main]
async fn main() {
    let listen = std::env::var("CITE_MOCK_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let mock = MockGithub::bind(&listen)
        .await
        .expect("failed to start cite-mock-github");
    if let Ok(raw) = std::env::var("CITE_MOCK_TARBALL_DELAY_MS")
        && let Ok(ms) = raw.parse::<u64>()
        && ms > 0
    {
        mock.set_tarball_delay(std::time::Duration::from_millis(ms));
    }
    println!("{}", mock.base_url());
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    mock.shutdown().await;
}
