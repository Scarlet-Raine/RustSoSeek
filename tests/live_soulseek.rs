//! Opt-in live integration test for the native Soulseek client.
//!
//! This test contacts the real Soulseek server and requires real credentials.
//! It is `#[ignore]`d so normal CI never runs it. To run it explicitly:
//!
//! ```powershell
//! $env:AGPEER_LIVE_SOULSEEK="1"
//! $env:AGPEER_SOULSEEK_USERNAME="..."
//! $env:AGPEER_SOULSEEK_PASSWORD="..."
//! cargo test --test live_soulseek -- --ignored --nocapture
//! ```
//!
//! Credentials are read from environment variables only and are never
//! hardcoded, committed, or logged.

use rustsoseek::{NativeClient, NativeConfig};

/// Read live-test credentials from the environment. Returns `None` (after
/// printing a one-line skip notice to stderr) unless the live gate is enabled
/// and both credentials are present.
fn live_credentials() -> Option<(String, String)> {
    if std::env::var("AGPEER_LIVE_SOULSEEK").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping: set AGPEER_LIVE_SOULSEEK=1 with AGPEER_SOULSEEK_USERNAME/AGPEER_SOULSEEK_PASSWORD"
        );
        return None;
    }
    let username = std::env::var("AGPEER_SOULSEEK_USERNAME").unwrap_or_default();
    let password = std::env::var("AGPEER_SOULSEEK_PASSWORD").unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        eprintln!(
            "skipping: set AGPEER_LIVE_SOULSEEK=1 with AGPEER_SOULSEEK_USERNAME/AGPEER_SOULSEEK_PASSWORD"
        );
        return None;
    }
    Some((username, password))
}

#[tokio::test]
#[ignore = "live network test; opt in via AGPEER_LIVE_SOULSEEK=1"]
async fn live_login_and_search() {
    let Some((username, password)) = live_credentials() else {
        return;
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind free listen port");
    let listen_port = listener.local_addr().expect("listen local addr").port();
    drop(listener);

    let client = NativeClient::connect(NativeConfig {
        username,
        password,
        listen_port,
        download_dir: std::env::temp_dir().to_string_lossy().into_owned(),
        ..NativeConfig::default()
    })
    .await
    .expect("connect/login");

    let token = client.start_search("flac").await.expect("start search");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let results = client.results(token, 100);
    println!("live search returned {} results", results.len());
    client.stop_search(token);
}
