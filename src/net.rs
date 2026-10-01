use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context;

/// One shared client so later key batches reuse the TLS connection.
pub fn client() -> anyhow::Result<reqwest::blocking::Client> {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let built = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(concat!("tesdec/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;
    Ok(CLIENT.get_or_init(|| built).clone())
}
