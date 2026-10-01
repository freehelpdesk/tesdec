use std::time::Duration;

use anyhow::Context;

pub fn client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent(concat!("tesdec/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}
