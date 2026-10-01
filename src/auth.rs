//! Tesla OAuth for the public `dashcam` client used by dashcam.tesla.com.
//!
//! The browser window (or the pasted callback) only completes Tesla's PKCE
//! login. The password stays on Tesla's page. The resulting access token is
//! what `POST /api/1/decrypt/batch` expects.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::net;

pub const CLIENT_ID: &str = "dashcam";
pub const REDIRECT_URI: &str = "https://dashcam.tesla.com/callback";
/// Scopes the official viewer requests. `employee` is part of that list.
pub const SCOPE: &str = "openid profile email employee";
const DEFAULT_AUTH: &str = "https://auth.tesla.com";
const DEFAULT_API: &str = "https://dashcam.tesla.com";
const EXPIRY_SKEW_SECS: u64 = 120;

#[derive(Clone, Debug)]
pub struct Endpoints {
    pub auth_base: String,
    pub api_base: String,
}

impl Endpoints {
    pub fn from_region(
        region: &str,
        auth_base: Option<&str>,
        api_base: Option<&str>,
    ) -> Result<Self> {
        let auth_base = match auth_base {
            Some(value) => value.trim_end_matches('/').to_string(),
            None => match region {
                "us" | "na" | "eu" => DEFAULT_AUTH.to_string(),
                "cn" => "https://auth.tesla.cn".to_string(),
                other => bail!("unknown region {other}; use us or cn"),
            },
        };
        let api_base = api_base
            .unwrap_or(DEFAULT_API)
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            auth_base,
            api_base,
        })
    }
}

#[derive(Clone)]
pub struct Session {
    pub access_token: String,
    pub api_base: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredAuth {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_at: u64,
    auth_base: String,
    api_base: String,
    #[serde(default)]
    account: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PendingLogin {
    verifier: String,
    state: String,
    auth_base: String,
    api_base: String,
    created_unix: u64,
}

struct Pkce {
    verifier: String,
    challenge: String,
    state: String,
}

pub fn login(
    endpoints: &Endpoints,
    paste: bool,
    reauth: bool,
    callback_url: Option<&str>,
) -> Result<()> {
    if let Some(url) = callback_url {
        let pending = load_pending()?;
        let code = code_from_callback(url, &pending.state)?;
        let tokens = exchange_code(&pending.auth_base, &code, &pending.verifier)?;
        store_tokens(&pending.auth_base, &pending.api_base, tokens, None)?;
        let _ = fs::remove_file(pending_path()?);
        println!(
            "Signed in. Credentials saved to {}",
            credentials_path()?.display()
        );
        return Ok(());
    }

    let pkce = Pkce::generate()?;
    let url = authorize_url(&endpoints.auth_base, &pkce, reauth)?;
    let use_paste = paste || !cfg!(feature = "webview");
    let tokens = if use_paste {
        login_via_paste(endpoints, &pkce, &url)?
    } else {
        match login_via_window(&url, &pkce.state) {
            WindowOutcome::Code(code) => {
                exchange_code(&endpoints.auth_base, &code, &pkce.verifier)?
            }
            WindowOutcome::Cancelled => bail!("login cancelled"),
            WindowOutcome::Failed(reason) => bail!("{reason}"),
            WindowOutcome::Unavailable(reason) => {
                eprintln!("Could not open the sign-in window ({reason}).");
                eprintln!("Continuing in the browser instead.");
                login_via_paste(endpoints, &pkce, &url)?
            }
        }
    };
    store_tokens(&endpoints.auth_base, &endpoints.api_base, tokens, None)?;
    println!(
        "Signed in. Credentials saved to {}",
        credentials_path()?.display()
    );
    Ok(())
}

fn login_via_paste(endpoints: &Endpoints, pkce: &Pkce, url: &str) -> Result<TokenResponse> {
    let pending = PendingLogin {
        verifier: pkce.verifier.clone(),
        state: pkce.state.clone(),
        auth_base: endpoints.auth_base.clone(),
        api_base: endpoints.api_base.clone(),
        created_unix: now(),
    };
    write_secret(&pending_path()?, &serde_json::to_vec_pretty(&pending)?)?;
    if open::that(url).is_err() {
        eprintln!("Could not launch a browser. Open the URL below yourself.");
    }
    eprintln!("Sign in with the Tesla account that owns the car.");
    eprintln!("tesdec never sees your password.");
    eprintln!();
    eprintln!("After login, the address bar becomes:");
    eprintln!("  {REDIRECT_URI}?code=…&state=…");
    eprintln!("Copy that full URL immediately. If the dashcam page finishes loading,");
    eprintln!("it may spend the code, and you will need to start login again.");
    eprintln!();
    eprintln!("{url}");
    eprintln!();
    eprint!("Paste the callback URL and press Enter: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("failed to read the callback URL")?;
    let code = code_from_callback(line.trim(), &pkce.state)?;
    let tokens = exchange_code(&endpoints.auth_base, &code, &pkce.verifier);
    if tokens.is_ok() {
        let _ = fs::remove_file(pending_path()?);
    }
    tokens
}

enum WindowOutcome {
    Code(String),
    Cancelled,
    Failed(String),
    Unavailable(String),
}

#[cfg(not(feature = "webview"))]
fn login_via_window(_url: &str, _state: &str) -> WindowOutcome {
    WindowOutcome::Unavailable("this build has no sign-in window".into())
}

#[cfg(feature = "webview")]
fn login_via_window(url: &str, expected_state: &str) -> WindowOutcome {
    use std::sync::{Arc, Mutex};

    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::platform::run_return::EventLoopExtRunReturn;
    use tao::window::WindowBuilder;
    use wry::{WebContext, WebViewBuilder};

    enum LoginEvent {
        Finished(Result<String, String>),
    }

    let mut event_loop = EventLoopBuilder::<LoginEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = match WindowBuilder::new()
        .with_title("Sign in to Tesla — tesdec")
        .with_inner_size(tao::dpi::LogicalSize::new(480.0, 760.0))
        .build(&event_loop)
    {
        Ok(window) => window,
        Err(err) => return WindowOutcome::Unavailable(err.to_string()),
    };

    let state = expected_state.to_string();
    let mut context = match webview_dir().and_then(|dir| {
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }) {
        Ok(dir) => WebContext::new(Some(dir)),
        Err(err) => return WindowOutcome::Unavailable(err.to_string()),
    };
    let webview = WebViewBuilder::new_with_web_context(&mut context)
        .with_url(url)
        .with_navigation_handler(
            move |navigated| match classify_callback(&navigated, &state) {
                CallbackHit::Ignore => true,
                CallbackHit::Code(code) => {
                    let _ = proxy.send_event(LoginEvent::Finished(Ok(code)));
                    false
                }
                CallbackHit::Error(message) => {
                    let _ = proxy.send_event(LoginEvent::Finished(Err(message)));
                    false
                }
            },
        )
        .build(&window);

    let webview = match webview {
        Ok(webview) => webview,
        Err(err) => return WindowOutcome::Unavailable(err.to_string()),
    };

    eprintln!("A Tesla sign-in window is open.");
    eprintln!("Sign in with the account that owns the car. tesdec never sees your password.");

    let slot = Arc::new(Mutex::new(None));
    let slot_for_loop = Arc::clone(&slot);
    let _ = event_loop.run_return(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        let _keep_webview = &webview;
        let _keep_window = &window;
        match event {
            Event::UserEvent(LoginEvent::Finished(result)) => {
                *slot_for_loop.lock().unwrap_or_else(|err| err.into_inner()) = Some(result);
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                let mut guard = slot_for_loop.lock().unwrap_or_else(|err| err.into_inner());
                if guard.is_none() {
                    *guard = Some(Err("window closed".into()));
                }
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });

    let outcome = slot.lock().unwrap_or_else(|err| err.into_inner()).take();
    match outcome {
        Some(Ok(code)) => WindowOutcome::Code(code),
        Some(Err(message)) if message == "window closed" => WindowOutcome::Cancelled,
        Some(Err(message)) => WindowOutcome::Failed(message),
        None => WindowOutcome::Cancelled,
    }
}

enum CallbackHit {
    Ignore,
    Code(String),
    Error(String),
}

fn classify_callback(raw: &str, expected_state: &str) -> CallbackHit {
    let Ok(parsed) = Url::parse(raw) else {
        return CallbackHit::Ignore;
    };
    if parsed.host_str() != Some("dashcam.tesla.com") {
        return CallbackHit::Ignore;
    }
    let path = parsed.path().trim_end_matches('/');
    if path != "/callback" {
        return CallbackHit::Ignore;
    }
    match callback_params(&parsed, expected_state) {
        Ok(code) => CallbackHit::Code(code),
        Err(err) => CallbackHit::Error(err.to_string()),
    }
}

fn code_from_callback(raw: &str, expected_state: &str) -> Result<String> {
    let parsed = Url::parse(raw.trim()).context(
        "that was not a callback URL; paste the full https://dashcam.tesla.com/callback?code=… address",
    )?;
    callback_params(&parsed, expected_state)
}

fn callback_params(parsed: &Url, expected_state: &str) -> Result<String> {
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if !pairs.iter().any(|(key, _)| key == "code") {
        if let Some(fragment) = parsed.fragment() {
            if let Ok(fake) = Url::parse(&format!("https://dashcam.tesla.com/callback?{fragment}"))
            {
                pairs.extend(
                    fake.query_pairs()
                        .map(|(key, value)| (key.into_owned(), value.into_owned())),
                );
            }
        }
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (key, value) in pairs {
        match key.as_str() {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => error = Some(value),
            "error_description" => error_description = Some(value),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        bail!("OAuth state did not match this login. Start tesdec login again.");
    }
    if let Some(err) = error {
        let desc = error_description.unwrap_or_default();
        bail!("Tesla login failed: {err} {desc}");
    }
    code.context("the callback URL did not include a code")
}

fn authorize_url(auth_base: &str, pkce: &Pkce, reauth: bool) -> Result<String> {
    let mut url = Url::parse(&format!(
        "{}/oauth2/v3/authorize",
        auth_base.trim_end_matches('/')
    ))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", CLIENT_ID);
        pairs.append_pair("redirect_uri", REDIRECT_URI);
        pairs.append_pair("scope", SCOPE);
        pairs.append_pair("code_challenge", &pkce.challenge);
        pairs.append_pair("code_challenge_method", "S256");
        pairs.append_pair("state", &pkce.state);
        if reauth {
            pairs.append_pair("prompt", "login");
        }
    }
    Ok(url.into())
}

fn exchange_code(auth_base: &str, code: &str, verifier: &str) -> Result<TokenResponse> {
    let body = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", verifier),
    ];
    post_token(auth_base, &body)
}

fn refresh(auth_base: &str, refresh_token: &str) -> Result<TokenResponse> {
    let body = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh_token),
        ("redirect_uri", REDIRECT_URI),
        ("scope", SCOPE),
    ];
    post_token(auth_base, &body)
}

fn post_token(auth_base: &str, form: &[(&str, &str)]) -> Result<TokenResponse> {
    let url = format!("{}/oauth2/v3/token", auth_base.trim_end_matches('/'));
    let client = net::client()?;
    let response = client
        .post(url)
        .form(form)
        .send()
        .context("token request to Tesla failed")?;
    let status = response.status();
    let body = response.text().context("reading Tesla token response")?;
    if !status.is_success() {
        let snippet: String = body.chars().take(400).collect();
        bail!("Tesla token request returned {status}: {snippet}");
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).context("Tesla token response was not JSON")?;
    if let Some(err) = parsed.error.as_deref() {
        let desc = parsed.error_description.as_deref().unwrap_or("");
        bail!("Tesla token request failed: {err} {desc}");
    }
    if parsed.access_token.is_empty() {
        bail!("Tesla token response did not include an access token");
    }
    Ok(parsed)
}

fn store_tokens(
    auth_base: &str,
    api_base: &str,
    tokens: TokenResponse,
    previous_account: Option<String>,
) -> Result<()> {
    let account = account_hint(&tokens).or(previous_account);
    let stored = StoredAuth {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: now().saturating_add(tokens.expires_in.unwrap_or(3600)),
        auth_base: auth_base.to_string(),
        api_base: api_base.to_string(),
        account,
    };
    write_secret(&credentials_path()?, &serde_json::to_vec_pretty(&stored)?)?;
    Ok(())
}

pub fn logout() -> Result<()> {
    let creds = credentials_path()?;
    let pending = pending_path()?;
    let mut removed = false;
    if creds.exists() {
        fs::remove_file(&creds)?;
        removed = true;
    }
    if pending.exists() {
        fs::remove_file(&pending)?;
        removed = true;
    }
    if let Ok(dir) = webview_dir() {
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
            removed = true;
        }
    }
    if removed {
        println!("Signed out and removed saved Tesla credentials.");
    } else {
        println!("No saved Tesla credentials.");
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let path = credentials_path()?;
    if !path.exists() {
        println!("Not signed in. Run `tesdec login`.");
        return Ok(());
    }
    let stored = read_stored(&path)?;
    match &stored.account {
        Some(account) => println!("Account: {account}"),
        None => println!("Account: signed in"),
    }
    let now = now();
    if stored.expires_at > now {
        println!(
            "Access token expires in {}.",
            format_duration(stored.expires_at - now)
        );
    } else {
        println!(
            "Access token expired {}. The next decrypt refreshes it.",
            format_duration(now - stored.expires_at)
        );
    }
    println!("Key service: {}", stored.api_base);
    println!("Credentials: {}", path.display());
    Ok(())
}

/// Access token for a decrypt run. Refreshes and saves when the stored one is due.
pub fn session_for(token_override: Option<&str>, api_override: Option<&str>) -> Result<Session> {
    if let Some(token) = token_override {
        let token = token.trim().trim_start_matches("Bearer ").trim();
        if token.is_empty() {
            bail!("--token was empty");
        }
        return Ok(Session {
            access_token: token.to_string(),
            api_base: api_override
                .unwrap_or(DEFAULT_API)
                .trim_end_matches('/')
                .to_string(),
        });
    }
    let path = credentials_path()?;
    if !path.exists() {
        bail!("not signed in. Run `tesdec login`, or pass --token.");
    }
    let mut stored = read_stored(&path)?;
    if let Some(api) = api_override {
        stored.api_base = api.trim_end_matches('/').to_string();
    }
    if stored.expires_at <= now().saturating_add(EXPIRY_SKEW_SECS) {
        let Some(refresh_token) = stored.refresh_token.clone() else {
            bail!("the saved Tesla token expired. Run `tesdec login` again.");
        };
        let tokens = refresh(&stored.auth_base, &refresh_token)
            .context("could not refresh the Tesla token; run `tesdec login` again")?;
        let mut merged = tokens;
        if merged.refresh_token.is_none() {
            merged.refresh_token = Some(refresh_token);
        }
        let account = stored.account.clone();
        let auth_base = stored.auth_base.clone();
        let api_base = stored.api_base.clone();
        store_tokens(&auth_base, &api_base, merged, account)?;
        stored = read_stored(&path)?;
    }
    Ok(Session {
        access_token: stored.access_token,
        api_base: stored.api_base,
    })
}

pub fn refresh_session(session: &Session) -> Result<Session> {
    let path = credentials_path()?;
    if !path.exists() {
        bail!("the access token was rejected and there is no saved refresh token. Run `tesdec login`.");
    }
    let stored = read_stored(&path)?;
    let Some(refresh_token) = stored.refresh_token.clone() else {
        bail!("the access token was rejected. Run `tesdec login` again.");
    };
    let mut tokens = refresh(&stored.auth_base, &refresh_token)?;
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_token);
    }
    let api_base = session.api_base.clone();
    store_tokens(&stored.auth_base, &api_base, tokens, stored.account.clone())?;
    let stored = read_stored(&path)?;
    Ok(Session {
        access_token: stored.access_token,
        api_base,
    })
}

fn account_hint(tokens: &TokenResponse) -> Option<String> {
    tokens
        .id_token
        .as_deref()
        .and_then(jwt_claim)
        .or_else(|| jwt_claim(&tokens.access_token))
}

fn jwt_claim(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("email")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn read_stored(path: &Path) -> Result<StoredAuth> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("{} is not a tesdec credential file", path.display()))
}

fn load_pending() -> Result<PendingLogin> {
    let path = pending_path()?;
    let text = fs::read_to_string(&path).context(
        "no login is waiting for a callback URL. Run `tesdec login --paste` and sign in first.",
    )?;
    let pending: PendingLogin = serde_json::from_str(&text)?;
    if now().saturating_sub(pending.created_unix) > 15 * 60 {
        let _ = fs::remove_file(path);
        bail!("that login expired. Run `tesdec login` again.");
    }
    Ok(pending)
}

fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("TESDEC_CONFIG") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = std::env::var_os("HOME").context("HOME is not set; set TESDEC_CONFIG")?;
    Ok(PathBuf::from(home).join(".config").join("tesdec"))
}

fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials.json"))
}

fn pending_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("pending-login.json"))
}

fn webview_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("webview"))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)?;
        }
    }
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m {}s", secs % 60)
    }
}

impl Pkce {
    fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|err| anyhow::anyhow!("failed to generate a login secret: {err}"))?;
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        Ok(Self {
            challenge: s256_challenge(&verifier),
            state: uuid::Uuid::new_v4().to_string(),
            verifier,
        })
    }
}

pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc_7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn callback_rejects_a_mismatched_state() {
        let url = "https://dashcam.tesla.com/callback?code=abc&state=expected";
        assert!(code_from_callback(url, "expected").is_ok());
        assert!(code_from_callback(url, "other").is_err());
        let err = "https://dashcam.tesla.com/callback?error=access_denied&state=expected";
        assert!(code_from_callback(err, "expected")
            .unwrap_err()
            .to_string()
            .contains("access_denied"));
    }

    #[test]
    fn region_selects_the_auth_host() {
        let us = Endpoints::from_region("us", None, None).unwrap();
        assert_eq!(us.auth_base, "https://auth.tesla.com");
        assert_eq!(us.api_base, "https://dashcam.tesla.com");
        let cn = Endpoints::from_region("cn", None, None).unwrap();
        assert_eq!(cn.auth_base, "https://auth.tesla.cn");
    }
}
