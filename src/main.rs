mod api;
mod auth;
mod container;
mod files;
mod net;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::api::FetchError;
use crate::files::JobKind;

#[derive(Parser)]
#[command(
    name = "tesdec",
    version,
    about = "Decrypt TeslaCam clips locally with your Tesla account",
    after_help = "\
Video stays on this machine. Tesla only receives the per-clip metadata that
dashcam.tesla.com sends, and returns the AES key for that clip.

Examples:
  tesdec login
  tesdec decrypt /Volumes/TESLA/TeslaCam --output ~/TeslaCam-plain
  tesdec decrypt clip.mp4 other.mp4 --output ~/out --overwrite
  tesdec decrypt /Volumes/TESLA/TeslaCam --in-place
"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in to Tesla and save a refresh token for later decrypts.
    Login(LoginArgs),
    /// Delete saved Tesla credentials and the sign-in window profile.
    Logout,
    /// Show whether a Tesla session is saved, without printing the token.
    Status,
    /// Decrypt encrypted TeslaCam .mp4 files or folders.
    Decrypt(DecryptArgs),
}

#[derive(clap::Args)]
struct LoginArgs {
    /// Tesla account region. `cn` uses auth.tesla.cn.
    #[arg(long, default_value = "us")]
    region: String,
    /// Override the Tesla OAuth host.
    #[arg(long)]
    auth_base: Option<String>,
    /// Override the dashcam key service. Default is https://dashcam.tesla.com.
    #[arg(long)]
    api_base: Option<String>,
    /// Open the system browser and paste the callback URL, instead of the sign-in window.
    #[arg(long)]
    paste: bool,
    /// Ask Tesla to show the password form even if this Mac already has a session.
    #[arg(long)]
    reauth: bool,
    /// Finish a `--paste` login with the callback URL, instead of reading stdin.
    #[arg(long)]
    callback_url: Option<String>,
}

#[derive(clap::Args)]
struct DecryptArgs {
    /// Files or directories. Directories are scanned recursively for .mp4 clips.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Write decrypted clips here, keeping paths relative to each input directory.
    #[arg(short, long, conflicts_with = "in_place")]
    output: Option<PathBuf>,
    /// Replace each encrypted clip with the decrypted MP4.
    #[arg(long)]
    in_place: bool,
    /// Replace files that already exist in the output directory.
    #[arg(long)]
    overwrite: bool,
    /// Skip the in-place confirmation prompt.
    #[arg(short, long)]
    yes: bool,
    /// Also copy non-mp4 files into the output directory.
    #[arg(long)]
    mirror: bool,
    /// Bearer token to use for this run. It is not saved.
    #[arg(long)]
    token: Option<String>,
    /// Clips per key request. Tesla accepts at most 30.
    #[arg(long, default_value_t = api::MAX_BATCH)]
    batch_size: usize,
    /// List what would be decrypted, without calling Tesla or writing files.
    #[arg(long)]
    dry_run: bool,
    /// Override the dashcam key service for this run.
    #[arg(long)]
    api_base: Option<String>,
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Login(args) => {
            let endpoints = auth::Endpoints::from_region(
                &args.region,
                args.auth_base.as_deref(),
                args.api_base.as_deref(),
            )?;
            auth::login(
                &endpoints,
                args.paste,
                args.reauth,
                args.callback_url.as_deref(),
            )
        }
        Command::Logout => auth::logout(),
        Command::Status => auth::status(),
        Command::Decrypt(args) => decrypt(args),
    }
}

fn decrypt(args: DecryptArgs) -> Result<()> {
    if args.batch_size == 0 || args.batch_size > api::MAX_BATCH {
        bail!("--batch-size must be from 1 to {}", api::MAX_BATCH);
    }
    let planned = files::plan(files::Options {
        inputs: &args.paths,
        output: args.output.as_deref(),
        in_place: args.in_place,
        overwrite: args.overwrite,
        mirror: args.mirror,
    })?;

    for note in &planned.skipped {
        println!("skip  {note}");
    }
    for note in &planned.invalid {
        eprintln!("error: {note}");
    }
    if planned.jobs.is_empty() && planned.invalid.is_empty() {
        println!("No clips to decrypt.");
        return Ok(());
    }
    if args.dry_run {
        for job in &planned.jobs {
            let action = match &job.kind {
                JobKind::Decrypt(_) => "decrypt",
                JobKind::Copy => "copy",
            };
            println!("{action}  {} -> {}", job.label, job.dest.display());
        }
        println!(
            "{} file(s) ready, {} skipped, {} unreadable.",
            planned.jobs.len(),
            planned.skipped.len(),
            planned.invalid.len()
        );
        if !planned.invalid.is_empty() {
            bail!("{} file(s) could not be read", planned.invalid.len());
        }
        return Ok(());
    }

    if args.in_place {
        files::confirm_in_place(&planned.jobs, args.yes)?;
    }

    let needs_tesla = planned
        .jobs
        .iter()
        .any(|job| matches!(job.kind, JobKind::Decrypt(_)));
    let mut session = if needs_tesla {
        Some(auth::session_for(
            args.token.as_deref(),
            args.api_base.as_deref(),
        )?)
    } else {
        None
    };

    let mut ok = 0usize;
    let mut failed = planned.invalid.len();
    let decrypt_jobs: Vec<_> = planned
        .jobs
        .iter()
        .filter(|job| matches!(job.kind, JobKind::Decrypt(_)))
        .collect();
    let mut index = 0usize;
    while index < decrypt_jobs.len() {
        let end = (index + args.batch_size).min(decrypt_jobs.len());
        let chunk = &decrypt_jobs[index..end];
        index = end;
        let items: Vec<_> = chunk
            .iter()
            .map(|job| match &job.kind {
                JobKind::Decrypt(header) => api::item_for(header),
                JobKind::Copy => unreachable!("chunk is decrypt-only"),
            })
            .collect();
        let current = session.clone().context("missing Tesla session")?;
        let fetched = match api::fetch_keys(&current.api_base, &current.access_token, &items) {
            Ok(fetched) => fetched,
            Err(FetchError::Unauthorized) => {
                if args.token.is_some() {
                    bail!("Tesla rejected --token. Sign in with `tesdec login` or pass a fresh token.");
                }
                eprintln!("Access token was rejected. Refreshing…");
                let refreshed = auth::refresh_session(&current)?;
                let fetched =
                    match api::fetch_keys(&refreshed.api_base, &refreshed.access_token, &items) {
                        Ok(fetched) => fetched,
                        Err(FetchError::Unauthorized) => {
                            bail!(
                                "Tesla still rejected the token after refresh. Run `tesdec login`."
                            )
                        }
                        Err(FetchError::Failed(message)) => bail!("{message}"),
                    };
                session = Some(refreshed);
                fetched
            }
            Err(FetchError::Failed(message)) => {
                eprintln!("error: {message}");
                failed += chunk.len();
                continue;
            }
        };
        let mut errors = std::collections::HashMap::new();
        for (id, message) in fetched.errors {
            errors.insert(id, message);
        }
        for (job, item) in chunk.iter().zip(items.iter()) {
            if let Some(message) = errors.get(&item.id) {
                eprintln!("error: {} — {message}", job.label);
                failed += 1;
                continue;
            }
            let Some(key) = fetched.keys.get(&item.id) else {
                eprintln!("error: {} — Tesla did not return a key", job.label);
                failed += 1;
                continue;
            };
            match container::decrypt_file(&job.src, &job.dest, key) {
                Ok(bytes) => {
                    println!(
                        "decrypted  {} -> {} ({})",
                        job.label,
                        job.dest.display(),
                        format_bytes(bytes)
                    );
                    ok += 1;
                }
                Err(err) => {
                    eprintln!("error: {} — {err:#}", job.label);
                    failed += 1;
                }
            }
        }
    }

    for job in planned
        .jobs
        .iter()
        .filter(|job| matches!(job.kind, JobKind::Copy))
    {
        match files::copy_file(&job.src, &job.dest) {
            Ok(_) => {
                println!("copied  {} -> {}", job.label, job.dest.display());
                ok += 1;
            }
            Err(err) => {
                eprintln!("error: {} — {err:#}", job.label);
                failed += 1;
            }
        }
    }

    println!(
        "Done. {ok} written, {} skipped, {failed} failed.",
        planned.skipped.len()
    );
    if failed > 0 {
        bail!("{failed} file(s) failed");
    }
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
