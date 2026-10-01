//! Copyright (c) 2026 freehelpdesk. Licensed under the MIT License.
//! See the LICENSE file in the repository root.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tesdec::api;
use tesdec::api::FetchError;
use tesdec::auth;
use tesdec::container;
use tesdec::files;
use tesdec::files::JobKind;

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
  tesdec decrypt - < clip.mp4 > plain.mp4
  tesdec decrypt clip.mp4 --output -
  tesdec --verbose decrypt /Volumes/TESLA/TeslaCam --output ~/TeslaCam-plain
"
)]
struct Cli {
    /// Print the plan, each key request, clip metadata, and timings on stderr.
    /// Tokens and AES keys are not included.
    #[arg(short, long, global = true)]
    verbose: bool,
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
    /// Files or directories. `-` reads one clip from stdin. Directories are scanned recursively for .mp4 clips.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Directory for decrypted clips, or `-` to write one clip to stdout.
    #[arg(short, long, conflicts_with = "in_place", allow_hyphen_values = true)]
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
    /// Clips to decrypt at once. The next key request runs while these finish.
    #[arg(short = 'j', long, default_value_t = default_jobs())]
    jobs: usize,
    /// List what would be decrypted, without calling Tesla or writing files.
    #[arg(long)]
    dry_run: bool,
    /// Override the dashcam key service for this run.
    #[arg(long)]
    api_base: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if files::is_broken_pipe(&err) => ExitCode::from(1),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Login(args) => {
            let endpoints = auth::Endpoints::from_region(
                &args.region,
                args.auth_base.as_deref(),
                args.api_base.as_deref(),
            )?;
            if cli.verbose {
                eprintln!("login: auth {}", endpoints.auth_base);
                eprintln!("login: key service {}", endpoints.api_base);
            }
            auth::login(
                &endpoints,
                args.paste,
                args.reauth,
                args.callback_url.as_deref(),
            )
        }
        Command::Logout => auth::logout(),
        Command::Status => auth::status(),
        Command::Decrypt(args) => decrypt(args, cli.verbose),
    }
}

fn decrypt(args: DecryptArgs, verbose: bool) -> Result<()> {
    if args.batch_size == 0 || args.batch_size > api::MAX_BATCH {
        bail!("--batch-size must be from 1 to {}", api::MAX_BATCH);
    }
    if args.jobs == 0 {
        bail!("--jobs must be at least 1");
    }
    let mode = files::stdio_mode(
        &args.paths,
        args.output.as_deref(),
        args.in_place,
        args.mirror,
    )?;
    // Stdin is not a file until it is spooled: the header check needs a length.
    let spool = if mode.from_stdin {
        Some(files::spool_stdin()?)
    } else {
        None
    };
    let inputs: Vec<PathBuf> = if let Some(spool) = &spool {
        vec![spool.file.clone()]
    } else {
        args.paths.clone()
    };
    let stdout_scratch = if mode.to_stdout {
        Some(files::TempTree::create("tesdec-stdout")?)
    } else {
        None
    };
    let output_buf = if let Some(scratch) = &stdout_scratch {
        Some(scratch.path().to_path_buf())
    } else {
        args.output.clone()
    };
    let mut planned = files::plan(files::Options {
        inputs: &inputs,
        output: output_buf.as_deref(),
        in_place: args.in_place,
        overwrite: args.overwrite,
        mirror: args.mirror,
        label_stdin: mode.from_stdin,
    })?;
    if let Some(spool) = &spool {
        let raw = spool.file.display().to_string();
        for note in &mut planned.invalid {
            *note = note.replace(&raw, "stdin");
        }
        for note in &mut planned.skipped {
            *note = note.replace(&raw, "stdin");
        }
    }
    if mode.to_stdout && planned.jobs.len() > 1 {
        bail!(
            "stdout can receive only one clip, found {}",
            planned.jobs.len()
        );
    }

    // MP4 bytes own stdout. Status stays on stderr, and a successful pipe is quiet.
    let emit = |line: &str| {
        if mode.to_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };
    let note = |line: &str| {
        if !mode.to_stdout || args.dry_run {
            emit(line);
        }
    };
    let dest_label = |dest: &std::path::Path| -> String {
        if mode.to_stdout {
            "stdout".to_string()
        } else {
            dest.display().to_string()
        }
    };

    for note in &planned.skipped {
        emit(&format!("skip  {note}"));
    }
    for note in &planned.invalid {
        eprintln!("error: {note}");
    }
    if planned.jobs.is_empty() && planned.invalid.is_empty() {
        emit("No clips to decrypt.");
        return Ok(());
    }
    let threads = args.jobs.min(planned.jobs.len().max(1));
    let output = output_label(&args, mode);
    if args.dry_run {
        log_plan(verbose, &planned, threads, args.batch_size, &output);
        for job in &planned.jobs {
            let action = match &job.kind {
                JobKind::Decrypt(_) => "decrypt",
                JobKind::Copy => "copy",
            };
            let dest = dest_label(&job.dest);
            emit(&format!("{action}  {} -> {dest}", job.label));
            vlog(verbose, plan_detail(job, &dest));
        }
        emit(&format!(
            "{} file(s) ready, {} skipped, {} unreadable.",
            planned.jobs.len(),
            planned.skipped.len(),
            planned.invalid.len()
        ));
        if !planned.invalid.is_empty() {
            bail!("{} file(s) could not be read", planned.invalid.len());
        }
        return Ok(());
    }
    log_plan(verbose, &planned, threads, args.batch_size, &output);

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

    let ok = AtomicUsize::new(0);
    let failed_tasks = AtomicUsize::new(0);
    let mut failed_now = planned.invalid.len();
    let to_stdout = mode.to_stdout;
    let started = Instant::now();
    if verbose {
        if let Some(session) = &session {
            eprintln!("decrypt: key service {}", session.api_base);
        }
    }
    // The queue outlives the worker threads. `scope` joins them before returning.
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(rx);

    thread::scope(|scope| -> Result<()> {
        for _ in 0..threads {
            let rx = &rx;
            let ok = &ok;
            let failed_tasks = &failed_tasks;
            scope.spawn(move || {
                loop {
                    // Hold the mutex only while waiting for the next clip, then
                    // decrypt outside it so the other workers can take work.
                    let task = {
                        let guard = rx.lock().unwrap_or_else(|err| err.into_inner());
                        match guard.recv() {
                            Ok(task) => task,
                            Err(_) => break,
                        }
                    };
                    execute_task(task, to_stdout, verbose, ok, failed_tasks);
                }
            });
        }

        let decrypt_jobs: Vec<_> = planned
            .jobs
            .iter()
            .filter(|job| matches!(job.kind, JobKind::Decrypt(_)))
            .collect();
        let batches = decrypt_jobs.len().div_ceil(args.batch_size.max(1));
        let mut index = 0usize;
        let mut batch_no = 0usize;
        while index < decrypt_jobs.len() {
            let end = (index + args.batch_size).min(decrypt_jobs.len());
            let chunk = &decrypt_jobs[index..end];
            index = end;
            batch_no += 1;
            let batch_started = Instant::now();
            let items: Vec<_> = chunk
                .iter()
                .map(|job| match &job.kind {
                    JobKind::Decrypt(header) => api::item_for(header),
                    JobKind::Copy => unreachable!("chunk is decrypt-only"),
                })
                .collect();
            let current = session.clone().context("missing Tesla session")?;
            vlog(
                verbose,
                format!(
                    "keys batch {batch_no}/{batches} start, {} clips, {}",
                    chunk.len(),
                    current.api_base
                ),
            );
            let fetched = match api::fetch_keys(&current.api_base, &current.access_token, &items) {
                Ok(fetched) => fetched,
                Err(FetchError::Unauthorized) => {
                    if args.token.is_some() {
                        bail!(
                            "Tesla rejected --token. Sign in with `tesdec login` or pass a fresh token."
                        );
                    }
                    eprintln!("Access token was rejected. Refreshing…");
                    let refreshed = auth::refresh_session(&current)?;
                    let fetched =
                        match api::fetch_keys(&refreshed.api_base, &refreshed.access_token, &items)
                        {
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
                    vlog(
                        verbose,
                        format!(
                            "keys batch {batch_no}/{batches} failed, {} clips",
                            chunk.len()
                        ),
                    );
                    failed_now += chunk.len();
                    continue;
                }
            };
            vlog(
                verbose,
                format!(
                    "keys batch {batch_no}/{batches} done, {} keys, {} errors, {}",
                    fetched.keys.len(),
                    fetched.errors.len(),
                    format_duration(batch_started.elapsed())
                ),
            );
            let mut errors = std::collections::HashMap::new();
            for (id, message) in fetched.errors {
                errors.insert(id, message);
            }
            for (job, item) in chunk.iter().zip(items.iter()) {
                if let Some(message) = errors.get(&item.id) {
                    let meta = clip_meta(job);
                    vlog(
                        verbose,
                        fail_detail(&job.label, batch_started.elapsed(), meta.as_ref()),
                    );
                    eprintln!("error: {} — {message}", job.label);
                    failed_now += 1;
                    continue;
                }
                let Some(key) = fetched.keys.get(&item.id) else {
                    let meta = clip_meta(job);
                    vlog(
                        verbose,
                        fail_detail(&job.label, batch_started.elapsed(), meta.as_ref()),
                    );
                    eprintln!("error: {} — Tesla did not return a key", job.label);
                    failed_now += 1;
                    continue;
                };
                tx.send(Task {
                    label: job.label.clone(),
                    src: job.src.clone(),
                    dest: job.dest.clone(),
                    op: TaskOp::Decrypt(key.clone()),
                    meta: clip_meta(job),
                })
                .context("decrypt worker stopped")?;
            }
        }

        for job in planned
            .jobs
            .iter()
            .filter(|job| matches!(job.kind, JobKind::Copy))
        {
            tx.send(Task {
                label: job.label.clone(),
                src: job.src.clone(),
                dest: job.dest.clone(),
                op: TaskOp::Copy,
                meta: None,
            })
            .context("decrypt worker stopped")?;
        }
        drop(tx);
        Ok(())
    })?;

    let ok = ok.load(Ordering::Relaxed);
    let failed = failed_now + failed_tasks.load(Ordering::Relaxed);

    if mode.to_stdout && ok == 1 {
        let mut stdout = std::io::stdout().lock();
        files::copy_bytes_to(&planned.jobs[0].dest, &mut stdout, "stdout")?;
    }

    note(&format!(
        "Done. {ok} written, {} skipped, {failed} failed.",
        planned.skipped.len()
    ));
    vlog(
        verbose,
        format!(
            "finished {ok} written, {} skipped, {failed} failed, {}",
            planned.skipped.len(),
            format_duration(started.elapsed())
        ),
    );
    if failed > 0 {
        bail!("{failed} file(s) failed");
    }
    Ok(())
}

struct Task {
    label: String,
    src: PathBuf,
    dest: PathBuf,
    op: TaskOp,
    meta: Option<ClipMeta>,
}

struct ClipMeta {
    vin: String,
    key_id: u32,
    timestamp: u64,
}

enum TaskOp {
    Decrypt(Vec<u8>),
    Copy,
}

fn default_jobs() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn execute_task(
    task: Task,
    to_stdout: bool,
    verbose: bool,
    ok: &AtomicUsize,
    failed: &AtomicUsize,
) {
    let show = |line: String| {
        if !to_stdout {
            println!("{line}");
        }
    };
    let dest = if to_stdout {
        "stdout".to_string()
    } else {
        task.dest.display().to_string()
    };
    let started = Instant::now();
    match task.op {
        TaskOp::Decrypt(ref key) => {
            let key_len = key.len();
            match container::decrypt_file(&task.src, &task.dest, key) {
                Ok(bytes) => {
                    show(format!(
                        "decrypted  {} -> {} ({})",
                        task.label,
                        task.dest.display(),
                        format_bytes(bytes)
                    ));
                    vlog(
                        verbose,
                        finish_detail(&task, &dest, bytes, started.elapsed(), Some(key_len)),
                    );
                    ok.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    vlog(
                        verbose,
                        fail_detail(&task.label, started.elapsed(), task.meta.as_ref()),
                    );
                    eprintln!("error: {} — {err:#}", task.label);
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        TaskOp::Copy => match files::copy_file(&task.src, &task.dest) {
            Ok(bytes) => {
                show(format!("copied  {} -> {}", task.label, task.dest.display()));
                vlog(
                    verbose,
                    finish_detail(&task, &dest, bytes, started.elapsed(), None),
                );
                ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                vlog(verbose, fail_detail(&task.label, started.elapsed(), None));
                eprintln!("error: {} — {err:#}", task.label);
                failed.fetch_add(1, Ordering::Relaxed);
            }
        },
    }
}

fn vlog(verbose: bool, line: impl AsRef<str>) {
    if verbose {
        eprintln!("decrypt: {}", line.as_ref());
    }
}

fn output_label(args: &DecryptArgs, mode: files::StdioMode) -> String {
    if mode.to_stdout {
        "stdout".to_string()
    } else if args.in_place {
        "in place".to_string()
    } else {
        args.output
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    }
}

fn log_plan(verbose: bool, planned: &files::Plan, threads: usize, batch_size: usize, output: &str) {
    if !verbose {
        return;
    }
    let decrypt_n = planned
        .jobs
        .iter()
        .filter(|job| matches!(job.kind, JobKind::Decrypt(_)))
        .count();
    let copy_n = planned.jobs.len() - decrypt_n;
    eprintln!(
        "decrypt: plan {}, {}, {}, {}, {}, batch {batch_size}",
        count_label(decrypt_n, "encrypted", "encrypted"),
        count_label(copy_n, "copy", "copies"),
        count_label(planned.skipped.len(), "skipped", "skipped"),
        count_label(planned.invalid.len(), "unreadable", "unreadable"),
        count_label(threads, "worker", "workers")
    );
    eprintln!("decrypt: output {output}");
}

fn plan_detail(job: &files::Job, dest: &str) -> String {
    match &job.kind {
        JobKind::Decrypt(header) => format!(
            "plan {} -> {dest} plaintext {} vin={} key_id={} timestamp={}",
            job.label,
            format_bytes(header.plaintext_size),
            header.vin,
            header.key_id,
            header.timestamp
        ),
        JobKind::Copy => format!("plan copy {} -> {dest}", job.label),
    }
}

fn clip_meta(job: &files::Job) -> Option<ClipMeta> {
    match &job.kind {
        JobKind::Decrypt(header) => Some(ClipMeta {
            vin: header.vin.clone(),
            key_id: header.key_id,
            timestamp: header.timestamp,
        }),
        JobKind::Copy => None,
    }
}

fn finish_detail(
    task: &Task,
    dest: &str,
    bytes: u64,
    elapsed: Duration,
    key_len: Option<usize>,
) -> String {
    match (&task.meta, key_len) {
        (Some(meta), Some(len)) => format!(
            "ok {} -> {dest} {} in {} vin={} key_id={} timestamp={} key={len}B",
            task.label,
            format_bytes(bytes),
            format_duration(elapsed),
            meta.vin,
            meta.key_id,
            meta.timestamp
        ),
        _ => format!(
            "copy {} -> {dest} {} in {}",
            task.label,
            format_bytes(bytes),
            format_duration(elapsed)
        ),
    }
}

fn fail_detail(label: &str, elapsed: Duration, meta: Option<&ClipMeta>) -> String {
    match meta {
        Some(meta) => format!(
            "fail {label} in {} vin={} key_id={} timestamp={}",
            format_duration(elapsed),
            meta.vin,
            meta.key_id,
            meta.timestamp
        ),
        None => format!("fail {label} in {}", format_duration(elapsed)),
    }
}

fn count_label(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis >= 10_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{millis}ms")
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tesdec::container::ClipHeader;

    #[test]
    fn verbose_parses_on_either_side_of_the_subcommand() {
        let before = Cli::try_parse_from([
            "tesdec",
            "--verbose",
            "decrypt",
            "clip.mp4",
            "--output",
            "out",
        ])
        .unwrap();
        assert!(before.verbose);

        let after = Cli::try_parse_from(["tesdec", "decrypt", "-v", "-", "--output", "-"]).unwrap();
        assert!(after.verbose);
        match after.command {
            Command::Decrypt(args) => {
                assert_eq!(args.paths.len(), 1);
                assert!(files::is_dash(&args.paths[0]));
                assert!(args
                    .output
                    .as_ref()
                    .is_some_and(|path| files::is_dash(path)));
            }
            _ => panic!("expected decrypt"),
        }

        let login = Cli::try_parse_from(["tesdec", "-v", "login"]).unwrap();
        assert!(login.verbose);
        let quiet =
            Cli::try_parse_from(["tesdec", "decrypt", "clip.mp4", "--output", "out"]).unwrap();
        assert!(!quiet.verbose);
    }

    #[test]
    fn verbose_lines_name_the_clip_and_omit_key_material() {
        let job = files::Job {
            src: "clip.mp4".into(),
            dest: "out.mp4".into(),
            label: "clip.mp4".into(),
            kind: JobKind::Decrypt(ClipHeader {
                plaintext_size: 5000,
                vin: "5YJ3E1EA7KF000001".into(),
                key_id: 7,
                timestamp: 99,
                wrapped_key: vec![0xAB; 44],
                public_key: vec![0x04, 0x22],
            }),
        };
        let planned = plan_detail(&job, "out.mp4");
        assert!(planned.contains("vin=5YJ3E1EA7KF000001"), "{planned}");
        assert!(planned.contains("key_id=7"), "{planned}");
        assert!(planned.contains("timestamp=99"), "{planned}");
        assert!(!planned.contains("abab"), "{planned}");

        let task = Task {
            label: job.label.clone(),
            src: job.src.clone(),
            dest: job.dest.clone(),
            op: TaskOp::Copy,
            meta: clip_meta(&job),
        };
        let line = finish_detail(
            &task,
            "out.mp4",
            5000,
            Duration::from_millis(1500),
            Some(16),
        );
        assert!(line.contains("key=16B"), "{line}");
        assert!(line.contains("1500ms"), "{line}");
        assert!(line.contains("vin=5YJ3E1EA7KF000001"), "{line}");
        assert!(!line.contains("abab"), "{line}");

        let failed = fail_detail(
            "clip.mp4",
            Duration::from_millis(12_500),
            task.meta.as_ref(),
        );
        assert_eq!(
            failed,
            "fail clip.mp4 in 12.5s vin=5YJ3E1EA7KF000001 key_id=7 timestamp=99"
        );
    }
}
