//! Discover clips in files and directories, and decide where decrypted output goes.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

use crate::container::{self, ClipHeader, Probe};

#[derive(Debug)]
pub struct Plan {
    pub jobs: Vec<Job>,
    pub skipped: Vec<String>,
    pub invalid: Vec<String>,
}

#[derive(Debug)]
pub struct Job {
    pub src: PathBuf,
    pub dest: PathBuf,
    pub label: String,
    pub kind: JobKind,
}

#[derive(Debug)]
pub enum JobKind {
    Decrypt(ClipHeader),
    Copy,
}

#[derive(Copy, Clone)]
pub struct Options<'a> {
    pub inputs: &'a [PathBuf],
    pub output: Option<&'a Path>,
    pub in_place: bool,
    pub overwrite: bool,
    pub mirror: bool,
    /// Label an explicit stdin spool as `-` instead of its temp path.
    pub label_stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioMode {
    pub from_stdin: bool,
    pub to_stdout: bool,
}

pub fn is_dash(path: &Path) -> bool {
    path.as_os_str() == "-"
}

/// `-` is one clip on stdin, or one decrypted MP4 on stdout.
///
/// `tesdec decrypt -` writes stdout. `tesdec decrypt clip.mp4 --output -` does
/// the same for a file. A directory still has to be expanded before stdout is
/// rejected for more than one clip.
pub fn stdio_mode(
    paths: &[PathBuf],
    output: Option<&Path>,
    in_place: bool,
    mirror: bool,
) -> Result<StdioMode> {
    let dash_inputs = paths.iter().filter(|path| is_dash(path)).count();
    if dash_inputs > 1 || (dash_inputs == 1 && paths.len() != 1) {
        bail!("`-` reads one clip from stdin; do not combine it with other paths");
    }
    let from_stdin = dash_inputs == 1;
    let to_stdout = output.is_some_and(is_dash) || (from_stdin && output.is_none() && !in_place);
    if in_place && from_stdin {
        bail!("stdin has no path to replace; choose --output <DIR> or write to stdout");
    }
    if in_place && to_stdout {
        bail!("--in-place replaces files where they are, so it cannot write to stdout");
    }
    if mirror && to_stdout {
        bail!("--mirror copies a folder of files, so it cannot write to stdout");
    }
    if to_stdout && !from_stdin && paths.len() != 1 {
        bail!("stdout can receive only one clip");
    }
    Ok(StdioMode {
        from_stdin,
        to_stdout,
    })
}

pub fn plan(opts: Options<'_>) -> Result<Plan> {
    if opts.inputs.is_empty() {
        bail!("pass at least one file or directory");
    }
    if opts.in_place && opts.output.is_some() {
        bail!("use either --output or --in-place");
    }
    if opts.mirror && opts.output.is_none() {
        bail!("--mirror copies the rest of a folder, so it needs --output");
    }
    if !opts.in_place && opts.output.is_none() {
        bail!(
            "choose --output <DIR> to write a new copy, --output - to write one clip to stdout, or --in-place to replace the encrypted clips"
        );
    }

    let multiple = opts.inputs.len() > 1;
    let mut plan = Plan {
        jobs: Vec::new(),
        skipped: Vec::new(),
        invalid: Vec::new(),
    };
    let mut seen: HashMap<PathBuf, String> = HashMap::new();

    for input in opts.inputs {
        if !input.exists() {
            bail!("{} does not exist", input.display());
        }
        // Follow a symlink the user named. Links discovered inside a directory are not followed.
        let meta =
            fs::metadata(input).with_context(|| format!("cannot stat {}", input.display()))?;
        if meta.is_file() {
            consider_file(input, input, opts, multiple, true, &mut plan, &mut seen)?;
        } else if meta.is_dir() {
            walk_dir(input, opts, multiple, &mut plan, &mut seen)?;
        } else {
            bail!("{} is not a file or directory", input.display());
        }
    }
    Ok(plan)
}

fn walk_dir(
    root: &Path,
    opts: Options<'_>,
    multiple: bool,
    plan: &mut Plan,
    seen: &mut HashMap<PathBuf, String>,
) -> Result<()> {
    let output_canon = opts.output.and_then(|path| path.canonicalize().ok());
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("cannot read {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if output_contains(path, opts.output, output_canon.as_deref()) {
            continue;
        }
        consider_file(root, path, opts, multiple, false, plan, seen)?;
    }
    Ok(())
}

fn consider_file(
    root: &Path,
    path: &Path,
    opts: Options<'_>,
    multiple: bool,
    explicit_file: bool,
    plan: &mut Plan,
    seen: &mut HashMap<PathBuf, String>,
) -> Result<()> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if name.starts_with('.') || name.ends_with(".tesdec-tmp") {
        return Ok(());
    }
    let is_mp4 = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .eq_ignore_ascii_case("mp4");

    let kind = if is_mp4 {
        match container::probe(path) {
            Probe::Encrypted(header) => JobKind::Decrypt(header),
            Probe::Plain => {
                if opts.in_place {
                    plan.skipped
                        .push(format!("{name}: already a plain MP4, left in place"));
                    return Ok(());
                }
                JobKind::Copy
            }
            Probe::Invalid(message) => {
                plan.invalid.push(message);
                return Ok(());
            }
        }
    } else if explicit_file {
        plan.invalid
            .push(format!("{} is not an .mp4 clip", path.display()));
        return Ok(());
    } else if opts.mirror && !opts.in_place {
        JobKind::Copy
    } else {
        return Ok(());
    };

    let dest = destination(root, path, opts, multiple, explicit_file)?;
    let label = label_for(root, path, multiple, explicit_file, opts.label_stdin);
    if !opts.in_place && !opts.overwrite && dest.exists() && !same_file(&dest, path) {
        plan.skipped
            .push(format!("{label}: already exists at {}", dest.display()));
        return Ok(());
    }
    if let Some(prev) = seen.insert(dest.clone(), label.clone()) {
        bail!(
            "{} would be written by both {prev} and {label}",
            dest.display()
        );
    }
    plan.jobs.push(Job {
        src: path.to_path_buf(),
        dest,
        label,
        kind,
    });
    Ok(())
}

fn output_contains(path: &Path, output: Option<&Path>, output_canon: Option<&Path>) -> bool {
    if let Some(out) = output {
        if path.starts_with(out) {
            return true;
        }
    }
    let Some(out) = output_canon else {
        return false;
    };
    if path.starts_with(out) {
        return true;
    }
    path.canonicalize()
        .map(|canon| canon.starts_with(out))
        .unwrap_or(false)
}

fn destination(
    root: &Path,
    path: &Path,
    opts: Options<'_>,
    multiple: bool,
    explicit_file: bool,
) -> Result<PathBuf> {
    if opts.in_place {
        return Ok(path.to_path_buf());
    }
    let output = opts.output.context("missing output directory")?;
    if explicit_file {
        let name = path.file_name().context("file has no name")?.to_os_string();
        return Ok(output.join(name));
    }
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    if multiple {
        let dirname = root.file_name().unwrap_or_default();
        Ok(output.join(dirname).join(rel))
    } else {
        Ok(output.join(rel))
    }
}

fn label_for(
    root: &Path,
    path: &Path,
    multiple: bool,
    explicit_file: bool,
    label_stdin: bool,
) -> String {
    if explicit_file {
        if label_stdin {
            return "-".to_string();
        }
        return path.display().to_string();
    }
    let rel = path
        .strip_prefix(root)
        .map(|rel| rel.display().to_string())
        .unwrap_or_else(|_| path.display().to_string());
    if multiple {
        let dirname = root.file_name().unwrap_or_default().to_string_lossy();
        format!("{dirname}/{rel}")
    } else {
        rel
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Copy `src` onto `dest` via a temp file so a crash does not leave a half-written clip.
pub fn copy_file(src: &Path, dest: &Path) -> Result<u64> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    let tmp = container::temp_path_for(dest);
    let bytes = fs::copy(src, &tmp)
        .with_context(|| format!("cannot copy {} to {}", src.display(), tmp.display()))?;
    fs::rename(&tmp, dest).with_context(|| format!("cannot move copy into {}", dest.display()))?;
    Ok(bytes)
}

/// Copy decrypted bytes to `dest`. Used for stdout, where only the MP4 belongs.
pub fn copy_bytes_to(src: &Path, dest: &mut impl Write, dest_label: &str) -> Result<u64> {
    let mut input = File::open(src).with_context(|| format!("cannot read {}", src.display()))?;
    let n = io::copy(&mut input, dest)
        .with_context(|| format!("cannot write decrypted bytes to {dest_label}"))?;
    dest.flush()
        .with_context(|| format!("cannot flush {dest_label}"))?;
    Ok(n)
}

pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// Directory removed when dropped. Holds a stdin spool or a stdout scratch file.
pub struct TempTree {
    path: PathBuf,
}

impl TempTree {
    pub fn create(prefix: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).with_context(|| format!("cannot create {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct SpooledStdin {
    dir: PathBuf,
    pub file: PathBuf,
}

impl Drop for SpooledStdin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Read one clip from `reader` into a temp `.mp4` so the container length can be checked.
pub fn spool_reader(mut reader: impl Read) -> Result<SpooledStdin> {
    let dir = std::env::temp_dir().join(format!(
        "tesdec-stdin-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let spooled = SpooledStdin {
        file: dir.join("stdin.mp4"),
        dir,
    };
    let mut out = File::create(&spooled.file)
        .with_context(|| format!("cannot create {}", spooled.file.display()))?;
    let n = io::copy(&mut reader, &mut out).context("cannot read stdin")?;
    out.flush().context("cannot write the stdin spool")?;
    if n == 0 {
        bail!("stdin was empty");
    }
    Ok(spooled)
}

pub fn spool_stdin() -> Result<SpooledStdin> {
    spool_reader(io::stdin().lock())
}

pub fn confirm_in_place(jobs: &[Job], yes: bool) -> Result<()> {
    let count = jobs
        .iter()
        .filter(|job| matches!(job.kind, JobKind::Decrypt(_)))
        .count();
    if count == 0 {
        return Ok(());
    }
    if !yes && !io::stdin().is_terminal() {
        bail!(
            "refusing to replace {count} encrypted clip(s) in a non-interactive shell; pass --yes"
        );
    }
    println!("Replace {count} encrypted clip(s) with decrypted MP4s:");
    for job in jobs
        .iter()
        .filter(|job| matches!(job.kind, JobKind::Decrypt(_)))
        .take(12)
    {
        println!("  {}", job.label);
    }
    if count > 12 {
        println!("  … and {} more", count - 12);
    }
    if yes {
        return Ok(());
    }
    print!("This overwrites those files. Continue? [y/N] ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let answer = line.trim();
    if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
        bail!("left the encrypted clips unchanged");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tesdec-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sealed(dir: &Path, rel: &str) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut plain = vec![0u8; 64];
        plain[4..8].copy_from_slice(b"ftyp");
        let bytes = crate::container::seal(&plain, &[9u8; 16], "5YJ3E1EA7KF000001", 1, 10);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn one_directory_keeps_relative_paths_and_skips_existing() {
        let root = scratch("plan");
        sealed(&root, "SavedClips/a/front.mp4");
        fs::write(root.join("SavedClips/a/event.json"), b"{}").unwrap();
        fs::write(root.join("plain.mp4"), b"\0\0\0\x18ftypisom").unwrap();
        let out = root.join("out");
        fs::create_dir_all(&out).unwrap();
        fs::create_dir_all(out.join("SavedClips/a")).unwrap();
        fs::write(out.join("SavedClips/a/front.mp4"), b"already").unwrap();

        let inputs = [root.clone()];
        let planned = plan(Options {
            inputs: &inputs,
            output: Some(&out),
            in_place: false,
            overwrite: false,
            mirror: false,
            label_stdin: false,
        })
        .unwrap();
        assert!(planned.jobs.iter().any(|job| job.label == "plain.mp4"));
        assert!(planned
            .skipped
            .iter()
            .any(|line| line.contains("SavedClips/a/front.mp4")));
        assert!(!planned
            .jobs
            .iter()
            .any(|job| job.label.ends_with("event.json")));

        let mirrored = plan(Options {
            inputs: &inputs,
            output: Some(&root.join("mirror")),
            in_place: false,
            overwrite: true,
            mirror: true,
            label_stdin: false,
        })
        .unwrap();
        assert!(mirrored
            .jobs
            .iter()
            .any(|job| job.label.ends_with("event.json")));
        let front = mirrored
            .jobs
            .iter()
            .find(|job| job.label.ends_with("front.mp4"))
            .unwrap();
        assert!(matches!(front.kind, JobKind::Decrypt(_)));
        assert_eq!(front.dest, root.join("mirror/SavedClips/a/front.mp4"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn several_inputs_are_namespaced_and_files_use_their_name() {
        let root = scratch("multi");
        let cam = root.join("TeslaCam");
        sealed(&cam, "recent.mp4");
        let loose = root.join("clip.mp4");
        sealed(&root, "clip.mp4");
        let out = root.join("decrypted");
        let inputs = [cam.clone(), loose.clone()];
        let planned = plan(Options {
            inputs: &inputs,
            output: Some(&out),
            in_place: false,
            overwrite: false,
            mirror: false,
            label_stdin: false,
        })
        .unwrap();
        let labels: Vec<_> = planned.jobs.iter().map(|job| job.dest.clone()).collect();
        assert!(labels.contains(&out.join("TeslaCam/recent.mp4")));
        assert!(labels.contains(&out.join("clip.mp4")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dash_selects_stdin_and_stdout() {
        let file = PathBuf::from("clip.mp4");
        let other = PathBuf::from("other.mp4");
        let dir = PathBuf::from("/tmp/out");
        assert_eq!(
            stdio_mode(&[PathBuf::from("-")], None, false, false).unwrap(),
            StdioMode {
                from_stdin: true,
                to_stdout: true,
            }
        );
        assert_eq!(
            stdio_mode(&[PathBuf::from("-")], Some(&dir), false, false).unwrap(),
            StdioMode {
                from_stdin: true,
                to_stdout: false,
            }
        );
        assert_eq!(
            stdio_mode(
                std::slice::from_ref(&file),
                Some(Path::new("-")),
                false,
                false
            )
            .unwrap(),
            StdioMode {
                from_stdin: false,
                to_stdout: true,
            }
        );
        assert_eq!(
            stdio_mode(std::slice::from_ref(&file), Some(&dir), false, false).unwrap(),
            StdioMode {
                from_stdin: false,
                to_stdout: false,
            }
        );
        assert!(stdio_mode(&[PathBuf::from("-"), other.clone()], None, false, false).is_err());
        assert!(stdio_mode(&[PathBuf::from("-")], None, true, false).is_err());
        assert!(stdio_mode(
            std::slice::from_ref(&file),
            Some(Path::new("-")),
            false,
            true
        )
        .is_err());
        assert!(stdio_mode(&[file, other], Some(Path::new("-")), false, false).is_err());
    }

    #[test]
    fn stdin_spool_is_one_labeled_clip_and_is_removed() {
        let root = scratch("spool");
        let sealed_path = sealed(&root, "clip.mp4");
        let bytes = fs::read(&sealed_path).unwrap();
        let spooled = spool_reader(std::io::Cursor::new(bytes)).unwrap();
        let dir = spooled.dir.clone();
        let out = root.join("out");
        let inputs = [spooled.file.clone()];
        let planned = plan(Options {
            inputs: &inputs,
            output: Some(&out),
            in_place: false,
            overwrite: false,
            mirror: false,
            label_stdin: true,
        })
        .unwrap();
        assert_eq!(planned.jobs.len(), 1);
        assert_eq!(planned.jobs[0].label, "-");
        assert_eq!(planned.jobs[0].dest, out.join("stdin.mp4"));
        assert!(matches!(planned.jobs[0].kind, JobKind::Decrypt(_)));
        drop(spooled);
        assert!(!dir.exists());
        assert!(spool_reader(std::io::Cursor::new([])).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn copy_bytes_to_writes_the_file_unchanged() {
        let root = scratch("bytes");
        let src = root.join("plain.mp4");
        fs::write(&src, b"\0\0\0\x18ftypisom").unwrap();
        let mut out = Vec::new();
        let n = copy_bytes_to(&src, &mut out, "stdout").unwrap();
        assert_eq!(n, out.len() as u64);
        assert_eq!(out, b"\0\0\0\x18ftypisom");
        let err = anyhow::Error::from(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            .context("cannot write decrypted bytes to stdout");
        assert!(is_broken_pipe(&err));
        let _ = fs::remove_dir_all(&root);
    }
}
