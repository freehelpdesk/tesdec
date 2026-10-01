//! Discover clips in files and directories, and decide where decrypted output goes.

use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
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
        bail!("choose --output <DIR> to write a new copy, or --in-place to replace the encrypted clips");
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
    let label = label_for(root, path, multiple, explicit_file);
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

fn label_for(root: &Path, path: &Path, multiple: bool, explicit_file: bool) -> String {
    if explicit_file {
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
        })
        .unwrap();
        let labels: Vec<_> = planned.jobs.iter().map(|job| job.dest.clone()).collect();
        assert!(labels.contains(&out.join("TeslaCam/recent.mp4")));
        assert!(labels.contains(&out.join("clip.mp4")));
        let _ = fs::remove_dir_all(&root);
    }
}
