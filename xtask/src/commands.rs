//! Command orchestration for bounded repository maintenance

use crate::{args::Command, corpus, package, process};
#[cfg(unix)]
use rustix::{
    fs::{CWD, RenameFlags, renameat_with},
    io::Errno,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

mod check;

const FUZZ_SMOKE_RUNS: &str = "1000";
const FUZZ_RELEASE_SECONDS: &str = "300";
const FUZZ_INPUT_TIMEOUT_SECONDS: &str = "5";
const FUZZ_MAX_LENGTH: &str = "65535";
// Native event-log inputs need full 64 KiB chunks plus their file envelope
const NATIVE_FUZZ_MAX_LENGTH: &str = "1048576";
const MUTATION_TIMEOUT_SECONDS: &str = "300";
const MUTATION_JOBS: &str = "2";

/// Locate the nearest Cargo workspace from the current directory
///
/// # Errors
///
/// Returns an error when the current directory cannot be read or no workspace
/// manifest can be found in its ancestor directories
pub fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut directory = env::current_dir()?;
    loop {
        let manifest = directory.join("Cargo.toml");
        if manifest.is_file() {
            let contents = fs::read_to_string(&manifest)?;
            if contents.lines().any(|line| line.trim() == "[workspace]") {
                return Ok(directory);
            }
        }
        if !directory.pop() {
            return Err("could not locate workspace Cargo.toml".into());
        }
    }
}

/// Run one parsed maintenance command
///
/// # Errors
///
/// Returns an error when a selected command cannot be prepared or its child
/// process fails
pub fn execute(root: &Path, command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Help => {
            println!("{}", crate::args::usage());
            Ok(())
        }
        Command::Check => check::run(root),
        Command::FuzzSmoke => fuzz(root, false),
        Command::FuzzRelease => fuzz(root, true),
        Command::Mutate => mutate(root),
        Command::Profile => profile(root),
        Command::CorpusMinimize => corpus_minimize(root),
        Command::PackageReview { number } => {
            let result = package::create_review(root, number)?;
            println!(
                "created {} ({} files, sha256 {})",
                result.archive.display(),
                result.file_count,
                result.archive_sha256
            );
            println!("checksum {}", result.checksum.display());
            println!("manifest {}", result.manifest.display());
            Ok(())
        }
    }
}

fn fuzz(root: &Path, release: bool) -> Result<(), Box<dyn std::error::Error>> {
    let targets = fuzz_targets(root)?;
    for target in targets {
        let max_length = if target == "native_endpoints" {
            NATIVE_FUZZ_MAX_LENGTH
        } else {
            FUZZ_MAX_LENGTH
        };
        let mut command = process::CommandSpec::new("cargo")
            .arg("+nightly")
            .arg("fuzz")
            .arg("run");
        if release {
            command = command.arg("-O");
        }
        command = command
            .arg(&target)
            .arg("--")
            .arg(if release {
                format!("-max_total_time={FUZZ_RELEASE_SECONDS}")
            } else {
                format!("-runs={FUZZ_SMOKE_RUNS}")
            })
            .arg(format!("-timeout={FUZZ_INPUT_TIMEOUT_SECONDS}"))
            .arg(format!("-max_len={max_length}"));
        run(root, &command)?;
    }
    Ok(())
}

fn mutate(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    run(
        root,
        &process::CommandSpec::new("cargo").args([
            "mutants",
            "--workspace",
            "--timeout",
            MUTATION_TIMEOUT_SECONDS,
            "--jobs",
            MUTATION_JOBS,
            "--no-shuffle",
            "--baseline",
            "run",
        ]),
    )
}

fn profile(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output_directory = root.join("target/xtask/profile");
    fs::create_dir_all(&output_directory)?;
    run(
        root,
        &process::CommandSpec::new("cargo")
            .args([
                "flamegraph",
                "--package",
                "l2-cli",
                "--bench",
                "offline",
                "--release",
                "--deterministic",
                "--output",
            ])
            .arg(output_directory.join("offline-parser.svg")),
    )
}

fn corpus_minimize(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let targets = fuzz_targets(root)?;
    let corpus_root = root.join("fuzz/corpus");
    let mut corpora = Vec::new();
    for target in targets {
        let source = corpus_root.join(&target);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to minimize symlinked corpus: {}",
                source.display()
            )
            .into());
        }
        if !metadata.is_dir() {
            continue;
        }
        let minimized = corpus_root.join(format!("{target}_minimized"));
        match fs::symlink_metadata(&minimized) {
            Ok(_) => {
                return Err(format!(
                    "refusing to replace existing minimized corpus: {}",
                    minimized.display()
                )
                .into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        corpora.push((target, source, minimized));
    }
    if corpora.is_empty() {
        return Err("no fuzz corpora were found".into());
    }

    for (target, source, minimized) in corpora {
        let prefix = format!("l2solver-xtask-corpus-{target}");
        let temporary = TemporaryDirectory::new_in(&corpus_root, &prefix)?;
        corpus::copy_corpus(&source, temporary.path())?;
        run(
            root,
            &process::CommandSpec::new("cargo")
                .arg("+nightly")
                .args(["fuzz", "cmin"])
                .arg(&target)
                .arg(temporary.path()),
        )?;
        publish_minimized_corpus(temporary.path(), &minimized)?;
        println!("minimized {target} corpus into {}", minimized.display());
    }
    Ok(())
}

fn publish_minimized_corpus(
    temporary: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        match renameat_with(CWD, temporary, CWD, destination, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => Err(format!(
                "refusing to replace existing minimized corpus: {}",
                destination.display()
            )
            .into()),
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (temporary, destination);
        Err("publishing minimized corpora requires Unix atomic no-replace rename".into())
    }
}

fn fuzz_targets(root: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let directory = root.join("fuzz/fuzz_targets");
    let mut targets = fs::read_dir(&directory)?
        .map(|result| result.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    targets.sort_unstable();
    let mut names = Vec::new();
    for path in targets {
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            return Err(format!("fuzz target path is not Unicode: {}", path.display()).into());
        };
        if stem.is_empty()
            || !stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(format!("fuzz target name is unsafe: {stem}").into());
        }
        names.push(stem.to_owned());
    }
    if names.is_empty() {
        return Err("no fuzz targets were found".into());
    }
    Ok(names)
}

fn run(root: &Path, command: &process::CommandSpec) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "running {} {}",
        command.program().to_string_lossy(),
        display_args(command.arguments())
    );
    process::run(root, command)?;
    Ok(())
}

fn display_args(arguments: &[std::ffi::OsString]) -> String {
    arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

struct TemporaryDirectory {
    path: PathBuf,
    parent: PathBuf,
    prefix: String,
}

impl TemporaryDirectory {
    fn new_in(parent: &Path, prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let process = std::process::id();
        for sequence in 0..1_024_u32 {
            let path = parent.join(format!("{prefix}-{process}-{sequence}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        parent: parent.to_owned(),
                        prefix: prefix.to_owned(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate a private temporary corpus directory".into())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let valid_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with(&self.prefix));
        if valid_name && self.path.parent() == Some(self.parent.as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
