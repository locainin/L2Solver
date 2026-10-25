#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

#[test]
fn fuzz_uses_installed_nightly_toolchain() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = capture_fuzz_arguments("canary")?;
    assert_eq!(
        arguments.lines().collect::<Vec<_>>(),
        [
            "+nightly",
            "fuzz",
            "run",
            "canary",
            "--",
            "-runs=1000",
            "-timeout=5",
            "-max_len=65535"
        ]
    );
    Ok(())
}

#[test]
fn native_endpoint_mutations_event_log() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = capture_fuzz_arguments("native_endpoints")?;
    let configured = arguments
        .lines()
        .find_map(|line| line.strip_prefix("-max_len="))
        .ok_or("fuzz input limit missing")?
        .parse::<usize>()?;
    // A valid EVTX envelope needs its file header and a complete 64 KiB chunk
    assert!(configured >= 4_096 + 65_536);
    assert!(
        configured <= 1_048_576,
        "input exceeds the native endpoint harness budget"
    );
    Ok(())
}

#[test]
fn cmin_persists_result() -> Result<(), Box<dyn std::error::Error>> {
    let project = MinimizeProject::new("corpus-minimize")?;
    let output = project.run()?;
    assert!(
        output.status.success(),
        "xtask failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        fs::read(project.output.join("minimized-seed"))?,
        b"minimized"
    );
    assert_eq!(fs::read(project.source.join("seed"))?, b"original");
    Ok(())
}

#[test]
fn cmin_refuses_existing_result() -> Result<(), Box<dyn std::error::Error>> {
    let project = MinimizeProject::new("corpus-minimize-existing")?;
    fs::create_dir(&project.output)?;
    fs::write(project.output.join("sentinel"), b"keep")?;

    let output = project.run()?;
    assert!(!output.status.success());
    assert_eq!(fs::read(project.output.join("sentinel"))?, b"keep");
    assert!(!project.log.exists());
    Ok(())
}

struct MinimizeProject {
    root: PathBuf,
    source: PathBuf,
    output: PathBuf,
    log: PathBuf,
}

impl MinimizeProject {
    fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root = test_root(name)?;
        fs::write(root.join("Cargo.toml"), "[workspace]\n")?;
        fs::create_dir_all(root.join("fuzz/fuzz_targets"))?;
        fs::write(root.join("fuzz/fuzz_targets/sample.rs"), "")?;
        let source = root.join("fuzz/corpus/sample");
        fs::create_dir_all(&source)?;
        fs::write(source.join("seed"), b"original")?;

        let log = root.join("cargo-arguments.txt");
        let fake_cargo = root.join("cargo");
        fs::write(
            &fake_cargo,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$L2SOLVER_XTASK_CAPTURE\"\nprintf '%s' minimized > \"$5/minimized-seed\"\n",
        )?;
        let mut permissions = fs::metadata(&fake_cargo)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&fake_cargo, permissions)?;

        Ok(Self {
            output: root.join("fuzz/corpus/sample_minimized"),
            root,
            source,
            log,
        })
    }

    fn run(&self) -> std::io::Result<std::process::Output> {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("corpus-minimize")
            .current_dir(&self.root)
            .env("PATH", &self.root)
            .env("L2SOLVER_XTASK_CAPTURE", &self.log)
            .output()
    }
}

impl Drop for MinimizeProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn capture_fuzz_arguments(target: &str) -> Result<String, Box<dyn std::error::Error>> {
    let root = test_root(target)?;
    fs::write(root.join("Cargo.toml"), "[workspace]\n")?;
    fs::create_dir_all(root.join("fuzz/fuzz_targets"))?;
    fs::write(root.join(format!("fuzz/fuzz_targets/{target}.rs")), "")?;

    let log = root.join("cargo-arguments.txt");
    let fake_cargo = root.join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$L2SOLVER_XTASK_CAPTURE\"\n",
    )?;
    let mut permissions = fs::metadata(&fake_cargo)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fake_cargo, permissions)?;

    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("fuzz-smoke")
        .current_dir(&root)
        .env("PATH", &root)
        .env("L2SOLVER_XTASK_CAPTURE", &log)
        .output()?;
    assert!(
        output.status.success(),
        "xtask failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let arguments = fs::read_to_string(&log)?;
    fs::remove_dir_all(root)?;
    Ok(arguments)
}

fn test_root(target: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "l2solver-xtask-fuzz-command-{target}-{}",
        std::process::id()
    ));
    if let Err(error) = fs::remove_dir_all(&root)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error.into());
    }
    fs::create_dir(&root)?;
    Ok(root)
}
