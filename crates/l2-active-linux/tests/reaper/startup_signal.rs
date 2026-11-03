use super::{ACTIVE_HELPERS, REAPER, reserve, sigchld_ignored};
use std::{io, process::Command, sync::atomic::Ordering};

const CHILD_MODE: &str = "L2_TEST_REAPER_SIGCHLD_CHILD";

#[test]
fn signal_status_rejects_missing_and_malformed_ignored_masks() {
    for status in [
        "",
        "SigIgn:\n",
        "SigIgn: not-hex\n",
        "SigIgn: 100000000000000000000000000000000\n",
    ] {
        assert_eq!(
            sigchld_ignored(status).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData),
            "status: {status:?}"
        );
    }
}

#[test]
fn signal_status_distinguishes_sigchld_from_other_ignored_signals() -> io::Result<()> {
    let sigchld = 1_u128 << (nix::libc::SIGCHLD - 1);
    assert!(sigchld_ignored(&format!("SigIgn: {sigchld:016x}\n"))?);
    assert!(!sigchld_ignored("SigIgn: 0000000000000001\n")?);
    // Some Linux architectures expose 128 signal bits in proc status
    assert!(!sigchld_ignored(
        "SigIgn: 00000001000000000000000000000000\n"
    )?);
    Ok(())
}

fn ignored_signals() -> io::Result<String> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find(|line| line.starts_with("SigIgn:"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("missing SigIgn status"))
}

fn run_with_disposition(disposition: &str, test: &str) -> io::Result<()> {
    let output = Command::new("python3")
        .args([
            "-c",
            "import os, signal, sys; signal.signal(signal.SIGCHLD, getattr(signal, sys.argv[1])); os.execv(sys.argv[2], [sys.argv[2], '--exact', sys.argv[3], '--nocapture'])",
            disposition,
        ])
        .arg(std::env::current_exe()?)
        .arg(test)
        .env(CHILD_MODE, "1")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "signal disposition child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[test]
fn ignored_sigchld_rejects_helper_reservation_before_startup() -> io::Result<()> {
    if std::env::var_os(CHILD_MODE).is_none() {
        return run_with_disposition(
            "SIG_IGN",
            "reaper::startup_signal::ignored_sigchld_rejects_helper_reservation_before_startup",
        );
    }

    let before = ignored_signals()?;
    let error = match reserve() {
        Ok(lease) => {
            drop(lease);
            return Err(io::Error::other("ignored SIGCHLD was accepted"));
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("SIGCHLD"));
    assert!(REAPER.get().is_none(), "reaper started before rejection");
    assert_eq!(ACTIVE_HELPERS.load(Ordering::Acquire), 0);
    assert_eq!(ignored_signals()?, before, "signal disposition changed");
    Ok(())
}

#[test]
fn default_sigchld_allows_helper_reservation_without_changing_disposition() -> io::Result<()> {
    if std::env::var_os(CHILD_MODE).is_none() {
        return run_with_disposition(
            "SIG_DFL",
            "reaper::startup_signal::default_sigchld_allows_helper_reservation_without_changing_disposition",
        );
    }

    let before = ignored_signals()?;
    let lease = reserve()?;
    assert_eq!(ACTIVE_HELPERS.load(Ordering::Acquire), 1);
    drop(lease);
    assert_eq!(ACTIVE_HELPERS.load(Ordering::Acquire), 0);
    assert_eq!(ignored_signals()?, before, "signal disposition changed");
    Ok(())
}
