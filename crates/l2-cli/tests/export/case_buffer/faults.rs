//! Check injected writer errors and real private-filesystem exhaustion

use super::{
    BufferedResult, MIB, TestResult, assert_previous_and_clean, case_for_index, old_destination,
};
use crate::publish;
use l2_workbench::{evidence::CaseSnapshotLimits, job::MemoryBudget};
use std::{
    cell::Cell,
    fs::File,
    io::{self, Write},
};

#[cfg(target_os = "linux")]
const FULL_TMPFS_TEST: &str = "export::processing::case_buffer::tests::qualification::faults::real_full_tmpfs_spill_preserves_previous_output_and_cleans_private_files";

#[cfg(unix)]
struct InjectedWriteError<'a> {
    file: &'a mut File,
    errno: Option<i32>,
    observed: &'a Cell<bool>,
}

#[cfg(unix)]
impl Write for InjectedWriteError<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(errno) = self.errno {
            self.observed.set(true);
            return Err(io::Error::from_raw_os_error(errno));
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
#[test]
fn injected_enospc_and_edquot_during_snapshot_writes_preserve_previous_output() -> TestResult {
    for errno in [libc::ENOSPC, libc::EDQUOT] {
        for fail_graph in [false, true] {
            let root = tempfile::tempdir()?;
            let (destination, prepared) = old_destination(root.path())?;
            let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
            let observed = Cell::new(false);
            let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
            let outcome = publish::replace_directory_with_precommit(
                &prepared,
                |staging| {
                    let case = case_for_index(&memory, 0, MIB)?;
                    let mut graph = tempfile::tempfile_in(staging)?;
                    let mut blobs = tempfile::tempfile_in(staging)?;
                    let mut graph_writer = InjectedWriteError {
                        file: &mut graph,
                        errno: fail_graph.then_some(errno),
                        observed: &observed,
                    };
                    let mut blob_writer = InjectedWriteError {
                        file: &mut blobs,
                        errno: (!fail_graph).then_some(errno),
                        observed: &observed,
                    };
                    crate::case_snapshot::with_cancellation(None, |cancellation| {
                        crate::case_snapshot::write_streams(
                            &mut graph_writer,
                            &mut blob_writer,
                            &case.case,
                            limits,
                            Some(&memory),
                            cancellation,
                        )
                    })?;
                    Ok(())
                },
                || Ok(()),
            );
            assert!(observed.get());
            assert!(matches!(
                outcome,
                Err(publish::DirectoryPublishError::BeforePublication(_))
            ));
            assert_previous_and_clean(root.path(), &destination, &memory)?;
            println!(
                "injected_errno={errno} stream={}",
                if fail_graph { "graph" } else { "blob" }
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn full_filesystem_child_rejects_the_parent_mount_namespace() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent_namespace = std::fs::read_link("/proc/self/ns/mnt")?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", FULL_TMPFS_TEST, "--nocapture"])
        .env("L2_TEST_ENOSPC_INNER", "1")
        .env("L2_TEST_ENOSPC_ROOT", root.path())
        .env("L2_TEST_PARENT_MOUNT_NAMESPACE", parent_namespace)
        .output()?;
    assert!(!output.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostic.contains("requires a private mount namespace"));
    assert_eq!(root.path().read_dir()?.count(), 0);
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_private_full_filesystem() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let parent = std::env::var_os("L2_TEST_PARENT_MOUNT_NAMESPACE")
        .ok_or("private mount namespace identity missing")?;
    if std::fs::read_link("/proc/self/ns/mnt")?.as_os_str() == parent.as_os_str() {
        return Err("full-filesystem test requires a private mount namespace".into());
    }
    let base = std::path::PathBuf::from(
        std::env::var_os("L2_TEST_ENOSPC_ROOT").ok_or("private full-filesystem root missing")?,
    );
    let output = std::process::Command::new("stat")
        .args(["-f", "-c", "%T %S %b"])
        .arg(&base)
        .output()?;
    if !output.status.success() {
        return Err("cannot inspect the private full filesystem".into());
    }
    let details = std::str::from_utf8(&output.stdout)?;
    let parts: Vec<_> = details.split_whitespace().collect();
    let ["tmpfs", block_size, blocks] = parts.as_slice() else {
        return Err("full-filesystem test requires a 1 MiB tmpfs".into());
    };
    let bytes = block_size
        .parse::<u64>()?
        .checked_mul(blocks.parse::<u64>()?);
    if bytes != Some(u64::try_from(MIB)?) {
        return Err("full-filesystem test requires a 1 MiB tmpfs".into());
    }
    Ok(base)
}

#[cfg(target_os = "linux")]
#[test]
fn real_full_tmpfs_spill_preserves_previous_output_and_cleans_private_files() -> TestResult {
    if std::env::var_os("L2_TEST_ENOSPC_INNER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        let root = tempfile::tempdir()?;
        let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/run-publish-filesystem-faults.sh");
        // The shared harness creates a private mount namespace and a 1 MiB tmpfs
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s", "bash"])
            .arg(harness)
            .arg("--case-buffer-only")
            .arg(std::env::current_exe()?)
            .arg(root.path())
            .env_remove("L2_TEST_ENOSPC_ROOT")
            .env_remove("L2_TEST_ENOSPC_INNER")
            .output()?;
        let marker = format!(
            "actual_filesystem_errno={} private_tmpfs_limit_bytes={}",
            libc::ENOSPC,
            MIB
        );
        if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains(&marker) {
            return Err(format!(
                "private full-filesystem test failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return Ok(());
    }
    let base = verify_private_full_filesystem()?;
    let root = tempfile::tempdir_in(base)?;
    let (destination, prepared) = old_destination(root.path())?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let outcome = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            let result = case_for_index(&memory, 0, 2 * MIB)?;
            drop(BufferedResult::spill(
                result,
                staging,
                limits,
                Some(&memory),
                None,
            )?);
            Ok(())
        },
        || Ok(()),
    );
    let Err(publish::DirectoryPublishError::BeforePublication(error)) = outcome else {
        return Err("full filesystem did not stop publication".into());
    };
    assert!(matches!(
        error.downcast_ref::<l2_workbench::evidence::EvidenceError>(),
        Some(l2_workbench::evidence::EvidenceError::WriteFailed)
    ));
    println!("real_spill_failure={error:?}");
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    let mut probe = tempfile::NamedTempFile::new_in(root.path())?;
    let error = probe
        .as_file_mut()
        .write_all(&vec![0_u8; 2 * MIB])
        .err()
        .ok_or("private tmpfs was not full")?;
    println!(
        "private_tmpfs_probe_error={error:?} kind={:?} raw={:?}",
        error.kind(),
        error.raw_os_error()
    );
    assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    drop(probe);
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    println!(
        "actual_filesystem_errno={} private_tmpfs_limit_bytes={}",
        libc::ENOSPC,
        MIB
    );
    Ok(())
}
