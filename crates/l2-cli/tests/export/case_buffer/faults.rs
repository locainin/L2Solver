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
                    crate::case_snapshot::write_streams(
                        &mut graph_writer,
                        &mut blob_writer,
                        &case.case,
                        limits,
                        Some(&memory),
                    )?;
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
#[ignore = "requires a private size-limited filesystem from the fault harness"]
fn real_full_tmpfs_spill_preserves_previous_output_and_cleans_private_files() -> TestResult {
    let base =
        std::env::var_os("L2_TEST_ENOSPC_ROOT").ok_or("private full-filesystem root missing")?;
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
