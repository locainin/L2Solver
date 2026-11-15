use super::{CapturePreparation, admit, parent_allowance, prepare_capture_from_input};
use crate::workbench::tshark::{ObjectExportBudget, resources};
use l2_workbench::job::{Job, MemoryBudget};
use l2_workbench::tshark::SourceIdentity;
use std::{
    error::Error,
    fs::{self, File},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn object_parent_allowance() -> Result<(), Box<dyn Error>> {
    let request =
        resources::object_request(ObjectExportBudget::DEFAULT, None, Some("20000".into()))?;
    assert_eq!(
        parent_allowance(0, 0, 0, Some(request.budget))?,
        20_000 * 4096 + 2 * 64 * 1024
    );
    Ok(())
}

#[test]
fn object_environment() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "L2_TEST_OBJECT_ENVIRONMENT";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = PathBuf::from(directory);
        let mut preparation = CapturePreparation {
            capture: directory.join("capture"),
            executable: PathBuf::from("unavailable-tshark"),
            keylog: None,
            timeout: Duration::from_secs(10),
            timeout_seconds: 10,
            input_maximum: Some(1024),
            object_budget: Some(ObjectExportBudget::DEFAULT),
            metadata_maximum: 1024,
            output_maximum: 1024,
            diagnostic_maximum: 1024,
        };
        if std::env::var_os("L2_TEST_OBJECT_VALID").is_some_and(|value| value == "1") {
            return object_admission(&preparation, &directory);
        }
        let error = admit(&preparation, Some(&directory), Instant::now(), None, None)
            .err()
            .ok_or("invalid object environment was accepted")?;
        assert!(error.to_string().contains("L2SOLVER_TSHARK_OBJECT_"));
        preparation.object_budget = None;
        let _admission = admit(&preparation, Some(&directory), Instant::now(), None, None)?;
        assert_eq!(fs::read_dir(&directory)?.count(), 1);
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("capture"), b"capture")?;
    for (bytes, files, valid) in [("invalid", "300", "0"), ("1", "0", "0"), ("1", "300", "1")] {
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "workbench::tshark::preparation::tests::object_environment",
            ])
            .env(CHILD, directory.path())
            .env("L2_TEST_OBJECT_VALID", valid)
            .env("L2SOLVER_TSHARK_OBJECT_MIB", bytes)
            .env("L2SOLVER_TSHARK_OBJECT_FILES", files)
            .output()?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn object_admission(
    preparation: &CapturePreparation,
    directory: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(128 * 1024 * 1024);
    let job = Job::with_memory_budget("object admission", &memory);
    let admission = admit(
        preparation,
        Some(directory),
        Instant::now(),
        None,
        Some(&job),
    )?;
    let budget = ObjectExportBudget {
        temporary_bytes: 1024 * 1024,
        temporary_files: 300,
    };
    assert_eq!(
        admission.resources.limits().object_bytes.get(),
        budget.temporary_bytes
    );
    assert_eq!(
        admission.resources.limits().object_files.get(),
        budget.temporary_files
    );
    let parent = parent_allowance(
        preparation.metadata_maximum,
        preparation.output_maximum,
        preparation.diagnostic_maximum,
        Some(budget),
    )?;
    assert_eq!(
        memory.snapshot()?.working_sets.reserved_bytes,
        parent + admission.resources.limits().child_memory_bytes.get()
    );
    drop(admission);
    assert_eq!(memory.snapshot()?.working_sets.reserved_bytes, 0);
    Ok(())
}

#[test]
fn retained_length_preflight() -> Result<(), Box<dyn Error>> {
    let source_directory = tempfile::tempdir()?;
    let workspace_parent = tempfile::tempdir()?;
    let source = source_directory.path().join("capture");
    fs::write(&source, b"capture")?;
    for length in [6, 8] {
        let mut retained = File::open(&source)?;
        let identity = SourceIdentity {
            label: "capture".into(),
            length,
            sha256: l2_workbench::sha256(b"capture"),
        };
        let preparation = CapturePreparation {
            capture: source.clone(),
            executable: PathBuf::from("unavailable-tshark"),
            keylog: None,
            timeout: Duration::from_secs(2),
            timeout_seconds: 2,
            input_maximum: Some(identity.length),
            object_budget: None,
            metadata_maximum: 1024,
            output_maximum: 1024,
            diagnostic_maximum: 1024,
        };

        let error = prepare_capture_from_input(
            &preparation,
            Some(workspace_parent.path()),
            Instant::now(),
            Some((&mut retained, &identity)),
            None,
        )
        .err()
        .ok_or("changed retained length was accepted")?;
        assert!(error.to_string().contains("retained source length changed"));
        assert_eq!(fs::read_dir(workspace_parent.path())?.count(), 0);
    }
    Ok(())
}
