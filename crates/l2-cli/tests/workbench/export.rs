use super::support::{path_arg, run, save_case};
use l2_workbench::evidence::Case;
use serde_json::json;
use std::{
    error::Error,
    fs,
    process::{Command, Stdio},
};

#[test]
fn exact_retained_stdout_new_file() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let bytes = [0, 0xff, 0, b'A', 0];
    let node = case.add_bytes_node("candidate", &bytes, Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let stdout = run(
        &["export", path_arg(&case_path)?, "--node", &node.to_string()],
        &[],
    )?;
    assert!(stdout.status.success());
    assert_eq!(stdout.stdout, bytes);
    assert_eq!(stdout.stderr.len(), 0);

    let destination = directory.path().join("candidate.bin");
    let file_output = run(
        &[
            "export",
            path_arg(&case_path)?,
            "--node",
            &node.to_string(),
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;
    assert!(file_output.status.success());
    assert_eq!(file_output.stdout.len(), 0);
    assert_eq!(fs::read(&destination)?, bytes);
    assert_eq!(
        String::from_utf8(file_output.stderr)?,
        format!(
            "Exported retained bytes from node {node} to {}\n",
            destination.display()
        )
    );
    Ok(())
}

#[test]
fn unknown_nodes_without_retained_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_node("marker", None, Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("candidate.bin");

    let unknown_node = node.checked_add(1).ok_or("node identifier overflow")?;
    for id in [unknown_node, node] {
        let output = run(
            &[
                "export",
                path_arg(&case_path)?,
                "--node",
                &id.to_string(),
                "--output",
                path_arg(&destination)?,
            ],
            &[],
        )?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout.len(), 0);
        assert!(!String::from_utf8(output.stderr)?.contains("Exported"));
        assert!(!destination.exists());
    }
    Ok(())
}

#[test]
fn incomplete_writing_bytes_partial_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.mark_incomplete("Some input records were omitted")?;
    let bytes = [0x00, 0xff, 0x42];
    let node = case.add_bytes_node("candidate", &bytes, Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &["export", path_arg(&case_path)?, "--node", &node.to_string()],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, bytes);
    assert_eq!(
        String::from_utf8(output.stderr)?,
        format!(
            "Exported retained bytes from node {node} to stdout; case collection is incomplete (exit status 3)\n"
        )
    );

    let destination = directory.path().join("partial.bin");
    let output = run(
        &[
            "export",
            path_arg(&case_path)?,
            "--node",
            &node.to_string(),
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout.len(), 0);
    assert_eq!(fs::read(&destination)?, bytes);
    assert_eq!(
        String::from_utf8(output.stderr)?,
        format!(
            "Exported retained bytes from node {node} to {}; case collection is incomplete (exit status 3)\n",
            destination.display()
        )
    );
    Ok(())
}

#[test]
fn export_not_replace_existing_file() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"new bytes", Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("candidate.bin");
    fs::write(&destination, b"preserve")?;

    let output = run(
        &[
            "export",
            path_arg(&case_path)?,
            "--node",
            &node.to_string(),
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert!(!String::from_utf8(output.stderr)?.contains("Exported"));
    assert_eq!(fs::read(destination)?, b"preserve");
    Ok(())
}

#[test]
fn notice_escapes_control_characters_destination() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("candidate", b"retained", Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("candidate\n.bin");

    let output = run(
        &[
            "export",
            path_arg(&case_path)?,
            "--node",
            &node.to_string(),
            "--output",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 0);
    assert_eq!(fs::read(&destination)?, b"retained");
    let diagnostic = String::from_utf8(output.stderr)?;
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(diagnostic.contains("candidate\\n.bin"));
    Ok(())
}

#[test]
fn incomplete_status_notice_pipe_closed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.mark_incomplete("Some input records were omitted")?;
    let bytes = [0x00, 0xff, 0x42];
    let node = case.add_bytes_node("candidate", &bytes, Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "workbench",
            "export",
            path_arg(&case_path)?,
            "--node",
            &node.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Closing the reader makes the notice fail without changing the export result
    drop(child.stderr.take());
    let output = child.wait_with_output()?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, bytes);
    Ok(())
}
