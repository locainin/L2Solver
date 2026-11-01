//! Export recovered byte artifacts into one safely published directory

use super::artifact_export::{self, ArtifactProvenance, SelectedArtifact};
use super::load;
use serde::Serialize;
use std::{error::Error, fmt::Write as _, fs::File, io::Write, path::Path};

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: u8,
    artifacts: Vec<ArtifactRecord<'a>>,
}

#[derive(Serialize)]
struct ArtifactRecord<'a> {
    file: &'a str,
    byte_length: usize,
    nodes: &'a [ArtifactProvenance],
}

pub(super) fn run(
    case_path: &Path,
    directory: &Path,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = load(case_path)?;
    let artifacts = artifact_export::select_artifacts(&case, None)?;
    let node_count = artifact_export::artifact_node_count(&artifacts);
    let complete = case.collection_complete();
    let summary = format_summary(directory, &artifacts, complete, node_count);
    let manifest = Manifest {
        schema_version: 1,
        artifacts: artifacts
            .iter()
            .map(|artifact| ArtifactRecord {
                file: artifact.file_name(),
                byte_length: artifact.bytes().len(),
                nodes: artifact.provenance(),
            })
            .collect(),
    };

    artifact_export::publish_artifact_directory(directory, &artifacts, |staging| {
        let mut manifest_file = File::options()
            .write(true)
            .create_new(true)
            .open(staging.join("manifest.json"))?;
        serde_json::to_writer(&mut manifest_file, &manifest)?;
        manifest_file.write_all(b"\n")?;
        manifest_file.sync_all()?;

        let mut summary_file = File::options()
            .write(true)
            .create_new(true)
            .open(staging.join("summary.txt"))?;
        summary_file.write_all(summary.as_bytes())?;
        summary_file.sync_all()?;
        Ok(())
    })?;

    write_cli_summary(output, directory, &artifacts, node_count, complete)?;
    Ok(complete)
}

fn format_summary(
    directory: &Path,
    artifacts: &[SelectedArtifact<'_>],
    complete: bool,
    node_count: usize,
) -> String {
    let duplicate_count = node_count - artifacts.len();
    let mut summary = format!(
        "Recovered artifacts\nDirectory: {}\nFiles: {}; retained artifact nodes: {}; duplicate byte references grouped: {}\nEvidence retention: {}\n",
        directory.display().to_string().escape_debug(),
        artifacts.len(),
        node_count,
        duplicate_count,
        if complete { "complete" } else { "incomplete" },
    );
    for artifact in artifacts {
        summary.push_str(artifact.file_name());
        summary.push_str(" <- ");
        for (index, node) in artifact.provenance().iter().enumerate() {
            if index > 0 {
                summary.push_str(", ");
            }
            let _ = write!(summary, "{} node {}", node.kind.escape_debug(), node.id);
            if let Some(path) = &node.archive_path {
                let _ = write!(summary, " (archive path {path:?})");
            }
            if let Some(completion_basis) = &node.completion_basis {
                let _ = write!(summary, " (completion basis {completion_basis:?})");
            }
            let _ = write!(
                summary,
                " (Reconstruction: {})",
                node.reconstruction_status.as_str()
            );
            let structural_status = node.structural_validation.status();
            let _ = write!(
                summary,
                " (Structural validation: {}",
                structural_status.human_label()
            );
            if let Some(format) = node.structural_validation.format() {
                let _ = write!(summary, " as {format:?}");
            }
            summary.push(')');
            if let Some(evidence_node) = node.validation_evidence_node() {
                let _ = write!(summary, " (validation evidence node {evidence_node})");
            }
            if let Some(evidence_node) = node.extension_evidence_node {
                let _ = write!(summary, " (extension evidence node {evidence_node})");
            }
        }
        summary.push('\n');
    }
    summary
}

fn write_cli_summary(
    output: &mut impl Write,
    directory: &Path,
    artifacts: &[SelectedArtifact<'_>],
    node_count: usize,
    complete: bool,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Exported {} recovered artifact {} from {} retained {} to {}",
        artifacts.len(),
        plural(artifacts.len(), "file", "files"),
        node_count,
        plural(node_count, "node", "nodes"),
        directory.display().to_string().escape_debug()
    )?;
    for artifact in artifacts {
        for node in artifact.provenance() {
            let structural_status = node.structural_validation.status();
            write!(
                output,
                "  {} node {}: Reconstruction: {}; Structural validation: {}",
                artifact.file_name(),
                node.id,
                node.reconstruction_status.as_str(),
                structural_status.human_label()
            )?;
            if let Some(format) = node.structural_validation.format() {
                write!(output, " as {format}")?;
            }
            writeln!(output)?;
        }
    }
    if !complete {
        writeln!(
            output,
            "Evidence retention is incomplete (exit status 3); retained artifact files were exported"
        )?;
    }
    Ok(())
}

const fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}
