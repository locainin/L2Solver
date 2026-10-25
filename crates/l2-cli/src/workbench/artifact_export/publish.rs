//! Publish selected artifacts atomically without replacing existing output

use super::selection::SelectedArtifact;
use crate::publish;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
    path::Path,
};

/// Stage artifacts and companion files, then publish the completed directory once
pub fn publish_artifact_directory(
    directory: &Path,
    artifacts: &[SelectedArtifact<'_>],
    write_companion_files: impl FnOnce(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    publish::create_directory(directory, |staging| {
        write_artifacts_into(staging, artifacts)?;
        write_companion_files(staging)?;

        // Flush staged entries before the publisher makes the directory visible
        File::open(staging)?.sync_all()?;
        Ok(())
    })?;
    Ok(())
}

/// Write selected immutable artifact files into a caller-managed staging directory
pub fn write_artifacts_into(
    staging: &Path,
    artifacts: &[SelectedArtifact<'_>],
) -> Result<(), Box<dyn Error>> {
    for artifact in artifacts {
        validate_flat_file_name(artifact.file_name())?;
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(staging.join(artifact.file_name()))?;
        file.write_all(artifact.bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

pub fn artifact_node_count(artifacts: &[SelectedArtifact<'_>]) -> usize {
    artifacts
        .iter()
        .map(|artifact| artifact.provenance().len())
        .sum()
}

pub(super) fn validate_flat_file_name(file_name: &str) -> io::Result<()> {
    if !crate::safe_filename::is_safe_flat_file_name(file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact file name must be a safe flat name",
        ));
    }
    Ok(())
}
