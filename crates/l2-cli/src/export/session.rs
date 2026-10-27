//! Identify capture results independently of output paths and presentation settings

use crate::{
    arguments::ExportOptions,
    result_directory::{ResultIdentity, ResultKind},
};
use l2_workbench::job::cache::{SourceFingerprint, SourceIdentity};
use serde_json::json;
use std::error::Error;

pub(super) fn identity(
    options: &ExportOptions,
    job: &l2_workbench::job::Job,
) -> Result<ResultIdentity, Box<dyn Error>> {
    let fingerprint = SourceFingerprint::fast(&options.capture).map_err(|error| {
        std::io::Error::other(format!(
            "cannot open capture {} as a stable regular, non-symlink file: {error}",
            options.capture.display()
        ))
    })?;
    Ok(ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: super::recovery_cache::RECOVERY_STAGE_VERSION,
        source: SourceIdentity::Fast(fingerprint),
        settings: json!({
            "native_case_version": crate::workbench::full_source::NATIVE_CASE_VERSION,
            "evidence_encoding_version": super::evidence::ENCODING_VERSION,
            "evidence_compression_policy": super::evidence::COMPRESSION_POLICY_VERSION,
            "transform_proposal_version": l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
            "profile": options.recovery.profile,
            "memory_limit": options.recovery.memory_limit,
            "require_tshark": options.require_tshark,
            "tshark": crate::workbench::tshark_cache_identity(Some(job)),
        }),
    })
}

pub(super) fn check_source_unchanged(
    options: &ExportOptions,
    identity: &ResultIdentity,
) -> Result<(), Box<dyn Error>> {
    if let SourceIdentity::Fast(expected) = &identity.source {
        let current = SourceFingerprint::fast(&options.capture)?;
        if expected != &current {
            return Err(std::io::Error::other(
                "capture changed during extraction; the previous output remains intact",
            )
            .into());
        }
    }
    Ok(())
}
