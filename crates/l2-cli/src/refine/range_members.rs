//! Merge bounded ZIP member analysis into the source's existing artifact report

use l2_workbench::artifact::{
    AnalysisFormat, AnalysisOmission, AnalyzedArtifact, ArtifactAnalysis, ArtifactAnalysisOptions,
    ArtifactOrigin, ArtifactValidationState, ValidationSummary, analyze_artifacts,
    archive_member_origin, zip::ZipArtifactReport,
};
use std::{error::Error, io};

pub(super) fn append_members(
    report: &mut ArtifactAnalysis,
    archive: ZipArtifactReport,
    parent_index: usize,
    options: ArtifactAnalysisOptions,
) -> Result<(), Box<dyn Error>> {
    let signature_used = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.signatures_scanned)
        .try_fold(0_usize, |sum, artifact| {
            sum.checked_add(artifact.bytes.len())
        })
        .ok_or("signature work overflows")?;
    let zip_used = report.zip_expanded_work_bytes;
    let mut merger = MemberMerger {
        report,
        options,
        parent_index,
        archive_length: archive.archive_size,
        next_index: parent_index
            .checked_add(1)
            .ok_or("artifact index overflows")?,
        zip_remaining: options
            .limits
            .max_zip_expanded_bytes
            .saturating_sub(zip_used),
        signature_remaining: options
            .limits
            .max_signature_scan_bytes
            .saturating_sub(signature_used),
    };
    for entry in archive.entries {
        merger.append(entry)?;
    }
    Ok(())
}

struct MemberMerger<'a> {
    report: &'a mut ArtifactAnalysis,
    options: ArtifactAnalysisOptions,
    parent_index: usize,
    archive_length: usize,
    next_index: usize,
    zip_remaining: usize,
    signature_remaining: usize,
}

impl MemberMerger<'_> {
    fn append(
        &mut self,
        entry: l2_workbench::artifact::zip::ZipArtifactEntry,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(reason) = entry.omission {
            self.report.omissions.push(AnalysisOmission::ZipMember {
                artifact_index: self.parent_index,
                entry_index: entry.metadata.index,
                reason,
            });
        }
        let Some(bytes) = entry.content else {
            return Ok(());
        };
        let used_output = self
            .report
            .artifacts
            .iter()
            .try_fold(0_usize, |sum, artifact| {
                sum.checked_add(artifact.bytes.len())
            })
            .ok_or("artifact output size overflows")?;
        let remaining_output = self
            .options
            .limits
            .max_total_output_bytes
            .saturating_sub(used_output);
        let remaining_count = self
            .options
            .limits
            .max_artifacts
            .saturating_sub(self.report.artifacts.len().saturating_add(1));
        if remaining_count == 0 {
            self.report.omissions.push(AnalysisOmission::ArtifactLimit {
                maximum: self.options.limits.max_artifacts,
            });
            return Ok(());
        }
        if bytes.len() > remaining_output {
            self.report.omissions.push(AnalysisOmission::OutputLimit {
                parent_index: self.parent_index,
                length: bytes.len(),
                remaining: remaining_output,
            });
            return Ok(());
        }
        let origin = archive_member_origin(self.parent_index, self.archive_length, &entry.metadata);
        if self.options.limits.max_depth == 0
            || bytes.len() > self.options.limits.max_input_bytes
            || self.signature_remaining == 0
        {
            return self.append_unanalyzed(bytes, origin);
        }
        let mut child_options = self.options;
        child_options.limits.max_artifacts = remaining_count;
        child_options.limits.max_total_output_bytes = remaining_output;
        child_options.limits.max_total_work_bytes = self
            .options
            .limits
            .max_total_work_bytes
            .saturating_sub(self.report.work_bytes);
        child_options.limits.max_zip_expanded_bytes = self.zip_remaining;
        child_options.limits.max_signature_scan_bytes = self.signature_remaining;
        child_options.limits.max_depth = self.options.limits.max_depth.saturating_sub(1);
        let child = analyze_artifacts(&bytes, child_options)?;
        self.merge_child(child, &origin, entry.metadata.index)
    }

    fn append_unanalyzed(
        &mut self,
        bytes: Vec<u8>,
        origin: ArtifactOrigin,
    ) -> Result<(), Box<dyn Error>> {
        let index = self.next_index;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or("artifact index overflows")?;
        let length = bytes.len();
        self.report.artifacts.try_reserve(1)?;
        self.report.artifacts.push(AnalyzedArtifact {
            index,
            origins: vec![origin],
            sha256: l2_workbench::sha256(&bytes),
            signature_match_count: 0,
            signatures_scanned: false,
            validation: ValidationSummary {
                state: ArtifactValidationState::Omitted,
                format: None,
                boundary: None,
                range: None,
                structure_count: 0,
            },
            bytes,
        });
        let omission = if self.options.limits.max_depth == 0 {
            AnalysisOmission::DepthLimit {
                artifact_index: index,
                maximum: 0,
            }
        } else if length > self.options.limits.max_input_bytes {
            AnalysisOmission::InputLimit {
                length,
                maximum: self.options.limits.max_input_bytes,
            }
        } else {
            AnalysisOmission::SignatureScanLimit {
                artifact_index: index,
                requested: length,
                remaining: 0,
            }
        };
        self.report.omissions.push(omission);
        Ok(())
    }

    fn merge_child(
        &mut self,
        mut child: ArtifactAnalysis,
        origin: &ArtifactOrigin,
        entry_index: usize,
    ) -> Result<(), Box<dyn Error>> {
        let signature_work = child
            .artifacts
            .iter()
            .filter(|artifact| artifact.signatures_scanned)
            .try_fold(0_usize, |sum, artifact| {
                sum.checked_add(artifact.bytes.len())
            })
            .ok_or("signature work overflows")?;
        self.signature_remaining = self
            .signature_remaining
            .checked_sub(signature_work)
            .ok_or("signature scan budget exceeded")?;
        self.report.work_bytes = self
            .report
            .work_bytes
            .checked_add(child.work_bytes)
            .ok_or("artifact work overflows")?;
        self.zip_remaining = self
            .zip_remaining
            .checked_sub(child.zip_expanded_work_bytes)
            .ok_or("ZIP expansion budget exceeded")?;
        self.report.zip_expanded_work_bytes = self
            .report
            .zip_expanded_work_bytes
            .checked_add(child.zip_expanded_work_bytes)
            .ok_or("ZIP expansion work overflows")?;
        let mut indices = Vec::new();
        indices.try_reserve_exact(child.artifacts.len())?;
        for mut artifact in child.artifacts.drain(..) {
            for candidate in &mut artifact.origins {
                match candidate {
                    ArtifactOrigin::Source => *candidate = origin.clone(),
                    ArtifactOrigin::EmbeddedObject { parent_index, .. }
                    | ArtifactOrigin::ArchiveMember { parent_index, .. }
                    | ArtifactOrigin::Transformation { parent_index, .. } => {
                        *parent_index = *indices
                            .get(*parent_index)
                            .ok_or("member origin index missing")?;
                    }
                    ArtifactOrigin::SourceRange { .. } => {}
                }
            }
            indices.push(self.merge_artifact(artifact)?);
        }
        for omission in child.omissions {
            self.report
                .omissions
                .push(rebase_omission(omission, &indices, entry_index)?);
        }
        for mut region in child.region_transform_reports {
            region.artifact_index = *indices
                .get(region.artifact_index)
                .ok_or("region artifact index missing")?;
            self.report.region_transform_reports.push(region);
        }
        Ok(())
    }

    fn merge_artifact(&mut self, mut artifact: AnalyzedArtifact) -> Result<usize, Box<dyn Error>> {
        if let Some(existing) =
            self.report.artifacts.iter_mut().find(|existing| {
                existing.sha256 == artifact.sha256 && existing.bytes == artifact.bytes
            })
        {
            for origin in artifact.origins {
                if !existing.origins.contains(&origin) {
                    if existing.origins.len() >= self.options.limits.max_artifacts {
                        self.report.omissions.push(AnalysisOmission::ArtifactLimit {
                            maximum: self.options.limits.max_artifacts,
                        });
                    } else {
                        existing.origins.try_reserve(1)?;
                        existing.origins.push(origin);
                    }
                }
            }
            Ok(existing.index)
        } else {
            let index = self.next_index;
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or("artifact index overflows")?;
            artifact.index = index;
            self.report.artifacts.try_reserve(1)?;
            self.report.artifacts.push(artifact);
            Ok(index)
        }
    }
}

fn rebase_omission(
    mut omission: AnalysisOmission,
    indices: &[usize],
    entry_index: usize,
) -> Result<AnalysisOmission, io::Error> {
    let index = match &mut omission {
        AnalysisOmission::OutputLimit { parent_index, .. } => Some(parent_index),
        AnalysisOmission::DepthLimit { artifact_index, .. }
        | AnalysisOmission::WorkLimit { artifact_index, .. }
        | AnalysisOmission::SignatureScanLimit { artifact_index, .. }
        | AnalysisOmission::ValidationLimit { artifact_index, .. }
        | AnalysisOmission::TransformInputLimit { artifact_index, .. }
        | AnalysisOmission::TransformFailed { artifact_index, .. }
        | AnalysisOmission::ZipMember { artifact_index, .. }
        | AnalysisOmission::EmbeddedDiscovery { artifact_index, .. } => Some(artifact_index),
        _ => None,
    };
    if let Some(index) = index {
        *index = *indices
            .get(*index)
            .ok_or_else(|| io::Error::other("member omission index missing"))?;
    } else if matches!(
        omission,
        AnalysisOmission::InputLimit { .. } | AnalysisOmission::SourceOutputLimit { .. }
    ) {
        omission = AnalysisOmission::SourceRangeValidationLimit {
            format: AnalysisFormat::Zip,
            reason: format!("member {entry_index}: {omission:?}"),
        };
    }
    Ok(omission)
}
