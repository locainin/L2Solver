//! Merge bounded ZIP member analysis into the source's existing artifact report

use l2_workbench::artifact::{
    AnalysisFormat, AnalysisOmission, AnalysisStage, AnalyzedArtifact, ArtifactAnalysis,
    ArtifactAnalysisOptions, ArtifactOrigin, ArtifactValidationState, ValidationSummary,
    analyze_artifacts_with_memory, archive_member_origin, zip::ZipArtifactReport,
};
use l2_workbench::job::MemoryLease;
use std::{error::Error, io};

pub(super) fn append_members(
    report: &mut ArtifactAnalysis,
    archive: ZipArtifactReport,
    parent_index: usize,
    options: ArtifactAnalysisOptions,
    omission_memory: &mut MemoryLease,
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
        omission_memory,
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
    omission_memory: &'a mut MemoryLease,
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
            self.push_omission(AnalysisOmission::ZipMember {
                artifact_index: self.parent_index,
                entry_index: entry.metadata.index,
                reason,
            })?;
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
            self.push_omission(AnalysisOmission::ArtifactLimit {
                maximum: self.options.limits.max_artifacts,
            })?;
            return Ok(());
        }
        if bytes.len() > remaining_output {
            self.push_omission(AnalysisOmission::OutputLimit {
                parent_index: self.parent_index,
                length: bytes.len(),
                remaining: remaining_output,
            })?;
            return Ok(());
        }
        let identity_work = bytes
            .len()
            .checked_add(entry.metadata.raw_name.len())
            .ok_or("member identity work overflows")?;
        let remaining_work = self
            .options
            .limits
            .max_total_work_bytes
            .saturating_sub(self.report.work_bytes);
        if identity_work > remaining_work {
            return self.push_omission(AnalysisOmission::WorkLimit {
                artifact_index: self.parent_index,
                stage: AnalysisStage::ArtifactIdentity,
                requested: identity_work,
                remaining: remaining_work,
            });
        }
        // Both the member and its original name receive exact identities
        self.report.work_bytes += entry.metadata.raw_name.len();
        let preview_bytes = entry.metadata.raw_name.len().min(32) * 2;
        // Admit the name digest and preview before constructing member provenance
        super::analysis_memory::charge(self.omission_memory, 128 + preview_bytes)?;
        let origin = archive_member_origin(self.parent_index, self.archive_length, &entry.metadata);
        if self.options.limits.max_depth == 0
            || bytes.len() > self.options.limits.max_input_bytes
            || self.signature_remaining == 0
        {
            return self.append_unanalyzed(bytes, origin);
        }
        self.append_analyzed(
            &bytes,
            origin,
            entry.metadata.index,
            remaining_count,
            remaining_output,
        )
    }

    fn append_analyzed(
        &mut self,
        bytes: &[u8],
        origin: ArtifactOrigin,
        entry_index: usize,
        remaining_count: usize,
        remaining_output: usize,
    ) -> Result<(), Box<dyn Error>> {
        let mut child_options = self.options;
        child_options.limits.max_artifacts = remaining_count;
        child_options.limits.max_total_output_bytes = remaining_output;
        let remaining_work = self
            .options
            .limits
            .max_total_work_bytes
            .saturating_sub(self.report.work_bytes);
        // The analyzer hashes the exact member once before inspecting it
        self.report.work_bytes += bytes.len();
        child_options.limits.max_total_work_bytes = remaining_work - bytes.len();
        child_options.limits.max_zip_expanded_bytes = self.zip_remaining;
        child_options.limits.max_signature_scan_bytes = self.signature_remaining;
        child_options.limits.max_depth = self.options.limits.max_depth.saturating_sub(1);
        let child =
            analyze_artifacts_with_memory(bytes, None, child_options, self.omission_memory)?;
        self.merge_child(child, origin, entry_index)
    }

    fn append_unanalyzed(
        &mut self,
        bytes: Vec<u8>,
        origin: ArtifactOrigin,
    ) -> Result<(), Box<dyn Error>> {
        let remaining = self
            .options
            .limits
            .max_total_work_bytes
            .saturating_sub(self.report.work_bytes);
        if bytes.len() > remaining {
            return self.push_omission(AnalysisOmission::WorkLimit {
                artifact_index: self.parent_index,
                stage: AnalysisStage::ArtifactIdentity,
                requested: bytes.len(),
                remaining,
            });
        }
        // Member identity needs a complete byte pass even when inspection is skipped
        self.report.work_bytes += bytes.len();
        let index = self.next_index;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or("artifact index overflows")?;
        let length = bytes.len();
        super::analysis_memory::grow_vec(&mut self.report.artifacts, self.omission_memory, 1)?;
        let mut origins = Vec::new();
        super::analysis_memory::grow_vec(&mut origins, self.omission_memory, 1)?;
        origins.push(origin);
        super::analysis_memory::charge(self.omission_memory, 128)?;
        self.report.artifacts.push(AnalyzedArtifact {
            index,
            origins,
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
        self.push_omission(omission)?;
        Ok(())
    }

    fn merge_child(
        &mut self,
        mut child: ArtifactAnalysis,
        origin: ArtifactOrigin,
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
        let mut index_memory = self
            .omission_memory
            .split_off(0)
            .ok_or("index lease missing")?;
        let mut indices = Vec::new();
        super::analysis_memory::grow_vec(&mut indices, &mut index_memory, child.artifacts.len())?;
        let mut origin = Some(origin);
        for mut artifact in child.artifacts.drain(..) {
            for candidate in &mut artifact.origins {
                match candidate {
                    ArtifactOrigin::Source => {
                        *candidate = origin.take().ok_or("duplicate member source origin")?;
                    }
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
            let omission = rebase_omission(omission, &indices, entry_index, self.omission_memory)?;
            // The child analyzer already admitted any owned omission payload
            super::analysis_memory::reserve_omission(
                &mut self.report.omissions,
                self.omission_memory,
            )?;
            self.report.omissions.push(omission);
        }
        for mut region in child.region_transform_reports {
            region.artifact_index = *indices
                .get(region.artifact_index)
                .ok_or("region artifact index missing")?;
            super::analysis_memory::grow_vec(
                &mut self.report.region_transform_reports,
                self.omission_memory,
                1,
            )?;
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
                        super::analysis_memory::reserve_omission(
                            &mut self.report.omissions,
                            self.omission_memory,
                        )?;
                        self.report.omissions.push(AnalysisOmission::ArtifactLimit {
                            maximum: self.options.limits.max_artifacts,
                        });
                    } else {
                        super::analysis_memory::grow_vec(
                            &mut existing.origins,
                            self.omission_memory,
                            1,
                        )?;
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
            super::analysis_memory::grow_vec(&mut self.report.artifacts, self.omission_memory, 1)?;
            self.report.artifacts.push(artifact);
            Ok(index)
        }
    }

    fn push_omission(&mut self, omission: AnalysisOmission) -> Result<(), Box<dyn Error>> {
        super::analysis_memory::reserve_omission(&mut self.report.omissions, self.omission_memory)?;
        super::analysis_memory::charge_omission_payload(&omission, self.omission_memory)?;
        self.report.omissions.push(omission);
        Ok(())
    }
}

fn rebase_omission(
    mut omission: AnalysisOmission,
    indices: &[usize],
    entry_index: usize,
    memory: &mut MemoryLease,
) -> Result<AnalysisOmission, Box<dyn Error>> {
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
            reason: super::analysis_memory::format_message(
                format_args!("member {entry_index}: {omission:?}"),
                memory,
            )?,
        };
    }
    Ok(omission)
}
