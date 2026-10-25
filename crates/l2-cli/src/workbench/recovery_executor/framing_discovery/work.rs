use super::super::RecoveryExecutionError;
use super::input::{FramingDiscoveryPlan, FramingInput};
use l2_workbench::{
    evidence::{
        Case, MAX_BLOBS, MAX_EDGES, MAX_NODES, MAX_REASON_BYTES, MAX_RELATION_BYTES,
        MAX_SOURCE_LABEL_BYTES, MAX_SOURCES, MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES,
    },
    protocol::{ProtocolLimits, RecordSchemaProposalLimits},
};

pub(super) fn work_bound(inputs: &[FramingInput], limits: ProtocolLimits) -> Option<usize> {
    let total_bytes = inputs
        .iter()
        .try_fold(0_usize, |total, input| total.checked_add(input.byte_length))?;
    let count = inputs.len();
    let candidates = limits.max_candidates;
    // Candidate extraction and full-run materialization each scan per retained rule
    // Alias confirmation scans equal SHA-256 partition groups against one representative
    let scan_factor = candidates
        .checked_mul(3)?
        .checked_add(count)?
        .checked_add(1)?;
    let byte_work = total_bytes.checked_mul(scan_factor)?;
    let prefix_work = count
        .checked_mul(limits.max_prefix_offset.checked_add(1)?)?
        .checked_mul(14)?;
    let fixed_size_work = inputs.first()?.byte_length;
    byte_work
        .checked_add(prefix_work)?
        .checked_add(fixed_size_work)?
        .checked_add(limits.max_report_bytes)
}

pub(in crate::workbench::recovery_executor) fn case_work_bound(
    plan: &FramingDiscoveryPlan,
    limits: ProtocolLimits,
) -> Result<usize, RecoveryExecutionError> {
    plan.cohorts
        .values()
        .try_fold(plan.graph_work, |total, inputs| {
            if inputs.is_empty() {
                return Ok(total);
            }
            let Some(bound) = work_bound(inputs, limits) else {
                return Err(RecoveryExecutionError::InvalidPolicy(
                    "framing discovery work bound exceeds this platform's address space".to_owned(),
                ));
            };
            total.checked_add(bound).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "Case-wide framing discovery work exceeds this platform's address space"
                        .to_owned(),
                )
            })
        })
}

pub(in crate::workbench::recovery_executor) fn case_max_cohort_input_bytes(
    plan: &FramingDiscoveryPlan,
) -> Result<usize, RecoveryExecutionError> {
    plan.cohorts.values().try_fold(0_usize, |maximum, inputs| {
        let total = inputs.iter().try_fold(0_usize, |total, input| {
            total.checked_add(input.byte_length).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "framing discovery input batch exceeds this platform's address space"
                        .to_owned(),
                )
            })
        })?;
        Ok(maximum.max(total))
    })
}

pub(in crate::workbench::recovery_executor) fn post_framing_record_phase_work_bound(
    case: &Case,
    plan: &FramingDiscoveryPlan,
    framing_limits: ProtocolLimits,
    record_limits: RecordSchemaProposalLimits,
    max_output_bytes: usize,
) -> Result<usize, RecoveryExecutionError> {
    let analysis_and_assembly = plan
        .cohorts
        .iter()
        .try_fold(0_usize, |total, (key, inputs)| {
            let raw_bytes = inputs.iter().try_fold(0_usize, |total, input| {
                total.checked_add(input.byte_length).ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "post-framing record input bytes overflowed".to_owned(),
                    )
                })
            })?;
            let metadata_bytes = key
                .source_id
                .len()
                .checked_add(key.scope.len())
                .and_then(|value| value.checked_add(key.endpoint_pair.len()))
                .and_then(|value| value.checked_add(128))
                .ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "post-framing record metadata bound overflowed".to_owned(),
                    )
                })?;
            let cohort_bound = super::super::record_discovery::potential_framing_cohort_work_bound(
                raw_bytes,
                inputs.len(),
                metadata_bytes,
                framing_limits.max_candidates,
                record_limits,
                max_output_bytes.min(record_limits.discovery.record_limits.max_output_bytes),
            )
            .ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "post-framing record work bound exceeds this platform's address space"
                        .to_owned(),
                )
            })?;
            total.checked_add(cohort_bound).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "post-framing record work total overflowed".to_owned(),
                )
            })
        })?;
    let graph_scan = case_graph_scan_work_bound(case, max_output_bytes)?;
    analysis_and_assembly
        .checked_add(graph_scan)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "post-framing record work bound overflowed".to_owned(),
            )
        })
}

fn case_graph_scan_work_bound(
    case: &Case,
    max_output_bytes: usize,
) -> Result<usize, RecoveryExecutionError> {
    let existing_blob_bytes = case.blobs().iter().try_fold(0_usize, |total, blob| {
        total.checked_add(blob.bytes.len()).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy("retained Case blob bytes overflowed".to_owned())
        })
    })?;
    let node_work = MAX_NODES
        .checked_mul(64 + 128)
        .and_then(|value| value.checked_add(MAX_TOTAL_DETAILS_BYTES.checked_mul(2)?))
        .and_then(|value| {
            MAX_TOTAL_SOURCE_RANGES
                .checked_mul(64 + MAX_SOURCE_LABEL_BYTES.checked_mul(2)?)
                .and_then(|ranges| value.checked_add(ranges))
        })
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "Case node graph-scan bound overflowed".to_owned(),
            )
        })?;
    let edge_work = MAX_EDGES
        .checked_mul(MAX_RELATION_BYTES + MAX_REASON_BYTES + 17)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "Case edge graph-scan bound overflowed".to_owned(),
            )
        })?;
    // Case has no aggregate blob-byte limit, so each possible blob gets the output ceiling
    let blob_work = MAX_BLOBS
        .checked_mul(max_output_bytes.checked_add(128).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "Case blob graph-scan bound overflowed".to_owned(),
            )
        })?)
        .and_then(|value| value.checked_add(existing_blob_bytes))
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "Case blob graph-scan bound overflowed".to_owned(),
            )
        })?;
    let source_work = MAX_SOURCES
        .checked_mul(MAX_SOURCE_LABEL_BYTES)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "Case source graph-scan bound overflowed".to_owned(),
            )
        })?;
    node_work
        .checked_add(edge_work)
        .and_then(|value| value.checked_add(blob_work))
        .and_then(|value| value.checked_add(source_work))
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy("Case graph-scan bound overflowed".to_owned())
        })
}
