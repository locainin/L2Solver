//! Describe the limits of artifact-digest publication correlation

use super::{RecoveryTransitionSample, RecoveryTransitionStage, RecoveryTransitionSummary};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Attribution {
    basis: &'static str,
    pub(super) complete: bool,
    unrepresented_events: u64,
    unrepresented_artifacts_at_least: u64,
    artifact_count_unknown_events: u64,
    validation_identities_unavailable: bool,
    transition_history_omitted: bool,
}

pub(super) fn attribution(
    summary: &RecoveryTransitionSummary,
    compact: bool,
    records_omitted: bool,
) -> Option<Attribution> {
    let mut result = Attribution {
        basis: "artifact_digest",
        complete: true,
        unrepresented_events: 0,
        unrepresented_artifacts_at_least: 0,
        artifact_count_unknown_events: 0,
        validation_identities_unavailable: false,
        transition_history_omitted: summary.checkpoint_omitted_transition_records > 0
            || records_omitted,
    };
    let mut observed = false;
    for record in &summary.records {
        if record.stage != RecoveryTransitionStage::Publication {
            continue;
        }
        observed = true;
        let Some(RecoveryTransitionSample::Publication(sample)) = record.sample else {
            result.unrepresented_events = result.unrepresented_events.saturating_add(record.count);
            result.artifact_count_unknown_events = result
                .artifact_count_unknown_events
                .saturating_add(record.count);
            continue;
        };
        // One retained sample cannot describe the other merged events
        let unrepresented = record.count.saturating_sub(1);
        result.unrepresented_events = result.unrepresented_events.saturating_add(unrepresented);
        result.artifact_count_unknown_events = result
            .artifact_count_unknown_events
            .saturating_add(unrepresented);
        match (sample.artifact_count, sample.artifact.is_some()) {
            (Some(0), true) | (None, _) => {
                result.artifact_count_unknown_events =
                    result.artifact_count_unknown_events.saturating_add(1);
            }
            (Some(count), has_artifact) => {
                result.unrepresented_artifacts_at_least = result
                    .unrepresented_artifacts_at_least
                    .saturating_add(count.saturating_sub(u64::from(has_artifact)));
            }
        }
    }
    if !observed && !result.transition_history_omitted {
        return None;
    }
    result.validation_identities_unavailable =
        summary.funnel.validation_identities_unavailable(compact);
    result.complete = result.unrepresented_events == 0
        && result.unrepresented_artifacts_at_least == 0
        && result.artifact_count_unknown_events == 0
        && !result.validation_identities_unavailable
        && !result.transition_history_omitted;
    Some(result)
}
