//! Competing-output summaries across candidate parameters

use super::super::model::{CompetingOutput, DiscoveryCandidate, Partition};
use std::collections::BTreeMap;

pub(super) fn competing_outputs(candidates: &[DiscoveryCandidate]) -> Vec<CompetingOutput> {
    let mut groups: BTreeMap<(Partition, String), Vec<usize>> = BTreeMap::new();
    for candidate in candidates {
        if let Some(digest) = candidate
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
        {
            groups
                .entry((Partition::Discovery, digest.clone()))
                .or_default()
                .push(candidate.id);
        }
        if let Some(digest) = candidate
            .control
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
        {
            groups
                .entry((Partition::Control, digest.clone()))
                .or_default()
                .push(candidate.id);
        }
    }
    groups
        .into_iter()
        .map(|((partition, sha256), candidate_ids)| CompetingOutput {
            partition,
            sha256,
            candidate_ids,
        })
        .collect()
}

pub(super) fn apply_competitor_counts(candidates: &mut [DiscoveryCandidate]) {
    let mut counts = BTreeMap::new();
    for digest in candidates.iter().filter_map(|candidate| {
        candidate
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
    }) {
        *counts.entry(digest.clone()).or_default() += 1;
    }
    for candidate in candidates {
        if let Some(digest) = candidate
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
        {
            candidate.competitor_count = counts.get(digest).copied().unwrap_or(0);
        }
    }
}
