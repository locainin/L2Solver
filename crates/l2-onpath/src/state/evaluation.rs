//! Conservative report construction and status evaluation

use std::collections::BTreeMap;

use super::{
    AssessmentPhase, AssessmentSession, CheckBudgetUsage,
    support::{CanaryKey, clean_window},
};
use crate::{
    AddressFamily, AgentId, AuthenticatedCanaryReceipt, CanaryExpectation, CanaryTraversal,
    CheckKind, CleanupReceipt, CommitmentSubject, NeighborTransitionReceipt,
    OriginalBindingReceipt, PathExpectation, PrecheckReceipt,
};
use l2_segmentation::PacketReference;

/// Conservative result for one selected check or a complete report
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AssessmentStatus {
    /// Evidence supports the tested protection
    Protected,
    /// Evidence directly establishes an identity or path vulnerability
    Vulnerable,
    /// Evidence is incomplete, lossy, or contradictory
    Inconclusive,
}

impl AssessmentStatus {
    /// Stable report label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::Vulnerable => "vulnerable",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Return whether this status is a directly evidenced failure
    #[must_use]
    pub const fn is_vulnerable(self) -> bool {
        matches!(self, Self::Vulnerable)
    }

    /// Return whether this status supports the tested protection
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Protected)
    }
}

/// Result for one descriptor in an on-path report
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    check: CheckKind,
    status: AssessmentStatus,
    defensible_evidence: bool,
    committed_stimuli: usize,
    planned_stimuli: usize,
    transitions: usize,
    canary_traversals: usize,
    evidence_packets: Vec<PacketReference>,
    limitations: Vec<String>,
    budget_usage: CheckBudgetUsage,
}

impl CheckResult {
    /// Return the selected check kind
    #[must_use]
    pub const fn check(&self) -> CheckKind {
        self.check
    }

    /// Return the conservative result
    #[must_use]
    pub const fn status(&self) -> AssessmentStatus {
        self.status
    }

    /// Return whether the result has complete direct evidence
    #[must_use]
    pub const fn defensible_evidence(&self) -> bool {
        self.defensible_evidence
    }

    /// Return the number of committed stimuli for this check
    #[must_use]
    pub const fn committed_stimuli(&self) -> usize {
        self.committed_stimuli
    }

    /// Return the number of planned stimuli for this check
    #[must_use]
    pub const fn planned_stimuli(&self) -> usize {
        self.planned_stimuli
    }

    /// Return the number of neighbor transition receipts
    #[must_use]
    pub const fn transitions(&self) -> usize {
        self.transitions
    }

    /// Return the number of authenticated canary traversals
    #[must_use]
    pub const fn canary_traversals(&self) -> usize {
        self.canary_traversals
    }

    /// Return packet references supporting accepted or vulnerable evidence
    #[must_use]
    pub fn evidence_packets(&self) -> &[PacketReference] {
        &self.evidence_packets
    }

    /// Return bounded reasons a result remains uncertain
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    /// Return accepted traffic, cleanup reserve, and elapsed duration for this check
    #[must_use]
    pub const fn budget_usage(&self) -> CheckBudgetUsage {
        self.budget_usage
    }
}

/// Source-qualified baseline and cleanup receipts exposed by a report view
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleEvidence<'a> {
    plan: &'a crate::AssessmentPlan,
    originals: &'a BTreeMap<(AgentId, AddressFamily), OriginalBindingReceipt>,
    cleanup: &'a BTreeMap<(AgentId, AddressFamily), CleanupReceipt>,
}

impl<'a> LifecycleEvidence<'a> {
    /// Return accepted original-binding receipts in endpoint order
    pub fn original_bindings(
        &self,
    ) -> impl ExactSizeIterator<Item = &'a OriginalBindingReceipt> + '_ {
        self.originals.values()
    }

    /// Return accepted cleanup receipts in endpoint order
    pub fn cleanup_receipts(&self) -> impl ExactSizeIterator<Item = &'a CleanupReceipt> + '_ {
        self.cleanup.values()
    }

    /// Return endpoint identities with no accepted original-binding receipt
    pub fn missing_original_bindings(&self) -> impl Iterator<Item = (AgentId, AddressFamily)> + '_ {
        self.plan
            .endpoints()
            .iter()
            .filter(|endpoint| {
                !self
                    .originals
                    .contains_key(&(endpoint.id(), endpoint.family()))
            })
            .map(|endpoint| (endpoint.id(), endpoint.family()))
    }

    /// Return endpoint identities with no accepted cleanup receipt
    pub fn missing_cleanup_receipts(&self) -> impl Iterator<Item = (AgentId, AddressFamily)> + '_ {
        self.plan
            .endpoints()
            .iter()
            .filter(|endpoint| {
                !self
                    .cleanup
                    .contains_key(&(endpoint.id(), endpoint.family()))
            })
            .map(|endpoint| (endpoint.id(), endpoint.family()))
    }
}

/// Complete ordered report produced by evaluating one session
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentReport<'a> {
    phase: AssessmentPhase,
    results: Vec<CheckResult>,
    lifecycle_evidence: LifecycleEvidence<'a>,
}

impl AssessmentReport<'_> {
    /// Return the lifecycle phase at evaluation time
    #[must_use]
    pub const fn phase(&self) -> AssessmentPhase {
        self.phase
    }

    /// Return results in immutable plan order
    #[must_use]
    pub fn results(&self) -> &[CheckResult] {
        &self.results
    }

    /// Return original-binding and cleanup receipts separately from check evidence
    #[must_use]
    pub const fn lifecycle_evidence(&self) -> LifecycleEvidence<'_> {
        self.lifecycle_evidence
    }

    /// Return the most conservative result across selected checks
    #[must_use]
    pub fn overall_status(&self) -> AssessmentStatus {
        if self.results.is_empty() {
            return AssessmentStatus::Inconclusive;
        }
        let mut overall = AssessmentStatus::Protected;
        for result in &self.results {
            if result.status.is_vulnerable() {
                return AssessmentStatus::Vulnerable;
            }
            if matches!(result.status, AssessmentStatus::Inconclusive) {
                overall = AssessmentStatus::Inconclusive;
            }
        }
        overall
    }

    /// Alias for report consumers that call the final result a status
    #[must_use]
    pub fn status(&self) -> AssessmentStatus {
        self.overall_status()
    }
}

impl AssessmentSession {
    /// Evaluate the session conservatively at any point in its lifecycle
    #[must_use]
    pub fn evaluate(&self) -> AssessmentReport<'_> {
        let complete = self.lifecycle_complete();
        let mut results = Vec::with_capacity(self.plan.checks().len());
        for check in self.plan.checks() {
            results.push(self.evaluate_check(*check, complete));
        }
        AssessmentReport {
            phase: self.phase,
            results,
            lifecycle_evidence: LifecycleEvidence {
                plan: &self.plan,
                originals: &self.originals,
                cleanup: &self.cleanup,
            },
        }
    }

    fn evaluate_check(&self, check: CheckKind, complete: bool) -> CheckResult {
        let evidence = self.collect_check_evidence(check);
        let mut limitations = self.lifecycle_limitations();
        let (status, defensible_evidence) =
            self.status_for_check(&evidence, complete, &mut limitations);
        CheckResult {
            check,
            status,
            defensible_evidence,
            committed_stimuli: evidence.committed_stimuli,
            planned_stimuli: evidence.planned.len(),
            transitions: evidence.transitions.len(),
            canary_traversals: evidence.canary_traversals,
            evidence_packets: evidence.evidence_packets,
            limitations,
            budget_usage: self.budget_usage(check),
        }
    }

    fn collect_check_evidence(&self, check: CheckKind) -> CheckEvidence {
        let planned: Vec<_> = self
            .plan
            .stimuli()
            .iter()
            .copied()
            .filter(|stimulus| stimulus.check() == check)
            .collect();
        let committed_stimuli = planned
            .iter()
            .filter(|stimulus| self.stimuli.contains_key(&stimulus.id()))
            .count();
        let transitions: Vec<_> = planned
            .iter()
            .filter_map(|stimulus| self.transitions.get(&stimulus.id()).copied())
            .collect();
        let canary_expectations: Vec<_> = self
            .plan
            .canaries()
            .iter()
            .copied()
            .filter(|canary| {
                planned
                    .iter()
                    .any(|stimulus| stimulus.id() == canary.stimulus())
            })
            .collect();
        let canary_traversals = canary_expectations
            .iter()
            .filter(|expectation| self.has_canary(expectation))
            .count();
        let evidence_packets = self.evidence_packets(&planned, &canary_expectations);
        CheckEvidence {
            planned,
            committed_stimuli,
            transitions,
            canary_expectations,
            canary_traversals,
            evidence_packets,
        }
    }

    fn status_for_check(
        &self,
        evidence: &CheckEvidence,
        complete: bool,
        limitations: &mut Vec<String>,
    ) -> (AssessmentStatus, bool) {
        if !complete {
            return (AssessmentStatus::Inconclusive, false);
        }
        if evidence.planned.is_empty() {
            limitations.push(String::from("the selected check has no planned stimulus"));
            return (AssessmentStatus::Inconclusive, false);
        }
        if evidence.planned.iter().any(|stimulus| {
            self.plan
                .commitment(stimulus.sequence())
                .is_none_or(|commitment| {
                    commitment.subject() == CommitmentSubject::UnboundFrameClaim
                })
        }) {
            limitations.push(String::from(
                "one or more planned stimuli lack check-specific semantic binding",
            ));
            return (AssessmentStatus::Inconclusive, false);
        }
        if evidence.canary_expectations.is_empty() {
            limitations.push(String::from(
                "the selected check has no planned authenticated canary",
            ));
            return (AssessmentStatus::Inconclusive, false);
        }
        if evidence.transitions.len() != evidence.planned.len() {
            limitations.push(String::from(
                "one or more planned stimuli lack a neighbor transition receipt",
            ));
            return (AssessmentStatus::Inconclusive, false);
        }
        if self.has_vulnerable_evidence(evidence) {
            return (AssessmentStatus::Vulnerable, true);
        }
        if evidence
            .transitions
            .iter()
            .all(|receipt| receipt.disposition().is_clean())
            && self.canaries_match_expectations(&evidence.canary_expectations)
        {
            return (AssessmentStatus::Protected, true);
        }
        limitations.push(String::from(
            "one or more observations did not establish a clean disposition",
        ));
        (AssessmentStatus::Inconclusive, false)
    }

    fn has_vulnerable_evidence(&self, evidence: &CheckEvidence) -> bool {
        evidence
            .transitions
            .iter()
            .any(|receipt| receipt.disposition().is_vulnerable())
            || evidence.canary_expectations.iter().any(|expectation| {
                expectation.expectation() == PathExpectation::Blocked
                    && self
                        .canaries
                        .get(&CanaryKey::from_canary(&expectation.canary()))
                        .is_some_and(|receipt| receipt.traversal() == CanaryTraversal::Arrived)
            })
    }

    fn canaries_match_expectations(&self, expectations: &[CanaryExpectation]) -> bool {
        expectations.iter().all(|expectation| {
            self.canaries
                .get(&CanaryKey::from_canary(&expectation.canary()))
                .is_some_and(|receipt| match expectation.expectation() {
                    PathExpectation::Blocked => receipt.traversal() == CanaryTraversal::NotObserved,
                    PathExpectation::Forwarded => receipt.traversal() == CanaryTraversal::Arrived,
                })
        })
    }

    fn every_stimulus_has_canary(&self) -> bool {
        self.plan.stimuli().iter().all(|stimulus| {
            self.plan
                .canaries()
                .iter()
                .any(|expectation| expectation.stimulus() == stimulus.id())
        })
    }

    fn has_canary(&self, expectation: &CanaryExpectation) -> bool {
        self.canaries
            .contains_key(&CanaryKey::from_canary(&expectation.canary()))
    }

    fn evidence_packets(
        &self,
        stimuli: &[crate::Stimulus],
        canaries: &[CanaryExpectation],
    ) -> Vec<PacketReference> {
        let mut values = Vec::with_capacity(stimuli.len() + canaries.len());
        for stimulus in stimuli {
            if let Some(receipt) = self.stimuli.get(&stimulus.id()) {
                push_unique_packet(&mut values, receipt.evidence_packet());
            }
        }
        for expectation in canaries {
            if let Some(receipt) = self
                .canaries
                .get(&CanaryKey::from_canary(&expectation.canary()))
            {
                push_unique_packet(&mut values, receipt.evidence_packet());
            }
        }
        values
    }

    fn lifecycle_complete(&self) -> bool {
        self.precheck.is_some_and(PrecheckReceipt::is_clean)
            && self.originals.len() == self.plan.endpoints().len()
            && self
                .originals
                .values()
                .all(|receipt| receipt.evidence_origin().packet().is_some())
            && self.arms.len() == self.plan.endpoints().len()
            && self.stimuli.len() == self.plan.stimuli().len()
            && !self.plan.stimuli().is_empty()
            && self.transitions.len() == self.plan.stimuli().len()
            && self.canaries.len() == self.plan.canaries().len()
            && !self.plan.canaries().is_empty()
            && self.every_stimulus_has_canary()
            && self.cleanup.len() == self.plan.endpoints().len()
            && self
                .cleanup
                .values()
                .all(|receipt| receipt.restored() && receipt.capture_loss() == 0)
            && self
                .transitions
                .values()
                .all(|receipt| clean_window(receipt.window()))
            && self
                .canaries
                .values()
                .all(Self::canary_window_is_sufficient)
    }

    fn lifecycle_limitations(&self) -> Vec<String> {
        let mut limitations = Vec::new();
        if !self.precheck.is_some_and(PrecheckReceipt::is_clean) {
            limitations.push(String::from("precheck was not completed cleanly"));
        }
        if self.originals.len() != self.plan.endpoints().len() {
            limitations.push(String::from("one or more original bindings are missing"));
        }
        if self
            .originals
            .values()
            .any(|receipt| receipt.evidence_origin().packet().is_none())
        {
            limitations.push(String::from(
                "original binding evidence source reference is unavailable",
            ));
        }
        if self.arms.len() != self.plan.endpoints().len() {
            limitations.push(String::from(
                "one or more controlled endpoints were not armed",
            ));
        }
        if self.stimuli.len() != self.plan.stimuli().len() || self.plan.stimuli().is_empty() {
            limitations.push(String::from(
                "committed bounded stimulus receipts are incomplete",
            ));
        }
        if self.transitions.len() != self.plan.stimuli().len() {
            limitations.push(String::from("neighbor transition receipts are incomplete"));
        }
        if self.canaries.len() != self.plan.canaries().len() || self.plan.canaries().is_empty() {
            limitations.push(String::from(
                "authenticated canary traversal receipts are incomplete",
            ));
        }
        if !self.every_stimulus_has_canary() {
            limitations.push(String::from(
                "one or more planned stimuli have no authenticated canary expectation",
            ));
        }
        if self.cleanup.len() != self.plan.endpoints().len() {
            limitations.push(String::from("cleanup or restoration receipts are missing"));
        }
        if self.cleanup.values().any(|receipt| !receipt.restored()) {
            limitations.push(String::from(
                "one or more original bindings were not restored",
            ));
        }
        if self
            .cleanup
            .values()
            .any(|receipt| receipt.capture_loss() != 0)
            || self
                .transitions
                .values()
                .any(|receipt| !clean_window(receipt.window()))
            || self
                .canaries
                .values()
                .any(|receipt| !Self::canary_window_is_sufficient(receipt))
        {
            limitations.push(String::from(
                "capture loss or incomplete observation prevents a clean result",
            ));
        }
        limitations
    }

    fn canary_window_is_sufficient(receipt: &AuthenticatedCanaryReceipt) -> bool {
        match receipt.traversal() {
            CanaryTraversal::Arrived => true,
            CanaryTraversal::NotObserved => receipt
                .window()
                .proves_complete_absence_for(receipt.transmit()),
        }
    }
}

struct CheckEvidence {
    planned: Vec<crate::Stimulus>,
    committed_stimuli: usize,
    transitions: Vec<NeighborTransitionReceipt>,
    canary_expectations: Vec<CanaryExpectation>,
    canary_traversals: usize,
    evidence_packets: Vec<PacketReference>,
}

fn push_unique_packet(values: &mut Vec<PacketReference>, packet: PacketReference) {
    if !values.contains(&packet) {
        values.push(packet);
    }
}
