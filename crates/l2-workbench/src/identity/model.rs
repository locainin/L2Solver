use crate::{evidence::SourceRange, journal::Event};
use serde::{Deserialize, Serialize};

/// A supplied binding applies only to its exact source, scope and record interval
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBinding {
    pub id: String,
    pub source: String,
    pub scope: String,
    pub subject: String,
    pub identity: String,
    pub first_packet: u64,
    pub last_packet: Option<u64>,
    pub evidence: Vec<SourceRange>,
    pub origin_claim: String,
}

/// An affine clock mapping retains supplied anchors, rate, uncertainty and validity
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockCalibration {
    pub id: String,
    pub from_clock: String,
    pub to_clock: String,
    pub anchor_from: u64,
    pub anchor_to: u64,
    pub numerator: u64,
    pub denominator: u64,
    pub uncertainty_ticks: u64,
    pub valid_from: u64,
    pub valid_through: Option<u64>,
    pub evidence: Vec<SourceRange>,
    pub origin_claim: String,
}

/// Comparisons name exact event identities and an explicitly selected clock
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonRequest {
    pub left_event: String,
    pub right_event: String,
    pub clock: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationPlan {
    #[serde(default)]
    pub bindings: Vec<IdentityBinding>,
    #[serde(default)]
    pub calibrations: Vec<ClockCalibration>,
    #[serde(default)]
    pub comparisons: Vec<ComparisonRequest>,
}

/// Resource choices bound retained events and comparison work, not capture size
#[derive(Clone, Copy, Debug)]
pub struct CorrelationOptions {
    pub max_events: usize,
    pub max_work_items: u64,
}
impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            max_events: 100_000,
            max_work_items: 10_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Unique,
    Ambiguous,
    Unmapped,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityCandidate {
    pub identity: String,
    pub binding_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantResolution {
    pub observed: String,
    pub status: ResolutionStatus,
    pub candidates: Vec<IdentityCandidate>,
}

/// Bounds are target-clock ticks rounded outward, including supplied uncertainty
#[derive(Clone, Debug, Serialize)]
pub struct TimeInterval {
    pub clock: String,
    #[serde(serialize_with = "serialize_tick")]
    pub earliest: i128,
    #[serde(serialize_with = "serialize_tick")]
    pub latest: i128,
    pub calibration_id: Option<String>,
}

// Decimal text preserves exact signed ticks in readers without 128-bit JSON integers
fn serialize_tick<S: serde::Serializer>(ticks: &i128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(ticks)
}
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedEvent {
    pub identity: String,
    pub event: Event,
    pub actor: Option<ParticipantResolution>,
    pub peer: Option<ParticipantResolution>,
    pub times: Vec<TimeInterval>,
}

/// Equal supplied identity labels link observations without establishing ownership
#[derive(Clone, Debug, Serialize)]
pub struct IdentityGroup {
    pub identity: String,
    pub event_indices: Vec<usize>,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Actor,
    Peer,
}
/// Co-occurring network and Ethernet claims remain separate from identity bindings
#[derive(Clone, Debug, Serialize)]
pub struct HeaderAssociation {
    pub event_index: usize,
    pub role: ParticipantRole,
    pub address: String,
    pub mac: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRelation {
    Before,
    After,
    Overlapping,
    Unmapped,
    AmbiguousCalibration,
}
#[derive(Clone, Debug, Serialize)]
pub struct TimeComparison {
    pub request: ComparisonRequest,
    pub relation: TimeRelation,
    pub left_calibrations: Vec<String>,
    pub right_calibrations: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct CorrelationReport {
    pub plan_sha256: String,
    pub bindings: Vec<IdentityBinding>,
    pub calibrations: Vec<ClockCalibration>,
    pub events: Vec<ResolvedEvent>,
    pub groups: Vec<IdentityGroup>,
    pub header_associations: Vec<HeaderAssociation>,
    pub comparisons: Vec<TimeComparison>,
    pub omitted_events: usize,
    pub work_items: u64,
    pub complete: bool,
    pub limitations: Vec<&'static str>,
}
