use super::{Case, FLOW_SELECTION_KIND, FLOW_SELECTION_PREDICATE};
use crate::reconstruction::{RecordRetentionLimit, RecordRetentionStatus};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::HashSet, fmt};

const VERIFICATION_SCOPE: &str = "receipt_internal_consistency_and_source_reference";

/// Optional analyst-selected budgets for one receipt verification
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiptVerificationLimits {
    /// Maximum encoded receipt bytes, with no additional ceiling when absent
    pub max_receipt_bytes: Option<usize>,
    /// Maximum combined entries across all receipt lists
    pub max_list_entries: Option<usize>,
}

/// A structural or semantic failure in a built-in receipt
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptVerificationError {
    /// The selected node does not exist in the validated case
    MissingNode { node: u64 },
    /// The selected node is not a supported built-in receipt
    UnsupportedKind { kind: String },
    /// The receipt node has no retained byte blob
    MissingReceiptBlob,
    /// The retained receipt is not strict JSON matching its versioned schema
    ReceiptJson,
    /// The retained node details do not match the strict built-in schema
    DetailsJson,
    /// The representation or schema version is not supported
    UnsupportedFormat { version: Option<u64> },
    /// An optional caller-selected verification budget was exceeded
    LimitExceeded {
        resource: &'static str,
        maximum: usize,
    },
    /// Temporary verification state could not be allocated
    AllocationFailed { resource: &'static str },
    /// Two retained claims contradict one another
    Contradiction { invariant: &'static str },
}

impl fmt::Display for ReceiptVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNode { node } => write!(formatter, "evidence node {node} does not exist"),
            Self::UnsupportedKind { kind } => {
                write!(
                    formatter,
                    "node kind {kind:?} has no built-in receipt verifier"
                )
            }
            Self::MissingReceiptBlob => {
                formatter.write_str("built-in receipt node has no retained blob")
            }
            Self::ReceiptJson => formatter.write_str("invalid built-in receipt JSON"),
            Self::DetailsJson => formatter.write_str("invalid built-in receipt details"),
            Self::UnsupportedFormat { version } => match version {
                Some(version) => write!(
                    formatter,
                    "unsupported built-in receipt schema version {version}"
                ),
                None => formatter.write_str("unsupported built-in receipt representation"),
            },
            Self::LimitExceeded { resource, maximum } => {
                write!(
                    formatter,
                    "{resource} exceed the selected maximum {maximum}"
                )
            }
            Self::AllocationFailed { resource } => {
                write!(formatter, "could not allocate {resource}")
            }
            Self::Contradiction { invariant } => {
                write!(formatter, "built-in receipt contradicts {invariant}")
            }
        }
    }
}

impl std::error::Error for ReceiptVerificationError {}

/// Verified scalar claims from one version-1 indexed-flow selection receipt
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IndexFlowSelectionVerification {
    pub schema_version: u32,
    pub verified: bool,
    pub case_collection_complete: bool,
    pub node: u64,
    pub kind: String,
    pub receipt_blob: String,
    pub receipt_schema_version: u64,
    pub verification_scope: &'static str,
    pub source_id: String,
    pub requested_flow_count: u64,
    pub flow_count: u64,
    pub duplicate_flow_selections_removed: u64,
    pub selected_records: u64,
    pub retained_input_records: u64,
    pub omitted_records: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFlowSelectionReceipt<'a> {
    #[serde(borrow)]
    requested_flow_ids: &'a RawValue,
    #[serde(borrow)]
    flow_contributions: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowContribution {
    flow_id: i64,
    packet_records: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowSelectionDetails {
    representation: String,
    receipt_schema_version: u64,
    flow_count: u64,
    requested_flow_count: u64,
    duplicate_flow_selections_removed: u64,
    selected_records: u64,
    retained_input_records: u64,
    omitted_records: u64,
    #[serde(default)]
    retention_status: Option<RecordRetentionStatus>,
    #[serde(default)]
    retention_limits: Option<Vec<RecordRetentionLimit>>,
    source_id: String,
    predicate: String,
    #[serde(default, deserialize_with = "deserialize_optional_non_null_i64")]
    flow_id: Option<i64>,
}

pub(super) fn raw_flow_selection_details_are_valid(raw: &RawValue) -> bool {
    serde_json::from_str::<FlowSelectionDetails>(raw.get()).is_ok()
}

fn deserialize_optional_non_null_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    // Missing means absent, while an explicit null is not a valid generated claim
    Option::<i64>::deserialize(deserializer)?
        .map(Some)
        .ok_or_else(|| de::Error::custom("flow_id must not be null"))
}

#[derive(Clone, Copy)]
enum DeferredFailure {
    Limit {
        resource: &'static str,
        maximum: usize,
    },
    Allocation {
        resource: &'static str,
    },
    Contradiction {
        invariant: &'static str,
    },
}

impl DeferredFailure {
    const fn into_error(self) -> ReceiptVerificationError {
        match self {
            Self::Limit { resource, maximum } => {
                ReceiptVerificationError::LimitExceeded { resource, maximum }
            }
            Self::Allocation { resource } => {
                ReceiptVerificationError::AllocationFailed { resource }
            }
            Self::Contradiction { invariant } => {
                ReceiptVerificationError::Contradiction { invariant }
            }
        }
    }
}

struct ReceiptInput<'a> {
    blob_id: &'a str,
    bytes: &'a [u8],
    details: &'a serde_json::Value,
}

struct ReceiptClaims {
    requested_flow_count: u64,
    flow_count: u64,
    duplicate_flow_selections_removed: u64,
    selected_records: u64,
    expected_flow_id: Option<i64>,
}

struct ParseContext {
    maximum_entries: Option<usize>,
    entries: usize,
    failure: Option<DeferredFailure>,
}

impl ParseContext {
    const fn new(maximum_entries: Option<usize>) -> Self {
        Self {
            maximum_entries,
            entries: 0,
            failure: None,
        }
    }

    fn observe_entry(&mut self) -> Result<(), DeferredFailure> {
        let next = self
            .entries
            .checked_add(1)
            .ok_or(DeferredFailure::Allocation {
                resource: "receipt list accounting",
            })?;
        if let Some(maximum) = self.maximum_entries
            && next > maximum
        {
            return Err(DeferredFailure::Limit {
                resource: "receipt list entries",
                maximum,
            });
        }
        self.entries = next;
        Ok(())
    }

    fn reject<E: de::Error>(&mut self, failure: DeferredFailure) -> E {
        self.failure.get_or_insert(failure);
        E::custom("built-in receipt validation failed")
    }

    fn map_json_error(&self) -> ReceiptVerificationError {
        self.failure
            .map_or(ReceiptVerificationError::ReceiptJson, |failure| {
                failure.into_error()
            })
    }
}

struct RequestedFlows {
    count: usize,
    first_seen: Vec<i64>,
    seen: HashSet<i64>,
}

impl RequestedFlows {
    fn new() -> Self {
        Self {
            count: 0,
            first_seen: Vec::new(),
            seen: HashSet::new(),
        }
    }
}

struct RequestedFlowVisitor<'a> {
    context: &'a mut ParseContext,
    flows: &'a mut RequestedFlows,
}

impl<'de> Visitor<'de> for RequestedFlowVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of positive indexed flow identifiers")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(flow_id) = sequence.next_element::<i64>()? {
            if let Err(failure) = self.context.observe_entry() {
                return Err(self.context.reject(failure));
            }
            if flow_id <= 0 {
                return Err(self.context.reject(DeferredFailure::Contradiction {
                    invariant: "requested_flow_ids.positive",
                }));
            }
            self.flows.count = self.flows.count.checked_add(1).ok_or_else(|| {
                self.context.reject(DeferredFailure::Allocation {
                    resource: "requested flow count",
                })
            })?;
            if !self.flows.seen.contains(&flow_id) {
                self.flows.seen.try_reserve(1).map_err(|_| {
                    self.context.reject(DeferredFailure::Allocation {
                        resource: "requested flow membership",
                    })
                })?;
                self.flows.first_seen.try_reserve(1).map_err(|_| {
                    self.context.reject(DeferredFailure::Allocation {
                        resource: "requested flow order",
                    })
                })?;
                self.flows.seen.insert(flow_id);
                self.flows.first_seen.push(flow_id);
            }
        }
        Ok(())
    }
}

struct ContributionSummary {
    count: usize,
    packet_records: u64,
}

struct ContributionVisitor<'a> {
    context: &'a mut ParseContext,
    expected_flows: &'a [i64],
    summary: &'a mut ContributionSummary,
}

impl<'de> Visitor<'de> for ContributionVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of indexed flow contribution objects")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(contribution) = sequence.next_element::<FlowContribution>()? {
            if let Err(failure) = self.context.observe_entry() {
                return Err(self.context.reject(failure));
            }
            if self.expected_flows.get(self.summary.count) != Some(&contribution.flow_id) {
                return Err(self.context.reject(DeferredFailure::Contradiction {
                    invariant: "flow_contributions.first_seen_order",
                }));
            }
            self.summary.packet_records = self
                .summary
                .packet_records
                .checked_add(contribution.packet_records)
                .ok_or_else(|| {
                    self.context.reject(DeferredFailure::Contradiction {
                        invariant: "flow_contributions.packet_records_sum",
                    })
                })?;
            self.summary.count = self.summary.count.checked_add(1).ok_or_else(|| {
                self.context.reject(DeferredFailure::Allocation {
                    resource: "flow contribution count",
                })
            })?;
        }
        Ok(())
    }
}

fn parse_requested_flows(
    raw: &RawValue,
    context: &mut ParseContext,
) -> Result<RequestedFlows, ReceiptVerificationError> {
    let mut flows = RequestedFlows::new();
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let result = deserializer.deserialize_seq(RequestedFlowVisitor {
        context,
        flows: &mut flows,
    });
    if result.is_err() || deserializer.end().is_err() {
        return Err(context.map_json_error());
    }
    if flows.count == 0 {
        return Err(ReceiptVerificationError::Contradiction {
            invariant: "requested_flow_ids.nonempty",
        });
    }
    Ok(flows)
}

fn parse_contributions(
    raw: &RawValue,
    context: &mut ParseContext,
    expected_flows: &[i64],
) -> Result<ContributionSummary, ReceiptVerificationError> {
    let mut summary = ContributionSummary {
        count: 0,
        packet_records: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let result = deserializer.deserialize_seq(ContributionVisitor {
        context,
        expected_flows,
        summary: &mut summary,
    });
    if result.is_err() || deserializer.end().is_err() {
        return Err(context.map_json_error());
    }
    if summary.count != expected_flows.len() {
        return Err(ReceiptVerificationError::Contradiction {
            invariant: "flow_contributions.first_seen_order",
        });
    }
    Ok(summary)
}

/// Verify one version-1 indexed-flow receipt against its retained details and source reference
///
/// This checks internal case consistency, not whether an external index would replay identically
///
/// # Errors
/// Returns an explicit format, resource, allocation, or contradiction error
pub fn verify_index_flow_selection(
    case: &Case,
    node_id: u64,
    limits: ReceiptVerificationLimits,
) -> Result<IndexFlowSelectionVerification, ReceiptVerificationError> {
    let input = select_receipt(case, node_id, limits.max_receipt_bytes)?;
    let details = decode_details(input.details)?;
    let claims = decode_claims(input.bytes, limits.max_list_entries)?;
    verify_claims(case, &details, &claims)?;
    Ok(verification_report(
        case,
        node_id,
        input.blob_id,
        details,
        &claims,
    ))
}

fn select_receipt(
    case: &Case,
    node_id: u64,
    maximum_bytes: Option<usize>,
) -> Result<ReceiptInput<'_>, ReceiptVerificationError> {
    let node = node_id
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| case.nodes().get(index))
        .filter(|node| node.id == node_id)
        .ok_or(ReceiptVerificationError::MissingNode { node: node_id })?;
    if node.kind != FLOW_SELECTION_KIND {
        return Err(ReceiptVerificationError::UnsupportedKind {
            kind: node.kind.clone(),
        });
    }
    if !node.ranges.is_empty() {
        return Err(ReceiptVerificationError::Contradiction {
            invariant: "node.ranges",
        });
    }

    let blob_id = node
        .blob
        .as_deref()
        .ok_or(ReceiptVerificationError::MissingReceiptBlob)?;
    let blob = case
        .blob(blob_id)
        .ok_or(ReceiptVerificationError::MissingReceiptBlob)?;
    if let Some(maximum) = maximum_bytes
        && blob.bytes.len() > maximum
    {
        return Err(ReceiptVerificationError::LimitExceeded {
            resource: "receipt bytes",
            maximum,
        });
    }
    Ok(ReceiptInput {
        blob_id,
        bytes: &blob.bytes,
        details: &node.details,
    })
}

fn decode_details(
    value: &serde_json::Value,
) -> Result<FlowSelectionDetails, ReceiptVerificationError> {
    let details: FlowSelectionDetails =
        serde_json::from_value(value.clone()).map_err(|_| ReceiptVerificationError::DetailsJson)?;
    if details.representation != "json_blob" {
        return Err(ReceiptVerificationError::UnsupportedFormat { version: None });
    }
    if !matches!(details.receipt_schema_version, 1 | 2) {
        return Err(ReceiptVerificationError::UnsupportedFormat {
            version: Some(details.receipt_schema_version),
        });
    }
    Ok(details)
}

fn decode_claims(
    bytes: &[u8],
    maximum_entries: Option<usize>,
) -> Result<ReceiptClaims, ReceiptVerificationError> {
    // Raw values retain duplicate-key detection at both receipt object levels
    let receipt: RawFlowSelectionReceipt<'_> =
        serde_json::from_slice(bytes).map_err(|_| ReceiptVerificationError::ReceiptJson)?;
    let mut context = ParseContext::new(maximum_entries);
    let requested = parse_requested_flows(receipt.requested_flow_ids, &mut context)?;
    let contributions = parse_contributions(
        receipt.flow_contributions,
        &mut context,
        &requested.first_seen,
    )?;
    let requested_count =
        u64::try_from(requested.count).map_err(|_| ReceiptVerificationError::AllocationFailed {
            resource: "requested flow count",
        })?;
    let flow_count = u64::try_from(requested.first_seen.len()).map_err(|_| {
        ReceiptVerificationError::AllocationFailed {
            resource: "flow contribution count",
        }
    })?;
    let duplicates = requested_count - flow_count;
    let expected_flow_id = if requested.count == 1 {
        requested.first_seen.first().copied()
    } else {
        None
    };
    Ok(ReceiptClaims {
        requested_flow_count: requested_count,
        flow_count,
        duplicate_flow_selections_removed: duplicates,
        selected_records: contributions.packet_records,
        expected_flow_id,
    })
}

fn verify_claims(
    case: &Case,
    details: &FlowSelectionDetails,
    claims: &ReceiptClaims,
) -> Result<(), ReceiptVerificationError> {
    verify_detail(
        details.requested_flow_count == claims.requested_flow_count,
        "details.requested_flow_count",
    )?;
    verify_detail(
        details.flow_count == claims.flow_count,
        "details.flow_count",
    )?;
    verify_detail(
        details.duplicate_flow_selections_removed == claims.duplicate_flow_selections_removed,
        "details.duplicate_flow_selections_removed",
    )?;
    verify_detail(
        details.selected_records == claims.selected_records,
        "details.selected_records",
    )?;
    verify_detail(
        details.retained_input_records <= details.selected_records,
        "details.retained_input_records",
    )?;
    verify_detail(
        details
            .selected_records
            .checked_sub(details.retained_input_records)
            == Some(details.omitted_records),
        "details.omitted_records",
    )?;
    verify_retention_details(details)?;
    verify_detail(
        details.predicate == FLOW_SELECTION_PREDICATE,
        "details.predicate",
    )?;
    verify_detail(
        case.source(&details.source_id).is_some(),
        "details.source_id",
    )?;
    verify_detail(
        details.flow_id == claims.expected_flow_id,
        "details.flow_id",
    )
}

fn verify_retention_details(
    details: &FlowSelectionDetails,
) -> Result<(), ReceiptVerificationError> {
    match details.receipt_schema_version {
        1 => verify_detail(
            details.retention_status.is_none() && details.retention_limits.is_none(),
            "details.retention_status",
        ),
        2 => {
            let status = details
                .retention_status
                .ok_or(ReceiptVerificationError::DetailsJson)?;
            let limits = details
                .retention_limits
                .as_deref()
                .ok_or(ReceiptVerificationError::DetailsJson)?;
            let expected_status = if details.omitted_records == 0 {
                RecordRetentionStatus::Complete
            } else {
                RecordRetentionStatus::ResourceTruncatedPrefix
            };
            verify_detail(status == expected_status, "details.retention_status")?;
            verify_detail(
                (details.omitted_records == 0) == limits.is_empty(),
                "details.retention_limits",
            )?;
            let mut seen = 0_u8;
            for limit in limits {
                let mask = match limit {
                    RecordRetentionLimit::Frames => 0b001,
                    RecordRetentionLimit::Bytes => 0b010,
                    RecordRetentionLimit::Units => 0b100,
                };
                verify_detail(seen & mask == 0, "details.retention_limits")?;
                seen |= mask;
            }
            Ok(())
        }
        version => Err(ReceiptVerificationError::UnsupportedFormat {
            version: Some(version),
        }),
    }
}

fn verification_report(
    case: &Case,
    node_id: u64,
    blob_id: &str,
    details: FlowSelectionDetails,
    claims: &ReceiptClaims,
) -> IndexFlowSelectionVerification {
    IndexFlowSelectionVerification {
        schema_version: 1,
        verified: true,
        case_collection_complete: case.collection_complete(),
        node: node_id,
        kind: FLOW_SELECTION_KIND.to_owned(),
        receipt_blob: blob_id.to_owned(),
        receipt_schema_version: details.receipt_schema_version,
        verification_scope: VERIFICATION_SCOPE,
        source_id: details.source_id,
        requested_flow_count: claims.requested_flow_count,
        flow_count: claims.flow_count,
        duplicate_flow_selections_removed: claims.duplicate_flow_selections_removed,
        selected_records: details.selected_records,
        retained_input_records: details.retained_input_records,
        omitted_records: details.omitted_records,
    }
}

const fn verify_detail(
    condition: bool,
    invariant: &'static str,
) -> Result<(), ReceiptVerificationError> {
    if condition {
        Ok(())
    } else {
        Err(ReceiptVerificationError::Contradiction { invariant })
    }
}
