//! Bounded behavior summaries from captured and imported evidence

mod events;
mod model;
mod network;
mod smb2;
mod visitor;

pub use events::{
    EndpointClock, EndpointEvent, EndpointEventError, EndpointEventKind, EndpointEventReport,
    FileIdentity, MAX_ENDPOINT_EVENT_BYTES, MAX_ENDPOINT_EVENTS, ProcessIdentity,
    SourceEventReference, TimestampComparison, parse_endpoint_events,
};
pub use model::{BehaviorConfig, BehaviorFinding, BehaviorKind, BehaviorReport};
pub use visitor::visit_case;

use crate::evidence::Case;
use std::error::Error;

/// Analyze retained packet facts, canonical findings, and eligible TCP byte runs
///
/// Results describe observed patterns or bounded candidates; they do not assign
/// actor identity, malicious intent, or successful remote operations
/// This adapter retains at most 4,096 findings; [`visit_case`] supports caller-defined budgets
///
/// # Errors
/// Returns an error for invalid mapping receipts, exhausted allocation, or a count overflow
pub fn analyze_case(
    case: &Case,
    config: &BehaviorConfig,
) -> Result<BehaviorReport, Box<dyn Error>> {
    let mut findings = Vec::new();
    let mut omitted_findings = 0_usize;
    let mut limitations = visit_case(case, config, |finding| {
        if findings.len() == model::MAX_BEHAVIOR_FINDINGS {
            omitted_findings = omitted_findings
                .checked_add(1)
                .ok_or("omitted behavior finding count overflow")?;
        } else {
            // Allocate only for a finding that will be retained by the bounded adapter
            findings.try_reserve(1)?;
            findings.push(finding);
        }
        Ok(())
    })?;
    if omitted_findings != 0 {
        limitations
            .push("Some behavior findings were omitted after the bounded report limit".to_owned());
    }
    Ok(BehaviorReport {
        findings,
        complete: case.collection_complete() && omitted_findings == 0,
        omitted_findings,
        limitations,
    })
}
