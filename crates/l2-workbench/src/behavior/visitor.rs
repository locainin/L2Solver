use super::{BehaviorConfig, BehaviorFinding, model::default_limitations, network, smb2};
use crate::evidence::Case;
use std::error::Error;

pub(super) struct FindingVisitor<'a> {
    emit: &'a mut dyn FnMut(BehaviorFinding) -> Result<(), Box<dyn Error>>,
    limitations: Vec<String>,
}

/// Emit findings from one bounded case without retaining an intermediate finding list
///
/// The consumer applies its own retention budgets after any category or page filtering
/// Returned limitations describe analysis scope; source collection status remains available
/// through `Case::collection_complete`
///
/// # Errors
/// Returns an error for invalid retained mapping receipts or a failed consumer
pub fn visit_case(
    case: &Case,
    config: &BehaviorConfig,
    mut emit: impl FnMut(BehaviorFinding) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut visitor = FindingVisitor {
        emit: &mut emit,
        limitations: default_limitations(),
    };
    for limitation in case.limitations() {
        visitor.add_limitation(limitation);
    }
    // Both analyzers share the same consumer so later evidence has no separate retention cap
    network::analyze(case, config, &mut visitor)?;
    smb2::analyze(case, &mut visitor)?;
    Ok(visitor.limitations)
}

impl FindingVisitor<'_> {
    pub(super) fn push(&mut self, finding: BehaviorFinding) -> Result<(), Box<dyn Error>> {
        (self.emit)(finding)
    }

    pub(super) fn add_limitation(&mut self, text: &str) {
        // Retain each explanation once even when several findings share the same constraint
        if !self.limitations.iter().any(|prior| prior == text) {
            self.limitations.push(text.to_owned());
        }
    }
}
