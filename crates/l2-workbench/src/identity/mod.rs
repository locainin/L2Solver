//! Explicit identity and clock evidence connects observations without guessing ownership

mod clocks;
mod engine;
mod model;
mod observations;
mod validation;
pub use engine::{correlate, event_identity};
pub use model::{
    ClockCalibration, ComparisonRequest, CorrelationOptions, CorrelationPlan, CorrelationReport,
    HeaderAssociation, IdentityBinding, IdentityCandidate, IdentityGroup, ParticipantResolution,
    ParticipantRole, ResolutionStatus, ResolvedEvent, TimeComparison, TimeInterval, TimeRelation,
};
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct CorrelationError(String);
impl fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl Error for CorrelationError {}
pub type Result<T> = std::result::Result<T, CorrelationError>;
fn invalid(message: impl Into<String>) -> CorrelationError {
    CorrelationError(message.into())
}

struct Work {
    maximum: u64,
    used: u64,
}
impl Work {
    fn charge(&mut self) -> Result<()> {
        if self.used == self.maximum {
            return Err(invalid("correlation work budget exhausted"));
        }
        self.used += 1;
        Ok(())
    }
}
