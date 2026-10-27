//! Bounded source-backed byte facts and partial protocol constraints
//!
//! This layer tests candidate length fields but does not infer identifier, sequence,
//! counter, timestamp, or semantic offset roles

mod analyze;
mod budget;
mod error;
mod length;
mod limits;
mod model;
mod provenance;
mod regions;
mod validation;

#[cfg(test)]
#[path = "../../../tests/protocol/observation/analyze_region_only.rs"]
mod region_only_tests;

pub use analyze::observe;
pub(super) use analyze::observe_regions;
pub use error::ObservationError;
pub use model::{
    ByteObservation, ConstraintOutcome, IntegerInterpretation, ObservationCohort,
    ObservationCoverage, ObservationInput, ObservationLimits, ObservationOrigin, ObservationPlan,
    ObservationProvenance, ObservationReport, PartialConstraint, RegionCoverage, RegionObservation,
    RegionValue, SampleRange,
};
