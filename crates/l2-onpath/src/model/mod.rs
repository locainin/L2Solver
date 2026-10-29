//! Cohesive models for identities, budgets, checks, stimuli, and plans

mod bindings;
mod budget;
mod checks;
mod disposition;
mod limits;
mod plan;
mod stimulus;
mod timebase;

pub use bindings::validate_neighbor_address;
pub use bindings::{
    AddressFamily, ControlledEndpoint, MacAddress, NeighborBinding, ProtocolFamily,
};
pub use budget::{ActivityClass, Budget, RiskClass};
pub use checks::CheckKind;
pub use disposition::NeighborDisposition;
pub use limits::{
    MAX_BYTE_BUDGET, MAX_CANARIES, MAX_CHECKS, MAX_COMMITMENTS, MAX_DURATION_BUDGET_MILLIS,
    MAX_ENDPOINTS, MAX_PACKET_BUDGET, MAX_STIMULI,
};
pub use plan::AssessmentPlan;
pub use stimulus::{CanaryExpectation, PathExpectation, Stimulus, StimulusId};
pub use timebase::BudgetTimebase;
