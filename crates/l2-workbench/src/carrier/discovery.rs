//! Bounded bit-plane discovery over explicit, source-mapped byte samples

mod case;
mod engine;
mod model;
mod plan;
pub mod results;

pub use case::{
    MappedNode, discover_case, discover_case_to_store, discover_case_with_view, mapped_node,
    mapped_node_with_view, replay_case_candidate,
};
pub use engine::discover;
pub use model::{
    BitMappingReceipt, CaseHypothesis, CompetingOutput, ConstraintKind, ConstraintSummary,
    DiscoveryCandidate, DiscoveryError, DiscoveryIdentity, DiscoveryLimit, DiscoveryMapping,
    DiscoveryPlan, DiscoveryReport, DiscoverySample, DiscoverySampleReceipt, DiscoveryView,
    LengthHypothesis, Partition, PartitionSummary, PrintableRun, ResetMode, SampleOrder,
    SourceBitMapping,
};
pub use results::{
    DEFAULT_MAX_RESULT_PAGE_BYTES, DEFAULT_MAX_RESULT_RECORD_BYTES, DiscoveryResultStore,
    ReplayReceipt, ResultPage, ResultReadOptions, StoreOptions, StoredDiscoverySummary,
    discover_samples_to_store, replay_candidate,
};
