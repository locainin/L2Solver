mod error;
mod model;
mod search;

pub use error::RecordDiscoveryError;
pub use model::{
    RecordDiscoveryLimits, RecordDiscoveryPartition, RecordDiscoveryValidationBasis,
    RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace, RecordSchemaFalsification,
    RecordSchemaHypothesis,
};
pub use search::discover_record_schemas;
pub(super) use search::{
    discover_record_schemas_from_candidates_observed,
    discover_record_schemas_from_candidates_with_work,
};
