//! Explicit bounded parsing and assembly for repeated binary records

mod assemble;
mod discovery;
mod error;
mod header;
mod model;
mod parse;
mod proposal;

pub use assemble::{assemble_record_groups, assemble_record_groups_from_inputs};
pub use discovery::{
    RecordDiscoveryError, RecordDiscoveryLimits, RecordDiscoveryPartition,
    RecordDiscoveryValidationBasis, RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace,
    RecordSchemaFalsification, RecordSchemaHypothesis, discover_record_schemas,
};
pub use header::{HeaderParseTemplate, RecordInput};
pub use model::{
    ByteField, DEFAULT_MAX_IDENTIFIER_BYTES, DEFAULT_MAX_RECORD_GROUPS,
    DEFAULT_MAX_RECORD_INPUT_BYTES, DEFAULT_MAX_RECORD_ISSUE_EXAMPLES,
    DEFAULT_MAX_RECORD_OUTPUT_BYTES, DEFAULT_MAX_RECORD_REPORT_BYTES, DEFAULT_MAX_RECORDS,
    IntegerField, ParsedRecord, RecordAssemblyInput, RecordAssemblyOutcome, RecordAssemblyPart,
    RecordAssemblyReport, RecordCount, RecordError, RecordGroupOutcome, RecordGroupReceipt,
    RecordLengthMeaning, RecordLimits, RecordParseReport, RecordSchema,
};
pub use parse::{parse_records, parse_records_with_limits};
pub use proposal::{
    RecordBoundaryCue, RecordSchemaAnalysisReport, RecordSchemaMultiStrategyAnalysisReport,
    RecordSchemaProposalLimits, RecordSchemaProposalReport, RecordSchemaProposalValidationBasis,
    RecordSchemaStrategy, analyze_record_schemas, analyze_record_schemas_with_repeated_boundaries,
    analyze_record_schemas_with_repeated_boundaries_and_offsets,
    analyze_record_schemas_with_repeated_boundaries_and_offsets_observed,
    propose_record_schema_space,
};
