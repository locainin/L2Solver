//! Bounded candidate framing and explicit request/response field correlation

mod bootstrap;
mod boundaries;
mod correlation;
mod correlation_candidates;
mod error;
mod family;
mod framing;
mod model;
pub mod observation;
mod reconstructed_framing;
mod records;
mod relational;
pub(crate) mod report_size;
mod sampling;
mod stream;

pub use bootstrap::{
    FramingBootstrapExecution, FramingBootstrapExecutionPlan, FramingBootstrapReport,
    FramingBootstrapRunReport, FramingValidationBasis, bootstrap_framing_with_execution_plan,
    bootstrap_framing_with_limits,
};
pub use boundaries::{
    FrameBoundary, FrameBoundaryIter, extract_boundaries, extract_boundaries_with_limits,
    frame_boundaries, infer_run_boundaries, infer_run_boundaries_with_limits,
};
pub use correlation::correlate_fields;
pub use correlation::correlate_fields_with_limits;
pub use correlation_candidates::infer_correlation_candidates;
pub use family::{
    DEFAULT_MAX_FAMILY_RANGES, DEFAULT_MAX_FAMILY_REPORT_BYTES, DEFAULT_MAX_FAMILY_SAMPLES,
    DEFAULT_MAX_FAMILY_SELECTORS, DEFAULT_MAX_FAMILY_VALUES, MessageFamily, MessageFamilyError,
    MessageFamilyLimits, MessageFamilyReport, MessageFamilySelector, UnassignedFamilyObservation,
    UnassignedFamilyReason, discover_message_families,
};
pub use framing::{infer_framing, infer_framing_with_limits};
pub use model::{
    BoundaryAliasGroup, BoundaryCandidate, BoundaryExtractionReport, BoundaryStatus, ByteOrder,
    ByteRange, ByteRunSample, CorrelationAlias, CorrelationCandidate, CorrelationCandidateFit,
    CorrelationCandidateReport, CorrelationCounterexample, CorrelationReport, CorrelationSplit,
    CorrelationStatus, Direction, FieldTransition, FitSummary, FramingCandidate,
    FramingCounterexample, FramingKind, FramingReport, HoldoutBasis, LengthMeaning, MessageContext,
    MessageRole, MessageSample, ProtocolError, ProtocolLimits,
};
pub use reconstructed_framing::{
    ReconstructedFramingInputOmission, ReconstructedFramingInputOmissionReason,
    ReconstructedFramingInputOmissions, ReconstructedFramingReport, ReconstructedFramingRun,
    ReconstructedFramingStream, ReconstructedSourceMapping,
    discover_reconstructed_framing_with_limits,
};
pub use records::{
    BoundRecordAssemblyPlan, ByteField, DEFAULT_MAX_IDENTIFIER_BYTES, DEFAULT_MAX_RECORD_GROUPS,
    DEFAULT_MAX_RECORD_INPUT_BYTES, DEFAULT_MAX_RECORD_ISSUE_EXAMPLES,
    DEFAULT_MAX_RECORD_OUTPUT_BYTES, DEFAULT_MAX_RECORD_REPORT_BYTES, DEFAULT_MAX_RECORDS,
    HeaderParseTemplate, IntegerField, ParsedRecord, RecordAssemblyBindStats,
    RecordAssemblyHeaderModel, RecordAssemblyInput, RecordAssemblyMaterializedLayout,
    RecordAssemblyModelStatus, RecordAssemblyOutcome, RecordAssemblyPart, RecordAssemblyPlan,
    RecordAssemblyPlanDescription, RecordAssemblyPlanStats, RecordAssemblyReport,
    RecordBoundaryCue, RecordCount, RecordDiscoveryError, RecordDiscoveryLimits,
    RecordDiscoveryPartition, RecordDiscoveryValidationBasis, RecordError, RecordGroupOutcome,
    RecordGroupReceipt, RecordInput, RecordLengthMeaning, RecordLimits, RecordParseReport,
    RecordSchema, RecordSchemaAnalysisReport, RecordSchemaDiscoveryReport,
    RecordSchemaDiscoverySpace, RecordSchemaFalsification, RecordSchemaHypothesis,
    RecordSchemaMultiStrategyAnalysisReport, RecordSchemaProposalLimits,
    RecordSchemaProposalReport, RecordSchemaProposalValidationBasis, RecordSchemaStrategy,
    RecordWorkBudget, analyze_record_inputs_with_repeated_boundaries_and_offsets,
    analyze_record_inputs_with_repeated_boundaries_and_offsets_observed, analyze_record_schemas,
    analyze_record_schemas_with_repeated_boundaries,
    analyze_record_schemas_with_repeated_boundaries_and_offsets,
    analyze_record_schemas_with_repeated_boundaries_and_offsets_observed, assemble_record_groups,
    assemble_record_groups_from_inputs, discover_record_schemas, parse_records,
    parse_records_with_limits, propose_record_schema_space,
};
pub use relational::{
    RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCandidateEvaluation,
    RelationalCandidateEvaluationReport, RelationalCandidateOutputs, RelationalCoordinateBasis,
    RelationalCounterReset, RelationalEvaluationError, RelationalFalsification, RelationalFit,
    RelationalFitStatus, RelationalLengthField, RelationalOperationTemplate,
    RelationalOutputMapping, RelationalParserScope, RelationalRecordSample,
    RelationalReplayHistory, RelationalRetainedEvaluation, RelationalSearchLimit,
    RelationalSessionCheck, RelationalSessionId, RelationalSha256CounterXor,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
    RelationalTransformReport, RelationalTransformRule, RelationalTransformStatus,
    apply_relational_transform_rule, infer_relational_transform_candidates,
    infer_relational_transform_candidates_with_evaluator,
    infer_relational_transform_candidates_with_evaluator_and_history,
    infer_relational_transform_candidates_with_job,
};
pub(crate) use stream::validate_stream_framings;
pub use stream::{
    MessageOrigin, MessageRecord, StreamExtractionReport, StreamMessageParser, StreamTransition,
    StreamTransitionState,
};

/// Default maximum number of message samples retained for one analysis
pub const MAX_PROTOCOL_SAMPLES: usize = 4_096;
/// Default maximum bytes in one caller-selected message, not a wire protocol limit
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Default aggregate message bytes used by framing and correlation
pub const MAX_PROTOCOL_BYTES: usize = 8 * 1024 * 1024;
/// Default operational scan budget for one reconstructed TCP run, not a wire limit
pub const MAX_PROTOCOL_RUN_BYTES: usize = 1024 * 1024;
/// Default maximum candidates derived from discovery messages
pub const MAX_FRAMING_CANDIDATES: usize = 1_024;
/// Default number of boundary examples retained for each candidate hypothesis
pub const MAX_PROTOCOL_RETAINED_FRAMES: usize = 256;
/// Default logical report budget for candidate records, boundary ranges, and alias references
pub const MAX_PROTOCOL_REPORT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum example counterexamples retained for one candidate
pub const MAX_COUNTEREXAMPLES: usize = 16;
/// Maximum request sample IDs retained for one ambiguous response
pub const MAX_MATCH_CANDIDATES: usize = 16;
/// Highest zero-based offset scanned by default for inferred length fields
pub const MAX_PROTOCOL_PREFIX_OFFSET: usize = 15;
