//! Evidence-gated cross-session transformation rules with frozen held-out checks

mod model;
mod search;

pub use model::{
    RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCandidateEvaluation,
    RelationalCandidateEvaluationReport, RelationalCandidateOutputs, RelationalCoordinateBasis,
    RelationalCounterReset, RelationalEvaluationError, RelationalFalsification, RelationalFit,
    RelationalFitStatus, RelationalLengthField, RelationalOperationTemplate,
    RelationalOutputMapping, RelationalParserScope, RelationalRecordSample,
    RelationalRetainedEvaluation, RelationalSearchLimit, RelationalSessionCheck,
    RelationalSessionId, RelationalSha256CounterXor, RelationalTransformCandidate,
    RelationalTransformError, RelationalTransformEvaluationContext,
    RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
    RelationalTransformReport, RelationalTransformRule, RelationalTransformStatus,
};
pub use search::{
    RelationalCursorError, RelationalReplayHistory, RelationalRestoreBudget,
    RelationalSearchCursor, RelationalSearchSession, RelationalSearchStep,
    apply_relational_transform_rule, infer_relational_transform_candidates,
    infer_relational_transform_candidates_with_evaluator,
    infer_relational_transform_candidates_with_evaluator_and_history,
    infer_relational_transform_candidates_with_job,
};
