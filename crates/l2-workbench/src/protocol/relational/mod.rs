//! Evidence-gated cross-session transformation rules with frozen held-out checks

mod model;
mod search;

pub use model::{
    RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCounterReset,
    RelationalFalsification, RelationalFit, RelationalFitStatus, RelationalLengthField,
    RelationalOperationTemplate, RelationalParserScope, RelationalRecordSample,
    RelationalSearchLimit, RelationalSessionCheck, RelationalSessionId, RelationalSha256CounterXor,
    RelationalTransformCandidate, RelationalTransformError, RelationalTransformLimits,
    RelationalTransformPlan, RelationalTransformReport, RelationalTransformRule,
    RelationalTransformStatus,
};
pub use search::{
    apply_relational_transform_rule, infer_relational_transform_candidates,
    infer_relational_transform_candidates_with_job,
};
