//! Describe reusable record plans without retaining decoded payloads

pub(in crate::workbench::recovery_executor::relational) mod accepted;
pub(in crate::workbench::recovery_executor::relational) mod replay;
mod restore;
pub(in crate::workbench::recovery_executor::relational) mod structural;

pub(in crate::workbench::recovery_executor::relational) use restore::SchemaCacheRestoreContext;

// Recheck a retained positive assessment using the same parser and artifact validator
pub(in crate::workbench::recovery_executor::relational) fn verify_assessment(
    rule: &l2_workbench::protocol::RelationalTransformRule,
    accepted: &super::AcceptedRecordSchema,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), crate::workbench::recovery_executor::RecoveryExecutionError> {
    let frames = replay::replay(rule, context)?;
    accepted::verify(
        accepted,
        &frames.frames,
        context.schema_limits.discovery.record_limits,
        context,
    )
}

pub(in crate::workbench::recovery_executor::relational) fn verify_structural_assessment(
    rule: &l2_workbench::protocol::RelationalTransformRule,
    evidence: &structural::StructuralEvidence,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), crate::workbench::recovery_executor::RecoveryExecutionError> {
    let frames = replay::replay(rule, context)?;
    structural::verify(evidence, &frames.frames, context)
}

use super::{
    AcceptedRecordSchema, GateStatus, MAX_CACHED_SCHEMA_PLANS, SchemaAlternative, SchemaGateReport,
    SchemaOffsetScope, SchemaPlan, SchemaPlanCache,
    key::{SchemaHeaderKey, SchemaLayoutKey},
    operational,
    screen::SchemaAlternativeEvaluation,
};
use crate::workbench::recovery_executor::{
    RecoveryExecutionError,
    checkpoint::{self as executor_checkpoint, CheckpointUnavailable},
};
use l2_workbench::protocol::{
    RecordError, RecordLimits, RecordSchemaProposalLimits, RelationalTransformRule,
};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use serde_json::Value;
use std::cell::Cell;

// Earlier gate snapshots do not carry the structural witness needed for replay
const VERSION: u32 = 3;

// The small fixed index avoids cloning rules or allocating while preparing the writer
struct Producers<'a> {
    rules: [Option<&'a RelationalTransformRule>; MAX_CACHED_SCHEMA_PLANS],
    len: usize,
}

impl<'a> Producers<'a> {
    fn from_cache(cache: &'a SchemaPlanCache) -> Result<Self, RecoveryExecutionError> {
        let mut producers = Self {
            rules: [None; MAX_CACHED_SCHEMA_PLANS],
            len: 0,
        };
        for rule in cache
            .plans
            .values()
            .map(|plan| plan.producer_rule.as_deref())
            .chain(
                cache
                    .header_plans
                    .values()
                    .map(|plan| plan.producer_rule.as_deref()),
            )
        {
            let rule = rule
                .ok_or_else(|| super::invalid_policy("cached schema plan has no producing rule"))?;
            if producers.index(rule).is_none() {
                let slot = producers
                    .rules
                    .get_mut(producers.len)
                    .ok_or_else(|| super::invalid_policy("too many cached schema producers"))?;
                *slot = Some(rule);
                producers.len += 1;
            }
        }
        Ok(producers)
    }

    fn index(&self, rule: &RelationalTransformRule) -> Option<usize> {
        self.rules.iter().position(|saved| *saved == Some(rule))
    }
}

impl Serialize for Producers<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.len))?;
        for rule in self.rules.iter().flatten() {
            sequence.serialize_element(rule)?;
        }
        sequence.end()
    }
}

struct CacheRef<'a> {
    cache: &'a SchemaPlanCache,
    producers: Producers<'a>,
    limits: RecordLimits,
    maximum: usize,
    nested_limit_exceeded: Cell<bool>,
}

impl Serialize for CacheRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let producers = ProducersRef(&self.producers.rules);
        let mut result = serializer.serialize_struct("SchemaCache", 4)?;
        result.serialize_field("version", &VERSION)?;
        result.serialize_field("producers", &self.producers)?;
        result.serialize_field(
            "plans",
            &PlansRef {
                cache: self.cache,
                producers,
            },
        )?;
        result.serialize_field(
            "headers",
            &HeadersRef {
                cache: self.cache,
                producers,
                limits: self.limits,
                maximum: self.maximum,
                nested_limit_exceeded: &self.nested_limit_exceeded,
            },
        )?;
        result.end()
    }
}

struct PlansRef<'a> {
    cache: &'a SchemaPlanCache,
    producers: ProducersRef<'a>,
}

#[derive(Clone, Copy)]
struct ProducersRef<'a>(&'a [Option<&'a RelationalTransformRule>; MAX_CACHED_SCHEMA_PLANS]);

impl ProducersRef<'_> {
    fn index(self, rule: &RelationalTransformRule) -> Option<usize> {
        self.0.iter().position(|saved| *saved == Some(rule))
    }
}

impl Serialize for PlansRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.cache.plans.len()))?;
        for (key, plan) in &self.cache.plans {
            let producer = plan
                .producer_rule
                .as_deref()
                .and_then(|rule| self.producers.index(rule))
                .ok_or_else(|| serde::ser::Error::custom("schema producer is missing"))?;
            sequence.serialize_element(&PlanRef::new(key, producer, plan))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct PlanRef<'a> {
    key: &'a SchemaLayoutKey,
    producer: usize,
    plan: PlanBodyRef<'a>,
}

impl<'a> PlanRef<'a> {
    const fn new(key: &'a SchemaLayoutKey, producer: usize, plan: &'a SchemaPlan) -> Self {
        Self {
            key,
            producer,
            plan: PlanBodyRef(plan),
        }
    }
}

struct PlanBodyRef<'a>(&'a SchemaPlan);

impl Serialize for PlanBodyRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Body<'a> {
            alternatives: AlternativesRef<'a>,
            observation_work_bytes: usize,
            details: &'a Value,
            work_limited: bool,
            has_unassigned_family_messages: bool,
            family_search_complete: bool,
            assessment_scope: SchemaOffsetScope,
        }
        let plan = self.0;
        Body {
            alternatives: AlternativesRef(&plan.alternatives),
            observation_work_bytes: plan.observation_work_bytes,
            details: &plan.details,
            work_limited: plan.work_limited,
            has_unassigned_family_messages: plan.has_unassigned_family_messages,
            family_search_complete: plan.family_search_complete,
            assessment_scope: plan.assessment_scope,
        }
        .serialize(serializer)
    }
}

struct AlternativesRef<'a>(&'a [SchemaAlternative]);

impl Serialize for AlternativesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for alternative in self.0 {
            let observed = alternative
                .observed
                .as_ref()
                .map(Observed::capture)
                .transpose()
                .map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&AlternativeRef {
                label: &alternative.label,
                frame_indices: alternative.frame_indices.as_deref(),
                discovery_report: alternative.discovery_report.as_ref(),
                limits: alternative.limits,
                discovery_work_bytes: alternative.discovery_work_bytes,
                learning_message_count: alternative.learning_message_count,
                heldout_message_count: alternative.heldout_message_count,
                omitted_learning_messages: alternative.omitted_learning_messages,
                learning_session_count: alternative.learning_session_count,
                proposal_search_exhaustive: alternative.proposal_search_exhaustive,
                status: alternative.status,
                observed,
                details: &alternative.details,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct AlternativeRef<'a> {
    label: &'a str,
    frame_indices: Option<&'a [usize]>,
    discovery_report: Option<&'a SchemaGateReport>,
    limits: RecordSchemaProposalLimits,
    discovery_work_bytes: usize,
    learning_message_count: usize,
    heldout_message_count: usize,
    omitted_learning_messages: usize,
    learning_session_count: usize,
    proposal_search_exhaustive: bool,
    status: GateStatus,
    observed: Option<Observed<&'a AcceptedRecordSchema, &'a structural::StructuralWitness>>,
    details: &'a Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de>, W: Deserialize<'de>"))]
struct Observed<T, W> {
    exact_artifact_matches: usize,
    parser_omissions: usize,
    schemas_checked: usize,
    underdetermined_schemas: usize,
    variable_length_schemas: usize,
    coherent_sequence_schemas: usize,
    sequence_conflict_schemas: usize,
    surviving_schemas: usize,
    work_bytes: usize,
    strict_survivors_seen: usize,
    exact_artifact_survivor_ordinal: Option<usize>,
    accepted_schema: Option<T>,
    #[serde(default)]
    structural_witness: Option<W>,
    work_limited: bool,
    survives: bool,
    pending: bool,
    header_models_omitted: usize,
}

impl<'a> Observed<&'a AcceptedRecordSchema, &'a structural::StructuralWitness> {
    const fn capture(observed: &'a SchemaAlternativeEvaluation) -> Result<Self, &'static str> {
        if !observed.header_models.is_empty() || observed.header_model_bytes != 0 {
            return Err("uncompiled schema state cannot be checkpointed");
        }
        if observed.survives
            && observed.exact_artifact_matches == 0
            && observed.structural_witness.is_none()
        {
            return Err("structural schema evidence cannot be checkpointed without its witness");
        }
        Ok(Self {
            exact_artifact_matches: observed.exact_artifact_matches,
            parser_omissions: observed.parser_omissions,
            schemas_checked: observed.schemas_checked,
            underdetermined_schemas: observed.underdetermined_schemas,
            variable_length_schemas: observed.variable_length_schemas,
            coherent_sequence_schemas: observed.coherent_sequence_schemas,
            sequence_conflict_schemas: observed.sequence_conflict_schemas,
            surviving_schemas: observed.surviving_schemas,
            work_bytes: observed.work_bytes,
            strict_survivors_seen: observed.strict_survivors_seen,
            exact_artifact_survivor_ordinal: observed.exact_artifact_survivor_ordinal,
            accepted_schema: observed.accepted_schema.as_ref(),
            structural_witness: observed.structural_witness.as_ref(),
            work_limited: observed.work_limited,
            survives: observed.survives,
            pending: observed.pending,
            header_models_omitted: observed.header_models_omitted,
        })
    }
}

struct HeadersRef<'a> {
    cache: &'a SchemaPlanCache,
    producers: ProducersRef<'a>,
    limits: RecordLimits,
    maximum: usize,
    nested_limit_exceeded: &'a Cell<bool>,
}

impl Serialize for HeadersRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct HeaderRef<'a, T> {
            key: &'a SchemaHeaderKey,
            producer: usize,
            description: T,
            omitted_models: usize,
        }
        let mut sequence = serializer.serialize_seq(Some(self.cache.header_plans.len()))?;
        for (key, plan) in &self.cache.header_plans {
            let producer = plan
                .producer_rule
                .as_deref()
                .and_then(|rule| self.producers.index(rule))
                .ok_or_else(|| serde::ser::Error::custom("header producer is missing"))?;
            let description = plan
                .assembly_plan
                .checkpoint_description(self.limits, self.maximum)
                .map_err(|error| {
                    if matches!(error, RecordError::ReportTooLarge { .. }) {
                        self.nested_limit_exceeded.set(true);
                    }
                    serde::ser::Error::custom(error)
                })?;
            sequence.serialize_element(&HeaderRef {
                key,
                producer,
                description,
                omitted_models: plan.omitted_models,
            })?;
        }
        sequence.end()
    }
}

impl SchemaPlanCache {
    pub(in crate::workbench::recovery_executor::relational) fn checkpoint_description(
        &self,
        limits: RecordLimits,
        maximum: usize,
    ) -> Result<impl Serialize + '_, RecoveryExecutionError> {
        let producers = Producers::from_cache(self)?;
        // Both passes borrow the same immutable producer index and compiled plans
        let view = CacheRef {
            cache: self,
            producers,
            limits,
            maximum,
            nested_limit_exceeded: Cell::new(false),
        };
        let measured = executor_checkpoint::measure(&view, maximum);
        if view.nested_limit_exceeded.get() {
            return Err(executor_checkpoint::unavailable(
                CheckpointUnavailable::SizeLimit,
            ));
        }
        measured.map_err(|error| operational("record gate checkpoint encoding failed", error))?;
        Ok(view)
    }
}
