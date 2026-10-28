use super::{RelationalCohortKey, SampleCohort, StoredSample};
use crate::workbench::recovery_executor::{
    Executor, RecoveryPlan, execute_executor, normal_policy, test_support,
};
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{
        CounterByteOrder, CounterWidth, OperandRef, Operation, Recipe, SeedCounterOrder, run,
    },
    evidence::Case,
    protocol::{
        Direction, MessageContext, RelationalCounterReset, RelationalParserScope,
        RelationalRecordSample, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformStatus, infer_relational_transform_candidates,
    },
};
use serde_json::{Value, json};
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Cohort = (RelationalCohortKey, Vec<StoredSample>);

struct AdversarialFixture {
    case: Case,
    key: RelationalCohortKey,
    stored: Vec<StoredSample>,
    expected: Vec<Vec<u8>>,
}

#[test]
fn all_normal_cohorts_finish_before_incremental_search() -> TestResult {
    let mut case = Case::new();
    let cohorts = (1..=2_u64)
        .map(|number| simple_cohort(&mut case, number))
        .collect::<TestResult<Vec<_>>>()?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.relational_transform_plan.limits.max_candidates = 4;
    policy
        .relational_transform_plan
        .limits
        .max_locator_candidates = 16;
    policy.relational_transform_plan.limits.max_work_bytes = 8_192;
    let mut extra = policy.relational_transform_plan.clone();
    extra.limits.max_candidates = 8;
    extra.limits.max_marker_bytes = 4;
    policy.relational_incremental_plan = Some(extra);
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    for (key, samples) in cohorts {
        add_cohort_views(&mut executor, key, &samples, &samples);
    }
    execute_executor(&mut executor)?;
    assert_report_order(&reports(executor.case)?)
}

#[test]
fn stopped_incremental_metadata_does_not_recreate_history_during_normal_search() -> TestResult {
    let mut case = Case::new();
    let (key, samples) = simple_cohort(&mut case, 1)?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.relational_transform_plan.limits.max_candidates = 4;
    policy
        .relational_transform_plan
        .limits
        .max_locator_candidates = 16;
    policy.relational_transform_plan.limits.max_work_bytes = 8_192;
    policy.relational_incremental_plan = Some(policy.relational_transform_plan.clone());
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    add_cohort_views(&mut executor, key, &samples, &samples);
    // Metadata exhaustion drops the extra views before normal recovery begins
    executor.relational_samples.incremental_cohorts.clear();
    executor.relational_samples.incremental_metadata_stop =
        Some("incremental_metadata_limit".into());
    assert!(executor.flush_relational_cohorts(super::RelationalLane::Normal)?);
    let context = executor
        .relational_discoveries
        .values()
        .find_map(|contexts| contexts.first())
        .ok_or("normal discovery was not scheduled")?
        .clone();

    execute_executor(&mut executor)?;

    assert_eq!(reports(executor.case)?.len(), 1);
    assert!(
        executor
            .relational_samples
            .histories
            .published_history(&context, 256 * 1024)
            .is_none(),
        "a stopped extra lane must not retain unused replay histories"
    );
    Ok(())
}

#[test]
fn wider_cohort_keeps_normal_artifacts_and_reports_its_heldout_contradiction() -> TestResult {
    let AdversarialFixture {
        mut case,
        key,
        stored,
        expected,
    } = adversarial_fixture()?;
    let (normal, wider) = adversarial_plans();
    let narrow_samples = stored.get(..4).ok_or("missing normal samples")?;
    assert_wider_search_rejects_normal_rule(&case, &stored, &normal, &wider)?;

    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.relational_transform_plan = normal;
    policy.relational_incremental_plan = Some(wider);
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    add_cohort_views(&mut executor, key, narrow_samples, &stored);
    execute_executor(&mut executor)?;

    assert_normal_outputs(executor.case, narrow_samples, &expected);
    let incremental = reports(executor.case)?
        .into_iter()
        .find(|report| report.get("search_lane").and_then(Value::as_str) == Some("incremental"))
        .ok_or("incremental search did not retain its report")?;
    assert!(
        incremental
            .get("retained_rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| rules
                .iter()
                .any(|rule| rule.get("status").and_then(Value::as_str)
                    == Some("contradicted_by_heldout_session"))),
        "the additional contradictory session must remain visible"
    );
    Ok(())
}

#[test]
fn incremental_search_reuses_rules_only_after_their_outputs_are_published() -> TestResult {
    let AdversarialFixture {
        mut case,
        key,
        stored,
        expected,
    } = adversarial_fixture()?;
    let samples = stored.get(..4).ok_or("missing normal samples")?;
    let (mut normal, _) = adversarial_plans();
    normal.limits.max_candidates = 256;
    normal.limits.max_total_bytes = 256 * 1024;
    let mut extra = normal.clone();
    extra.limits.max_candidates = 512;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.relational_transform_plan = normal;
    policy.relational_incremental_plan = Some(extra);
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    add_cohort_views(&mut executor, key, samples, samples);
    execute_executor(&mut executor)?;
    assert_normal_outputs(executor.case, samples, &expected);
    let incremental = reports(executor.case)?
        .into_iter()
        .find(|report| report.get("search_lane").and_then(Value::as_str) == Some("incremental"))
        .ok_or("incremental search did not retain its report")?;
    assert!(
        incremental
            .get("history_reused_published")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0),
        "the incremental lane should reuse at least one committed exact rule"
    );
    assert_eq!(
        incremental.get("history_complete_before_publication"),
        Some(&Value::Bool(true))
    );
    assert!(incremental.get("history_complete").is_none());
    Ok(())
}

fn simple_cohort(case: &mut Case, number: u64) -> TestResult<Cohort> {
    let key = cohort_key(format!("source-{number}"));
    let mut samples = Vec::new();
    for session in 1..=2_u64 {
        let bytes = [u8::try_from(number)?, u8::try_from(session)?, 0xa5, 0x5a];
        let node_id = case.add_bytes_node("frame", &bytes, Vec::new(), json!({}))?;
        samples.push(stored_sample(&key, node_id, session));
    }
    Ok((key, samples))
}

fn add_cohort_views(
    executor: &mut Executor<'_>,
    key: RelationalCohortKey,
    normal: &[StoredSample],
    extra: &[StoredSample],
) {
    let mut normal_cohort = SampleCohort::new(key.clone());
    normal_cohort.samples = normal.to_vec();
    let mut incremental = SampleCohort::new(key);
    incremental.samples = extra.to_vec();
    executor.relational_samples.cohorts.push(normal_cohort);
    executor
        .relational_samples
        .incremental_cohorts
        .push(incremental);
}

fn reports(case: &Case) -> TestResult<Vec<Value>> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == "recovery_relational_transform_report")
        .map(|node| {
            let blob = node
                .blob
                .as_deref()
                .and_then(|id| case.blob(id))
                .ok_or("missing report blob")?;
            Ok::<_, Box<dyn Error>>(serde_json::from_slice::<Value>(&blob.bytes)?)
        })
        .collect()
}

fn assert_report_order(reports: &[Value]) -> TestResult {
    assert_eq!(
        reports.len(),
        4,
        "both views of both cohorts must be reported"
    );
    for (index, report) in reports.iter().enumerate() {
        let expected_limit = if index < 2 { 4 } else { 8 };
        assert_eq!(
            report
                .pointer("/configured_limits/max_candidates")
                .and_then(Value::as_u64),
            Some(expected_limit)
        );
        assert_eq!(
            report.get("search_lane").and_then(Value::as_str),
            (index >= 2).then_some("incremental")
        );
        let examined = report
            .get("candidate_count_examined")
            .and_then(Value::as_u64)
            .ok_or("missing candidate count")?;
        assert!(examined <= expected_limit);
        let work = report
            .get("work_bytes")
            .and_then(Value::as_u64)
            .ok_or("missing work count")?;
        assert!(
            report
                .get("prefix_probe_work_bytes")
                .and_then(Value::as_u64)
                .is_some_and(|prefix| prefix <= work)
        );
    }
    Ok(())
}

fn adversarial_fixture() -> TestResult<AdversarialFixture> {
    let mut case = Case::new();
    let key = cohort_key("adversarial-source".to_owned());
    let mut samples = Vec::new();
    let mut expected = Vec::new();
    for session in 1_u8..=5 {
        let seed = [
            session.wrapping_mul(17).wrapping_add(3),
            session.wrapping_mul(29).wrapping_add(11),
        ];
        let mut plaintext = vec![0x04, 60];
        plaintext.extend((0_u8..60).map(|index| session.wrapping_add(index.wrapping_mul(13))));
        let mut ciphertext = run(
            &plaintext,
            &Recipe {
                steps: vec![Operation::Sha256CounterXor {
                    seed: OperandRef::from(seed.to_vec()),
                    initial_counter: 0,
                    counter_width: CounterWidth::OneByte,
                    counter_byte_order: CounterByteOrder::BigEndian,
                    seed_order: SeedCounterOrder::SeedThenCounter,
                }],
                constraints: Vec::new(),
            },
        )?
        .output;
        if session == 5 {
            *ciphertext.first_mut().ok_or("missing ciphertext")? ^= 0xff;
        }
        let [first, second] = seed;
        let mut wire = vec![0x31, first, second, 0x82];
        wire.extend(ciphertext);
        let node_id = case.add_bytes_node("frame", &wire, Vec::new(), json!({}))?;
        samples.push(stored_sample(&key, node_id, u64::from(session)));
        expected.push(plaintext);
    }
    Ok(AdversarialFixture {
        case,
        key,
        stored: samples,
        expected,
    })
}

fn cohort_key(source_id: String) -> RelationalCohortKey {
    RelationalCohortKey {
        source_id,
        scope_json: "scope".to_owned(),
        endpoints_json: "{}".to_owned(),
        direction: Direction::FirstToSecond,
        framing_rule_json: "framed".to_owned(),
        schema_json: "{}".to_owned(),
    }
}

fn stored_sample(key: &RelationalCohortKey, node_id: u64, session: u64) -> StoredSample {
    StoredSample {
        node_id,
        context: MessageContext {
            source: key.source_id.clone(),
            scope: key.scope_json.clone(),
            session,
            direction: key.direction,
        },
        session_order: session,
        direction_node_id: session,
        episode_node_id: session,
        stream_offset: 0,
    }
}

fn adversarial_plans() -> (RelationalTransformPlan, RelationalTransformPlan) {
    let limits = RelationalTransformLimits {
        max_cohorts: 4,
        max_sessions: 4,
        max_records_per_session: 2,
        max_record_bytes: 128,
        max_total_bytes: 1024,
        max_marker_bytes: 1,
        max_marker_offset: 3,
        max_seed_bytes: 2,
        max_locator_offset: 4,
        max_locator_candidates: 32,
        max_candidates: 2_048,
        max_retained_candidates: 256,
        max_work_bytes: 1024 * 1024,
    };
    let normal = RelationalTransformPlan {
        limits,
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![SeedCounterOrder::SeedThenCounter],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::Continuous],
    };
    let mut wider = normal.clone();
    wider.limits.max_sessions = 5;
    wider.limits.max_marker_bytes = 2;
    wider.limits.max_locator_candidates = 128;
    wider.limits.max_candidates = 20_000;
    (normal, wider)
}

fn assert_wider_search_rejects_normal_rule(
    case: &Case,
    stored: &[StoredSample],
    normal: &RelationalTransformPlan,
    wider: &RelationalTransformPlan,
) -> TestResult {
    let samples = stored
        .iter()
        .map(|sample| {
            let node = case.node(sample.node_id).ok_or("missing input node")?;
            let blob = node
                .blob
                .as_deref()
                .and_then(|id| case.blob(id))
                .ok_or("missing input blob")?;
            Ok::<_, Box<dyn Error>>(RelationalRecordSample {
                sample: sample.node_id,
                context: sample.context.clone(),
                session_order: sample.session_order,
                bytes: &blob.bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let narrow_report = infer_relational_transform_candidates(
        samples.get(..4).ok_or("missing normal samples")?,
        normal,
    )?;
    let accepted = narrow_report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
                && candidate.rule.seed_locator.value_offset == 1
                && candidate.rule.seed_locator.value_length == Some(2)
                && candidate.rule.payload_locator.value_offset == 4
        })
        .ok_or("normal search did not recover the expected rule")?;
    let wide_report = infer_relational_transform_candidates(&samples, wider)?;
    let widened = wide_report
        .candidates
        .iter()
        .find(|candidate| candidate.rule == accepted.rule)
        .ok_or("wider search omitted the normal rule before its heldout check")?;
    assert_eq!(
        widened.status,
        RelationalTransformStatus::ContradictedByHeldoutSession
    );
    assert!(wide_report.candidates_examined <= wider.limits.max_candidates);
    assert!(wide_report.work_bytes <= wider.limits.max_work_bytes);
    Ok(())
}

fn assert_normal_outputs(case: &Case, stored: &[StoredSample], expected: &[Vec<u8>]) {
    for (sample, plaintext) in stored.iter().zip(expected) {
        let output = case.nodes().iter().find(|node| {
            node.kind == "relational_transform_output"
                && node
                    .blob
                    .as_deref()
                    .and_then(|id| case.blob(id))
                    .is_some_and(|blob| &blob.bytes == plaintext)
                && case.edges().iter().any(|edge| {
                    edge.from == node.id
                        && edge.to == sample.node_id
                        && edge.relation == "derived_from"
                })
        });
        assert!(
            output.is_some(),
            "normal artifact and its source must survive the wider contradiction"
        );
    }
}
