use std::error::Error;

use super::{
    RecordCohortKey, RecordCohortOrigin, RecordDiscoveryPlan, RecordFrameInput, apply_input_limits,
    collect_input_plan_excluding,
};
use l2_workbench::evidence::Case;
use l2_workbench::protocol::{ByteRange, Direction, RecordSchemaProposalLimits};
use serde_json::json;

fn cohort_key() -> RecordCohortKey {
    RecordCohortKey {
        source_id: "source-a".to_owned(),
        scope_json: "{\"scope\":1}".to_owned(),
        endpoints_json: "[]".to_owned(),
        direction: Direction::FirstToSecond,
        origin: RecordCohortOrigin::TcpMaterialized,
        framing_rule_json: "{\"kind\":\"length_prefix\"}".to_owned(),
    }
}

fn frame(session_node_id: u64, frame_index: usize, byte_length: usize) -> RecordFrameInput {
    let node_id = session_node_id * 100 + u64::try_from(frame_index).unwrap_or(u64::MAX) + 1;
    RecordFrameInput {
        node_id,
        blob_id: format!("blob-{node_id}"),
        receipt_node_id: session_node_id + 10_000,
        session_node_id,
        direction_node_id: session_node_id + 20_000,
        episode_node_id: session_node_id,
        session_id: session_node_id,
        frame_index,
        stream_range: ByteRange {
            start: frame_index * byte_length,
            end: (frame_index + 1) * byte_length,
        },
        stream_offset: 0,
        byte_length,
    }
}

fn limits(max_messages: usize, max_input_bytes: usize) -> RecordSchemaProposalLimits {
    let mut limits = RecordSchemaProposalLimits::default();
    limits.discovery.max_messages = max_messages;
    limits.discovery.record_limits.max_input_bytes = max_input_bytes;
    limits
}

#[test]
fn learning_budget_keeps_balanced_session_prefixes_and_full_application_inputs()
-> Result<(), Box<dyn Error>> {
    let key = cohort_key();
    let mut plan = RecordDiscoveryPlan::default();
    plan.cohorts.insert(
        key.clone(),
        (0..3)
            .flat_map(|session| {
                let session_node_id = 10 + session;
                (0..3).map(move |frame_index| frame(session_node_id, frame_index, 8))
            })
            .collect(),
    );

    let plan = apply_input_limits(plan, limits(4, 128))?;
    let learning = plan.cohorts.get(&key).ok_or("learning cohort is missing")?;
    let mut retained_by_session = std::collections::BTreeMap::new();
    for input in learning {
        *retained_by_session
            .entry(input.session_node_id)
            .or_insert(0) += 1;
    }
    let retained_order = learning
        .iter()
        .map(|input| (input.session_node_id, input.frame_index))
        .collect::<Vec<_>>();

    assert_eq!(learning.len(), 4);
    assert_eq!(retained_order, [(10, 0), (10, 1), (11, 0), (12, 0)]);
    assert_eq!(
        retained_by_session.values().copied().collect::<Vec<_>>(),
        [2, 1, 1]
    );
    assert_eq!(plan.cohort_omitted_frames.get(&key), Some(&5));
    assert_eq!(
        plan.application_cohorts.get(&key).map(Vec::len),
        Some(9),
        "schema application retains every validated frame in every session"
    );
    Ok(())
}

#[test]
fn byte_limited_learning_does_not_drop_other_session_prefixes() -> Result<(), Box<dyn Error>> {
    let key = cohort_key();
    let mut plan = RecordDiscoveryPlan::default();
    plan.cohorts.insert(
        key.clone(),
        [
            frame(10, 0, 5),
            frame(10, 1, 5),
            frame(20, 0, 30),
            frame(20, 1, 5),
            frame(30, 0, 5),
            frame(30, 1, 5),
        ]
        .into(),
    );

    let plan = apply_input_limits(plan, limits(4, 10))?;
    let learning = plan.cohorts.get(&key).ok_or("learning cohort is missing")?;
    let retained_session_ids = learning
        .iter()
        .map(|input| input.session_node_id)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(learning.len(), 2);
    assert_eq!(retained_session_ids, [10, 30].into());
    assert_eq!(plan.cohort_omitted_frames.get(&key), Some(&4));
    assert_eq!(
        plan.application_cohorts.get(&key).map(Vec::len),
        Some(6),
        "a byte-limited learning prefix must not remove frames from session application"
    );
    let omissions = plan
        .omissions
        .get(&Some("source-a".to_owned()))
        .ok_or("source scoped omissions are missing")?;
    assert_eq!(omissions.total, 4);
    assert!(
        omissions
            .reason_counts
            .contains_key("learning_prefix_aggregate_byte_limit")
    );
    Ok(())
}

#[test]
fn record_collection_skips_registered_derived_frames_and_keeps_native_omissions()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let registered_derived = case.add_bytes_node(
        "custom_protocol_frame",
        b"decoded frame without literal source ranges",
        Vec::new(),
        json!({"fixture":"registered derived frame"}),
    )?;
    let native_without_source = case.add_bytes_node(
        "custom_protocol_frame",
        b"native frame without source context",
        Vec::new(),
        json!({"fixture":"native frame without source"}),
    )?;

    let plan = collect_input_plan_excluding(&case, |node_id| node_id == registered_derived)?;
    let native_examples = plan
        .omissions
        .values()
        .flat_map(|omissions| omissions.examples.iter())
        .filter(|example| {
            example.get("reason").and_then(serde_json::Value::as_str) == Some("missing_source")
        })
        .filter_map(|example| {
            example
                .get("frame_node_id")
                .and_then(serde_json::Value::as_u64)
        })
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(native_examples, [native_without_source].into());
    assert!(!native_examples.contains(&registered_derived));
    Ok(())
}

#[test]
fn eligibility_omissions_exclude_learning_limits_but_keep_real_input_failures()
-> Result<(), Box<dyn Error>> {
    use super::RecordDiscoveryInputOmissions;
    let mut omissions = RecordDiscoveryInputOmissions::default();
    omissions.record_many(
        "missing_materialization_receipt",
        2,
        Some("source-a"),
        &[1, 2],
    )?;
    omissions.record_many(
        "learning_prefix_message_count_limit",
        7,
        Some("source-a"),
        &[3],
    )?;
    let eligibility = omissions.eligibility_only();
    assert_eq!(eligibility.total, 2);
    assert_eq!(
        eligibility
            .reason_counts
            .get("missing_materialization_receipt"),
        Some(&2)
    );
    assert!(
        !eligibility
            .reason_counts
            .contains_key("learning_prefix_message_count_limit")
    );
    assert!(eligibility.examples.iter().all(|example| example.get("reason") == Some(&json!("missing_materialization_receipt"))));
    Ok(())
}
