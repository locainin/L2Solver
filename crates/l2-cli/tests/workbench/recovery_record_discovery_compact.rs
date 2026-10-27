use super::{
    TestResult, add_materialized_session, capture, execute, normal_policy, record, recovery_plan,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    protocol::FramingKind,
    recovery::{RecoveryCandidate, RecoveryInput, RecoveryTask},
};
use serde_json::{Value, json};

fn fixture() -> TestResult<(Case, u64, u64)> {
    let mut case = Case::new();
    let source = capture(&mut case, "compact-frame")?;
    let message = record(b"\x19\x82\xd1", 4, b"alpha");
    let session = add_materialized_session(
        &mut case,
        &source,
        "compact-scope",
        10,
        0,
        &[message],
        &FramingKind::FixedSize { bytes: 14 },
    )?;
    Ok((
        case,
        *session
            .frame_nodes
            .first()
            .ok_or("fixture frame is missing")?,
        *session
            .receipt_nodes
            .first()
            .ok_or("fixture receipt is missing")?,
    ))
}

fn edit_case(case: &Case, edit: impl FnOnce(&mut Value) -> TestResult<()>) -> TestResult<Case> {
    let mut wire: Value = serde_json::from_slice(&case.to_json()?)?;
    edit(&mut wire)?;
    Ok(Case::from_json(&serde_json::to_vec(&wire)?)?)
}

fn node_mut(wire: &mut Value, id: u64) -> TestResult<&mut Value> {
    Ok(wire
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .find(|node| node.get("id").and_then(Value::as_u64) == Some(id))
        })
        .ok_or("fixture node is missing")?)
}

fn details_mut(wire: &mut Value, id: u64) -> TestResult<&mut serde_json::Map<String, Value>> {
    Ok(node_mut(wire, id)?
        .get_mut("details")
        .and_then(Value::as_object_mut)
        .ok_or("fixture details are missing")?)
}

fn retained_frame_count(case: &Case) -> TestResult<usize> {
    let mut copy = case.try_clone()?;
    let policy = normal_policy(&copy)?;
    let outcome = execute(&mut copy, &recovery_plan(), &policy)?;
    Ok(outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .flat_map(RecoveryCandidate::inputs)
        .flat_map(RecoveryInput::origin_node_ids)
        .count())
}

#[test]
fn compact_frame_resolves_its_frozen_rule_from_one_receipt_edge() -> TestResult<()> {
    let (case, frame, receipt) = fixture()?;
    let details = &case.node(frame).ok_or("missing frame")?.details;
    assert_eq!(details.get("framing_schema_version"), Some(&json!(2)));
    assert!(details.get("framing_rule").is_none());
    assert!(details.get("selection_basis").is_none());
    assert!(case.edges().iter().any(|edge| {
        edge.from == receipt && edge.to == frame && edge.relation == "materialized"
    }));
    assert_eq!(retained_frame_count(&case)?, 1);
    Ok(())
}

#[test]
fn compact_frame_rejects_a_missing_or_contradictory_receipt_reference() -> TestResult<()> {
    let (case, frame, receipt) = fixture()?;
    let without_link = edit_case(&case, |wire| {
        wire.get_mut("edges")
            .and_then(Value::as_array_mut)
            .ok_or("fixture edges are missing")?
            .retain(|edge| {
                !(edge.get("from").and_then(Value::as_u64) == Some(receipt)
                    && edge.get("to").and_then(Value::as_u64) == Some(frame)
                    && edge.get("relation").and_then(Value::as_str) == Some("materialized"))
            });
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&without_link)?, 0);

    let contradictory = edit_case(&case, |wire| {
        details_mut(wire, frame)?.insert(
            "framing_rule".to_owned(),
            json!({"kind":"fixed_size","bytes":7}),
        );
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&contradictory)?, 0);

    let changed_receipt = edit_case(&case, |wire| {
        details_mut(wire, receipt)?.insert(
            "framing_rule".to_owned(),
            json!({"kind":"fixed_size","bytes":7}),
        );
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&changed_receipt)?, 0);

    let changed_basis = edit_case(&case, |wire| {
        details_mut(wire, receipt)?.insert(
            "selection_basis".to_owned(),
            json!({"kind":"discovered","report_node":99}),
        );
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&changed_basis)?, 0);

    let conflicting_range = edit_case(&case, |wire| {
        details_mut(wire, frame)?.insert("stream_range".to_owned(), json!({"start":0,"end":7}));
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&conflicting_range)?, 0);

    let mut ambiguous = case.try_clone()?;
    let other = ambiguous.add_node("unrelated", None, Vec::new(), json!({}))?;
    ambiguous.add_edge(Edge {
        from: other,
        to: frame,
        relation: "materialized".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "A competing receipt reference".to_owned(),
    })?;
    assert_eq!(retained_frame_count(&ambiguous)?, 0);
    Ok(())
}

#[test]
fn legacy_inline_frames_still_resolve_against_their_original_receipts() -> TestResult<()> {
    let (case, frame, receipt) = fixture()?;
    let receipt_node = case.node(receipt).ok_or("missing receipt")?;
    let old_blob = receipt_node.blob.as_deref().ok_or("missing receipt blob")?;
    let blob = case.blob(old_blob).ok_or("receipt blob not found")?;
    let mut content: Value = serde_json::from_slice(&blob.bytes)?;
    content
        .as_object_mut()
        .ok_or("receipt content is not an object")?
        .insert("schema_version".to_owned(), json!(1));
    let content = serde_json::to_vec(&content)?;
    let new_blob = format!("sha256:{}", l2_workbench::sha256(&content));
    let old_blob = old_blob.to_owned();
    let rule = receipt_node
        .details
        .get("framing_rule")
        .ok_or("receipt rule is missing")?
        .clone();
    let basis = receipt_node
        .details
        .get("selection_basis")
        .ok_or("receipt basis is missing")?
        .clone();

    let legacy = edit_case(&case, |wire| {
        let details = details_mut(wire, frame)?;
        if let Some(start) = details.remove("stream_start") {
            let end = details.remove("stream_end").ok_or("frame end is missing")?;
            details.insert("stream_range".to_owned(), json!({"start":start,"end":end}));
        }
        details.remove("framing_schema_version");
        details.insert("framing_rule".to_owned(), rule);
        details.insert("selection_basis".to_owned(), basis);
        details_mut(wire, receipt)?.insert("receipt_schema_version".to_owned(), json!(1));
        node_mut(wire, receipt)?
            .as_object_mut()
            .ok_or("receipt node is not an object")?
            .insert("blob".to_owned(), json!(new_blob));
        let retained = wire
            .get_mut("blobs")
            .and_then(Value::as_array_mut)
            .ok_or("fixture blobs are missing")?
            .iter_mut()
            .find(|blob| blob.get("id").and_then(Value::as_str) == Some(old_blob.as_str()))
            .and_then(Value::as_object_mut)
            .ok_or("fixture receipt blob is missing")?;
        retained.insert("id".to_owned(), json!(new_blob));
        retained.insert("bytes_base64".to_owned(), json!(STANDARD.encode(&content)));
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&legacy)?, 1);
    let contradictory = edit_case(&legacy, |wire| {
        details_mut(wire, frame)?.insert("stream_start".to_owned(), json!(1));
        details_mut(wire, frame)?.insert("stream_end".to_owned(), json!(7));
        Ok(())
    })?;
    assert_eq!(retained_frame_count(&contradictory)?, 0);
    Ok(())
}
