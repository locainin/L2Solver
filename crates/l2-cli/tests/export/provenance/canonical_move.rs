use std::error::Error;

use l2_workbench::{evidence::Case, job::MemoryBudget};
use serde_json::{Value, json};

use super::super::artifact_collection::{AddOutcome, ArtifactCollection, ArtifactLimits};
use super::{
    AdmittedArtifactProvenance, ArtifactPublication, ArtifactSelection, ArtifactSourceContext,
    ArtifactSourceProjection, artifact_provenance, canonical_origin,
};

type TestResult = Result<(), Box<dyn Error>>;

fn context() -> ArtifactSourceContext {
    ArtifactSourceContext {
        flow: Some(json!({"id": 7})),
        supporting_flows: vec![json!({"id": 7})],
        cohort_scope: None,
        case_id: Some("case-one".to_owned()),
        case_scope: json!({"kind": "flow"}),
    }
}

#[test]
fn canonical_origin_keeps_owned_stable_payloads_without_copying_them() -> TestResult {
    let node = Some(json!({"payload": "node".repeat(64)}));
    let selection = Some(json!({"payload": "selection".repeat(64)}));
    let candidates = vec![json!({"payload": "signature".repeat(64)})];
    let node_address = node
        .as_ref()
        .and_then(|value| value.get("payload"))
        .and_then(Value::as_str)
        .ok_or("node payload missing")?
        .as_ptr();
    let selection_address = selection
        .as_ref()
        .and_then(|value| value.get("payload"))
        .and_then(Value::as_str)
        .ok_or("selection payload missing")?
        .as_ptr();
    let candidates_address = candidates.as_ptr();
    let projection = ArtifactSourceProjection {
        source_ranges: Vec::new(),
        local_case_identity: None,
        local_case_scope: None,
    };
    let origin = canonical_origin(
        "native",
        &context(),
        &projection,
        None,
        None,
        (node, selection, candidates),
    );
    assert!(std::ptr::eq(
        origin
            .pointer("/node/payload")
            .and_then(Value::as_str)
            .ok_or("canonical node missing")?
            .as_ptr(),
        node_address
    ));
    assert!(std::ptr::eq(
        origin
            .pointer("/selection/payload")
            .and_then(Value::as_str)
            .ok_or("canonical selection missing")?
            .as_ptr(),
        selection_address
    ));
    assert!(std::ptr::eq(
        origin
            .get("signature_candidates")
            .and_then(Value::as_array)
            .ok_or("canonical candidates missing")?
            .as_ptr(),
        candidates_address
    ));
    Ok(())
}

fn retained_origin(
    case: &Case,
    node_id: u64,
    signature_id: u64,
    selected_name: &str,
    selection_id: u64,
    budget: &MemoryBudget,
) -> Result<AdmittedArtifactProvenance, Box<dyn Error>> {
    let node = case.node(node_id).ok_or("node missing")?;
    let signature = case.node(signature_id).ok_or("signature missing")?;
    artifact_provenance(
        "recovered_artifact",
        &context(),
        Some(node),
        Some("desc".to_owned()),
        Some(ArtifactSelection {
            details: json!({
                "id": selection_id,
                "selected_file_name": selected_name,
                "input_node": node_id,
                "note": "keep"
            }),
            source_ranges: Vec::new(),
        }),
        std::iter::once(signature),
        ArtifactPublication {
            case,
            memory: Some(budget),
        },
    )
}

#[test]
fn canonical_bytes_and_same_origin_dedup_stay_exact() -> TestResult {
    let mut case = Case::new();
    let node_id = case.add_bytes_node(
        "ftp_data_candidate",
        b"payload",
        Vec::new(),
        json!({"label": "raw"}),
    )?;
    let signature_id = case.add_node(
        "file_signature_match",
        None,
        Vec::new(),
        json!({"input_node": node_id, "marker": "match"}),
    )?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let first = retained_origin(&case, node_id, signature_id, "first.bin", 1, &budget)?;
    let expected = concat!(
        r#"{"category":"recovered_artifact","cohort_scope":null,"description":"desc","flow":{"id":7},"#,
        r#""local_case_identity":{"case_id":"case-one","node_id":1},"local_case_scope":{"kind":"flow"},"#,
        r#""node":{"blob":"sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5","details":{"label":"raw"},"kind":"ftp_data_candidate","ranges":[]},"#,
        r#""selection":{"input_node":{"blob":"sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5","kind":"ftp_data_candidate","ranges":[]},"note":"keep"},"#,
        r#""signature_candidates":[{"blob":null,"details":{"input_node":{"blob":"sha256:239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5","kind":"ftp_data_candidate","ranges":[]},"marker":"match"},"kind":"file_signature_match","ranges":[]}],"#,
        r#""source_ranges":null,"supporting_flows":[{"id":7}]}"#,
    );
    assert_eq!(serde_json::to_string(&first.canonical_origin)?, expected);
    let second = retained_origin(&case, node_id, signature_id, "second.bin", 99, &budget)?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    assert_eq!(
        artifacts.add_bytes(b"payload", "first.bin", &first, Some(&budget))?,
        AddOutcome::Stored
    );
    assert_eq!(
        artifacts.add_bytes(b"payload", "second.bin", &second, Some(&budget))?,
        AddOutcome::SameOrigin
    );
    assert_eq!(artifacts.coverage().references_retained, 1);
    assert_eq!(artifacts.coverage().same_origin_references_suppressed, 1);
    drop(first);
    drop(second);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
