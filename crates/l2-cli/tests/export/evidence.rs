use super::{
    ArtifactCollection, ArtifactLimits, ArtifactProvenance, ArtifactSourceContext, EvidenceSidecar,
    artifact_collection::AddOutcome, collect_case_artifacts_with_context,
};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, SourceRange};
use serde_json::{Value, json};
use std::{error::Error, fs};

#[test]
fn shared_artifact_keeps_resolvable_origins_from_distinct_cases() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar =
        EvidenceSidecar::new(temporary.path(), ArtifactLimits::default().evidence_bytes)?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let mut expected = Vec::new();

    for flow_id in [4, 9] {
        let case = case_with_receipt(b"shared object bytes")?;
        let record = sidecar.record_case(&case, &json!({"kind": "flow", "flow_id": flow_id}))?;
        assert!(record.retained);
        expected.push((record.case_id.clone(), 1_u64));
        assert!(matches!(
            artifacts.add_bytes(
                b"shared object bytes",
                "shared.bin",
                &artifact_provenance(Some(record.case_id.as_str()), Some(1), Some(2), None),
            )?,
            AddOutcome::Stored | AddOutcome::Duplicate
        ));
    }

    let mut artifacts_json = Vec::new();
    artifacts.write_manifest_artifacts(&mut artifacts_json)?;
    let manifest: Value =
        serde_json::from_slice(&format!("[{}]", String::from_utf8(artifacts_json)?).into_bytes())?;
    let origins = artifact_origins(&manifest)?;
    assert_eq!(origins.len(), 2);

    let records = read_sidecar(&temporary.path().join("evidence.jsonl"))?;
    for (case_id, node_id) in expected {
        let origin = origins
            .iter()
            .find(|origin| origin.get("case_id").and_then(Value::as_str) == Some(case_id.as_str()))
            .ok_or("artifact origin does not reference its Case")?;
        assert_eq!(
            origin.get("selected_node_id").and_then(Value::as_u64),
            Some(node_id)
        );
        assert_eq!(
            origin.get("validation_node_id").and_then(Value::as_u64),
            Some(2)
        );
        assert!(records.iter().any(|record| {
            record.get("case_id").and_then(Value::as_str) == Some(case_id.as_str())
                && record
                    .get("nodes")
                    .and_then(Value::as_array)
                    .is_some_and(|nodes| {
                        nodes
                            .iter()
                            .any(|node| node.get("id").and_then(Value::as_u64) == Some(node_id))
                            && nodes
                                .iter()
                                .any(|node| node.get("id") == origin.get("validation_node_id"))
                    })
        }));
    }
    assert_eq!(artifacts.coverage().unique_artifacts_retained, 1);
    assert_eq!(artifacts.coverage().duplicate_byte_references_grouped, 1);
    Ok(())
}

#[test]
fn identical_exportable_nodes_keep_case_qualified_provenance_once_each()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut case = Case::new();
    let details = json!({"status": "complete", "framing_complete": true});
    let first_node = case.add_bytes_node("http_body", b"same body", Vec::new(), details.clone())?;
    let second_node = case.add_bytes_node("http_body", b"same body", Vec::new(), details)?;
    assert_ne!(first_node, second_node);

    let scope = json!({"kind": "flow", "flow_id": 12});
    let mut sidecar =
        EvidenceSidecar::new(temporary.path(), ArtifactLimits::default().evidence_bytes)?;
    let record = sidecar.record_case(&case, &scope)?;
    assert!(record.retained);
    let case_id = record.case_id;

    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    for _ in 0..2 {
        collect_case_artifacts_with_context(&mut artifacts, &case, |_, _| {
            Ok(ArtifactSourceContext {
                flow: None,
                supporting_flows: Vec::new(),
                cohort_scope: None,
                case_id: Some(case_id.clone()),
                case_scope: scope.clone(),
            })
        })?;
    }

    let mut encoded = Vec::new();
    artifacts.write_manifest_artifacts(&mut encoded)?;
    let manifest: Value =
        serde_json::from_slice(&format!("[{}]", String::from_utf8(encoded)?).into_bytes())?;
    let entries = manifest.as_array().ok_or("artifact manifest is missing")?;
    assert_eq!(entries.len(), 1);
    let origins = artifact_origins(&manifest)?;
    assert_eq!(origins.len(), 2);
    for node_id in [first_node, second_node] {
        assert!(origins.iter().any(|origin| {
            origin.get("case_id").and_then(Value::as_str) == Some(case_id.as_str())
                && origin.get("selected_node_id").and_then(Value::as_u64) == Some(node_id)
        }));
    }

    let records = read_sidecar(&temporary.path().join("evidence.jsonl"))?;
    assert!(records.iter().any(|record| {
        record.get("case_id").and_then(Value::as_str) == Some(case_id.as_str())
            && record
                .get("nodes")
                .and_then(Value::as_array)
                .is_some_and(|nodes| {
                    nodes
                        .iter()
                        .any(|node| node.get("id").and_then(Value::as_u64) == Some(first_node))
                        && nodes
                            .iter()
                            .any(|node| node.get("id").and_then(Value::as_u64) == Some(second_node))
                })
    }));
    assert_eq!(artifacts.coverage().unique_artifacts_retained, 1);
    assert_eq!(artifacts.coverage().references_retained, 2);
    assert_eq!(artifacts.coverage().duplicate_byte_references_grouped, 1);
    assert_eq!(artifacts.coverage().same_origin_references_suppressed, 2);
    let artifact_names = artifacts.file_names()?;
    assert_eq!(artifact_names.len(), 1);
    let artifact_name = artifact_names
        .iter()
        .next()
        .ok_or("retained artifact file is missing")?;
    let stored_bytes = fs::read(temporary.path().join(artifact_name))?;
    assert_eq!(stored_bytes.as_slice(), b"same body");
    Ok(())
}

#[test]
fn omitted_case_evidence_does_not_leave_export_node_references() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut case = Case::new();
    let source = case.add_source("capture.pcap", "capture", 1024, &"a".repeat(64), None)?;
    let body = b"body omitted from evidence";
    let source_range = SourceRange {
        source,
        packet: Some(8),
        offset: 20,
        length: u64::try_from(body.len())?,
    };
    case.add_bytes_node(
        "http_body",
        body,
        vec![source_range.clone()],
        json!({"status": "complete", "framing_complete": true}),
    )?;
    let scope = json!({"kind": "flow", "flow_id": 13});
    let mut sidecar = EvidenceSidecar::new(temporary.path(), 1)?;
    let record = sidecar.record_case(&case, &scope)?;
    assert!(!record.retained);

    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    collect_case_artifacts_with_context(&mut artifacts, &case, |_, _| {
        Ok(ArtifactSourceContext {
            flow: None,
            supporting_flows: Vec::new(),
            cohort_scope: None,
            case_id: None,
            case_scope: scope.clone(),
        })
    })?;

    let mut found_origin = false;
    artifacts.visit_artifact_origins(|_, _, origin| {
        found_origin = true;
        assert!(origin.case_id.is_none());
        assert!(origin.selected_node_id.is_none());
        assert!(origin.validation_node_id.is_none());
        assert!(origin.extension_node_id.is_none());
        assert!(origin.node.is_none());
        assert!(origin.selection.is_none());
        assert!(origin.signature_candidates.is_empty());
        assert_eq!(
            origin.source_ranges.as_slice(),
            std::slice::from_ref(&source_range)
        );
        Ok(())
    })?;
    assert!(found_origin);

    let mut encoded = Vec::new();
    artifacts.write_manifest_artifacts(&mut encoded)?;
    let manifest: Value =
        serde_json::from_slice(&format!("[{}]", String::from_utf8(encoded)?).into_bytes())?;
    let origin = first_artifact_origin(&manifest)?;
    assert!(origin.get("case_id").is_none_or(Value::is_null));
    assert!(origin.get("selected_node_id").is_none_or(Value::is_null));
    assert_eq!(origin.get("source_ranges"), Some(&json!([source_range])));
    Ok(())
}

#[test]
fn receipt_payload_edges_and_local_node_ids_are_retained_per_case() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = EvidenceSidecar::new(temporary.path(), 1_000_000)?;
    let first = case_with_receipt(b"private artifact payload")?;
    let second = case_with_receipt(b"private artifact payload")?;
    let first_result = sidecar.record_case(&first, &json!({"kind": "flow", "flow_id": 1}))?;
    let second_result = sidecar.record_case(&second, &json!({"kind": "flow", "flow_id": 2}))?;
    let records = read_sidecar(&temporary.path().join("evidence.jsonl"))?;

    assert_ne!(first_result.case_id, second_result.case_id);
    assert_eq!(records.len(), 2);
    for record in &records {
        assert_receipt_case(record)?;
    }
    let encoded = fs::read_to_string(temporary.path().join("evidence.jsonl"))?;
    assert!(!encoded.contains("private artifact payload"));
    assert!(!encoded.contains("cHJpdmF0ZSBhcnRpZmFjdCBwYXlsb2Fk"));
    Ok(())
}

#[test]
fn same_scope_gets_distinct_case_ids_when_graph_content_differs() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = EvidenceSidecar::new(temporary.path(), 1_000_000)?;
    let first = case_with_receipt(b"first artifact")?;
    let second = case_with_receipt(b"second artifact")?;
    let scope = json!({"kind": "flow", "flow_id": 5});

    let first_result = sidecar.record_case(&first, &scope)?;
    let second_result = sidecar.record_case(&second, &scope)?;

    assert_ne!(first_result.case_id, second_result.case_id);
    Ok(())
}

#[test]
fn evidence_budget_omits_a_whole_case_and_leaves_no_artifact_node_reference()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let case = case_with_receipt(b"retained artifact")?;
    let mut sidecar = EvidenceSidecar::new(temporary.path(), 1)?;
    let result = sidecar.record_case(&case, &json!({"kind": "flow", "flow_id": 7}))?;
    let coverage = sidecar.coverage();
    let record = artifact_provenance(
        result.retained.then_some(result.case_id.as_str()),
        result.retained.then_some(1),
        result.retained.then_some(2),
        None,
    );
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    assert_eq!(
        artifacts.add_bytes(b"retained artifact", "retained.bin", &record)?,
        AddOutcome::Stored
    );

    assert!(!result.retained);
    assert_eq!(coverage.selected_cases, 1);
    assert_eq!(coverage.retained_cases, 0);
    assert_eq!(coverage.omitted_cases, 1);
    assert_eq!(coverage.retained_bytes, 0);
    assert!(coverage.omitted_bytes > 0);
    assert!(fs::read_to_string(temporary.path().join("evidence.jsonl"))?.is_empty());
    assert_eq!(artifacts.coverage().unique_artifacts_retained, 1);

    let mut encoded = Vec::new();
    artifacts.write_manifest_artifacts(&mut encoded)?;
    let manifest: Value =
        serde_json::from_slice(&format!("[{}]", String::from_utf8(encoded)?).into_bytes())?;
    let origin = first_artifact_origin(&manifest)?;
    assert!(origin.get("case_id").is_none_or(Value::is_null));
    assert!(origin.get("selected_node_id").is_none_or(Value::is_null));
    assert!(origin.get("validation_node_id").is_none_or(Value::is_null));
    Ok(())
}

fn case_with_receipt(output_bytes: &[u8]) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("capture.pcap", "capture", 4096, &"a".repeat(64), None)?;
    let output_range = SourceRange {
        source,
        packet: Some(8),
        offset: 20,
        length: u64::try_from(output_bytes.len())?,
    };
    let output = case.add_bytes_node(
        "file_candidate",
        output_bytes,
        vec![output_range],
        json!({}),
    )?;
    let receipt_payload = serde_json::to_vec(&json!({"mapping_count": 1}))?;
    let receipt = case.add_bytes_node(
        "byte_mapping_receipt",
        &receipt_payload,
        Vec::new(),
        json!({"representation": "json_blob", "output_node": output}),
    )?;
    case.add_edge(Edge {
        from: output,
        to: receipt,
        relation: String::from("mapped_by"),
        status: EvidenceStatus::Observed,
        reason: String::from("receipt observes the retained output mapping"),
    })?;
    case.add_limitation("sample scope limitation")?;
    Ok(case)
}

fn artifact_provenance(
    case_id: Option<&str>,
    selected_node_id: Option<u64>,
    validation_node_id: Option<u64>,
    extension_node_id: Option<u64>,
) -> ArtifactProvenance {
    ArtifactProvenance {
        category: String::from("recovered_artifact"),
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        case_id: case_id.map(str::to_owned),
        selected_node_id,
        validation_node_id,
        extension_node_id,
        node: None,
        description: Some(String::from("recovered object")),
        selection: None,
        signature_candidates: Vec::new(),
        source_ranges: Vec::new(),
        canonical_origin: json!({"category": "recovered_artifact", "case_id": case_id}),
    }
}

fn artifact_origins(manifest: &Value) -> Result<&[Value], Box<dyn Error>> {
    let artifact = json_array_item(manifest, 0, "artifact manifest entry")?;
    field(artifact, "provenance", "artifact provenance")?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "artifact provenance is not an array".into())
}

fn first_artifact_origin(manifest: &Value) -> Result<&Value, Box<dyn Error>> {
    slice_item(artifact_origins(manifest)?, 0, "first artifact origin")
}

fn assert_receipt_case(record: &Value) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        field(
            field(record, "metadata", "metadata")?,
            "schema_version",
            "schema version"
        )?,
        1
    );
    let nodes = field(record, "nodes", "nodes")?;
    let first_node = json_array_item(nodes, 0, "first evidence node")?;
    let second_node = json_array_item(nodes, 1, "second evidence node")?;
    assert_eq!(field(first_node, "id", "first node id")?, 1);
    assert_eq!(field(second_node, "id", "second node id")?, 2);
    let first_range = json_array_item(
        field(first_node, "ranges", "first node ranges")?,
        0,
        "first source range",
    )?;
    assert_eq!(field(first_range, "packet", "source packet")?, 8);
    assert_eq!(field(first_range, "offset", "source offset")?, 20);
    assert_eq!(
        field(
            field(second_node, "details", "second node details")?,
            "representation",
            "receipt representation",
        )?,
        "json_blob"
    );
    let edge = json_array_item(field(record, "edges", "edges")?, 0, "first evidence edge")?;
    assert_eq!(field(edge, "from", "edge source")?, 1);
    assert_eq!(field(edge, "to", "edge target")?, 2);
    assert_eq!(field(edge, "status", "edge status")?, "observed");
    assert_eq!(
        field(edge, "reason", "edge reason")?,
        "receipt observes the retained output mapping"
    );
    assert_eq!(
        json_array_item(
            field(record, "limitations", "limitations")?,
            0,
            "first limitation",
        )?,
        "sample scope limitation"
    );
    let blobs = field(record, "blobs", "blobs")?
        .as_array()
        .ok_or("evidence blobs are not an array")?;
    assert_eq!(blobs.len(), 2);
    let receipt_blob = blobs
        .iter()
        .find(|blob| blob.get("inline_payload").is_some_and(Value::is_object))
        .ok_or("marked receipt JSON payload is missing")?;
    assert_eq!(
        field(
            field(receipt_blob, "inline_payload", "inline receipt payload")?,
            "mapping_count",
            "receipt mapping count",
        )?,
        1
    );
    assert!(
        field(receipt_blob, "byte_length", "receipt byte length")?
            .as_u64()
            .is_some()
    );
    assert!(blobs.iter().all(|blob| blob.get("bytes_base64").is_none()));
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str, context: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(name)
        .ok_or_else(|| format!("{context} is missing").into())
}

fn json_array_item<'a>(
    value: &'a Value,
    index: usize,
    context: &str,
) -> Result<&'a Value, Box<dyn Error>> {
    value
        .as_array()
        .and_then(|items| items.get(index))
        .ok_or_else(|| format!("{context} is missing").into())
}

fn slice_item<'a>(
    items: &'a [Value],
    index: usize,
    context: &str,
) -> Result<&'a Value, Box<dyn Error>> {
    items
        .get(index)
        .ok_or_else(|| format!("{context} is missing").into())
}

fn read_sidecar(path: &std::path::Path) -> Result<Vec<Value>, Box<dyn Error>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}
