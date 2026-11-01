use super::evidence::{ENCODING_VERSION, SIDECAR_FILE_NAME};
use super::{
    ArtifactCollection, ArtifactLimits, ArtifactProvenance, ArtifactSourceContext, EvidenceSidecar,
    artifact_collection::AddOutcome, collect_case_artifacts_with_context,
};
use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, SourceRange};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    io::{self, BufReader, Cursor, Read},
    path::Path,
};

fn sidecar_with_budget(path: &Path, bytes: u64) -> io::Result<EvidenceSidecar> {
    EvidenceSidecar::new(path, bytes, None)
}

#[test]
fn publication_memory_pressure_keeps_the_prior_member_and_reports_typed_error()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    let mut sidecar = EvidenceSidecar::new(directory.path(), u64::MAX, Some(&budget))?;
    let case = case_with_receipt(b"retained bytes")?;
    let scope = json!({"kind":"flow", "flow_id":1});
    sidecar.record_case(&case, &scope)?;
    sidecar.finish()?;
    let before = fs::read(directory.path().join(SIDECAR_FILE_NAME))?;
    let coverage = sidecar.coverage();
    let held = budget.try_reserve(MemoryClass::Case, 3 * 1024 * 1024)?;
    let error = sidecar
        .record_case(&case, &scope)
        .err()
        .ok_or("pressure unexpectedly admitted publication")?;
    assert!(
        error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .is_some_and(|cause| cause.downcast_ref::<MemoryError>().is_some())
    );
    assert_eq!(sidecar.coverage().selected_cases, coverage.selected_cases);
    assert_eq!(sidecar.coverage().retained_cases, coverage.retained_cases);
    assert_eq!(sidecar.coverage().omitted_cases, coverage.omitted_cases);
    assert_eq!(fs::read(directory.path().join(SIDECAR_FILE_NAME))?, before);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Publication), 0);
    assert!(
        fs::read_dir(directory.path())?.all(|entry| entry.is_ok_and(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".l2solver-evidence-case-")))
    );
    drop(held);
    sidecar.record_case(&case, &scope)?;
    Ok(())
}

#[test]
fn admitted_shared_budget_keeps_the_same_retained_cases_and_wire_bytes()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::job::MemoryBudget;
    let first = case_with_receipt(b"first retained artifact")?;
    let second = repetitive_case()?;
    let scope = json!({"kind":"flow", "flow_id":38});
    let sizing_dir = tempfile::tempdir()?;
    let mut sizing = sidecar_with_budget(sizing_dir.path(), u64::MAX)?;
    sizing.record_case(&first, &scope)?;
    let limit = sizing.coverage().retained_bytes;
    let baseline_dir = tempfile::tempdir()?;
    let mut baseline = sidecar_with_budget(baseline_dir.path(), limit)?;
    let baseline_first = baseline.record_case(&first, &scope)?;
    let baseline_second = baseline.record_case(&second, &scope)?;
    baseline.finish()?;
    let budget_dir = tempfile::tempdir()?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut budgeted = EvidenceSidecar::new(budget_dir.path(), limit, Some(&memory))?;
    let budgeted_first = budgeted.record_case(&first, &scope)?;
    let budgeted_second = budgeted.record_case(&second, &scope)?;
    budgeted.finish()?;
    assert!(baseline_first.retained && budgeted_first.retained);
    assert!(!baseline_second.retained && !budgeted_second.retained);
    assert_eq!(baseline_first.case_id, budgeted_first.case_id);
    assert_eq!(baseline_second.case_id, budgeted_second.case_id);
    assert_eq!(
        baseline_second.compressed_bytes,
        budgeted_second.compressed_bytes
    );
    assert_eq!(
        baseline.coverage().omitted_bytes,
        budgeted.coverage().omitted_bytes
    );
    assert_eq!(
        fs::read(baseline_dir.path().join(SIDECAR_FILE_NAME))?,
        fs::read(budget_dir.path().join(SIDECAR_FILE_NAME))?
    );
    Ok(())
}

#[test]
fn shared_artifact_keeps_resolvable_origins_from_distinct_cases() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar =
        sidecar_with_budget(temporary.path(), ArtifactLimits::default().evidence_bytes)?;
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

    let records = read_sidecar(&temporary.path().join(SIDECAR_FILE_NAME))?;
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
        sidecar_with_budget(temporary.path(), ArtifactLimits::default().evidence_bytes)?;
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

    let records = read_sidecar(&temporary.path().join(SIDECAR_FILE_NAME))?;
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
    let mut sidecar = sidecar_with_budget(temporary.path(), 1)?;
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
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let first = case_with_receipt(b"private artifact payload")?;
    let second = case_with_receipt(b"private artifact payload")?;
    let first_result = sidecar.record_case(&first, &json!({"kind": "flow", "flow_id": 1}))?;
    let second_result = sidecar.record_case(&second, &json!({"kind": "flow", "flow_id": 2}))?;
    let records = read_sidecar(&temporary.path().join(SIDECAR_FILE_NAME))?;

    assert_ne!(first_result.case_id, second_result.case_id);
    assert_eq!(records.len(), 2);
    for record in &records {
        assert_receipt_case(record)?;
    }
    let encoded = String::from_utf8(read_sidecar_bytes(
        &temporary.path().join(SIDECAR_FILE_NAME),
    )?)?;
    assert!(!encoded.contains("private artifact payload"));
    assert!(!encoded.contains("cHJpdmF0ZSBhcnRpZmFjdCBwYXlsb2Fk"));
    Ok(())
}

#[test]
fn sidecar_writes_versioned_normalized_records_with_decodable_receipts()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let case = case_with_receipt(b"normalized source")?;
    sidecar.record_case(&case, &json!({"kind":"flow","flow_id":4}))?;
    sidecar.finish()?;
    let mut raw = Vec::new();
    MultiGzDecoder::new(fs::File::open(temporary.path().join(SIDECAR_FILE_NAME))?)
        .read_to_end(&mut raw)?;
    let first: Value = serde_json::from_slice(
        raw.split(|byte| *byte == b'\n')
            .next()
            .ok_or("missing header")?,
    )?;
    assert_eq!(first.get("record"), Some(&json!("header")));
    assert_eq!(
        first.pointer("/value/version"),
        Some(&json!(
            l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION
        ))
    );
    let mut decoded = Vec::new();
    l2_workbench::evidence::decode_published_evidence(
        l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION,
        Cursor::new(raw),
        &mut decoded,
        l2_workbench::evidence::PublishedEvidenceLimits::new(16_000_000, 8_000_000),
    )?;
    let record: Value = serde_json::from_slice(&decoded)?;
    assert_receipt_case(&record)?;
    Ok(())
}

#[test]
fn same_scope_gets_distinct_case_ids_when_graph_content_differs() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let first = case_with_receipt(b"first artifact")?;
    let second = case_with_receipt(b"second artifact")?;
    let scope = json!({"kind": "flow", "flow_id": 5});

    let first_result = sidecar.record_case(&first, &scope)?;
    let second_result = sidecar.record_case(&second, &scope)?;

    assert_ne!(first_result.case_id, second_result.case_id);
    Ok(())
}

#[test]
fn case_id_matches_the_digest_of_its_persisted_record() -> Result<(), Box<dyn Error>> {
    const CASE_ID_PREFIX: &[u8] = b"{\"case_id\":\"";
    const HASH_DOMAIN: &[u8] = b"l2solver-export-case-v2\0";

    let temporary = tempfile::tempdir()?;
    let case = case_with_receipt(b"persisted record identity")?;
    let scope = json!({"kind": "flow", "flow_id": 11});
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let record = sidecar.record_case(&case, &scope)?;
    assert!(record.retained);
    sidecar.finish()?;

    let mut encoded = read_sidecar_bytes(&temporary.path().join(SIDECAR_FILE_NAME))?;
    assert!(encoded.ends_with(b"\n"));
    let placeholder = format!("case-{}", "0".repeat(64));
    assert_eq!(record.case_id.len(), placeholder.len());
    let id_start = CASE_ID_PREFIX.len();
    let id_end = id_start + record.case_id.len();
    assert_eq!(encoded.get(..id_start), Some(CASE_ID_PREFIX));
    assert_eq!(
        encoded.get(id_start..id_end),
        Some(record.case_id.as_bytes())
    );

    encoded
        .get_mut(id_start..id_end)
        .ok_or("case ID field should remain inside the persisted record")?
        .copy_from_slice(placeholder.as_bytes());
    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update(1_u64.to_be_bytes());
    digest.update(encoded);
    let recomputed_id = format!("case-{:x}", digest.finalize());

    assert_eq!(record.case_id, recomputed_id);
    Ok(())
}

#[test]
fn gzip_sidecar_appends_valid_members_and_checks_each_member_crc() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let empty_member_bytes = sidecar.coverage().retained_bytes;
    assert!(empty_member_bytes > 0);
    let first = case_with_receipt(b"first compressed case")?;
    let second = case_with_receipt(b"second compressed case")?;
    let first_record = sidecar.record_case(&first, &json!({"kind": "flow", "flow_id": 21}))?;
    let second_record = sidecar.record_case(&second, &json!({"kind": "flow", "flow_id": 22}))?;
    assert!(first_record.retained);
    assert!(second_record.retained);
    sidecar.finish()?;

    let sidecar_path = temporary.path().join(SIDECAR_FILE_NAME);
    let mut encoded = fs::read(&sidecar_path)?;
    assert!(encoded.starts_with(&[0x1f, 0x8b]));
    assert_eq!(
        u64::try_from(encoded.len())?,
        empty_member_bytes + first_record.compressed_bytes + second_record.compressed_bytes
    );
    assert_eq!(
        sidecar.coverage().retained_bytes,
        u64::try_from(encoded.len())?
    );
    let records = read_sidecar(&sidecar_path)?;
    assert_eq!(records.len(), 2);
    let first_record_value = records
        .first()
        .ok_or("first gzip member should contain a JSONL record")?;
    let second_record_value = records
        .get(1)
        .ok_or("second gzip member should contain a JSONL record")?;
    assert_eq!(
        first_record_value.get("case_id").and_then(Value::as_str),
        Some(first_record.case_id.as_str())
    );
    assert_eq!(
        second_record_value.get("case_id").and_then(Value::as_str),
        Some(second_record.case_id.as_str())
    );

    let crc_offset = encoded
        .len()
        .checked_sub(8)
        .ok_or("gzip sidecar is missing its trailer")?;
    let crc = encoded
        .get_mut(crc_offset)
        .ok_or("gzip CRC byte is missing")?;
    *crc ^= 1;
    let corrupted_path = temporary.path().join("corrupted-evidence.jsonl.gz");
    fs::write(&corrupted_path, encoded)?;
    let mut crc_checked_reader = MultiGzDecoder::new(fs::File::open(corrupted_path)?);
    let mut decompressed_bytes = Vec::new();
    assert!(
        crc_checked_reader
            .read_to_end(&mut decompressed_bytes)
            .is_err()
    );
    Ok(())
}

#[test]
fn empty_sidecar_is_valid_gzip_when_its_physical_member_fits() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut sidecar = sidecar_with_budget(temporary.path(), 1_000_000)?;
    let coverage = sidecar.coverage();
    assert_eq!(coverage.selected_cases, 0);
    assert_eq!(coverage.retained_cases, 0);
    assert_eq!(coverage.raw_retained_bytes, 0);
    assert!(coverage.retained_bytes > 0);
    sidecar.finish()?;

    let path = temporary.path().join(SIDECAR_FILE_NAME);
    let encoded = fs::read(&path)?;
    assert_eq!(u64::try_from(encoded.len())?, coverage.retained_bytes);
    assert!(read_sidecar_bytes(&path)?.is_empty());

    let zero_budget_directory = tempfile::tempdir()?;
    let mut zero_budget = sidecar_with_budget(zero_budget_directory.path(), 0)?;
    assert_eq!(zero_budget.coverage().retained_bytes, 0);
    zero_budget.finish()?;
    assert!(fs::read(zero_budget_directory.path().join(SIDECAR_FILE_NAME))?.is_empty());
    Ok(())
}

#[test]
fn evidence_budget_uses_physical_gzip_bytes_and_tracks_raw_bytes() -> Result<(), Box<dyn Error>> {
    let case = case_with_receipt(b"budgeted compressed record")?;
    let scope = json!({"kind": "flow", "flow_id": 31});
    let sizing_directory = tempfile::tempdir()?;
    let mut sizing_sidecar = sidecar_with_budget(sizing_directory.path(), u64::MAX)?;
    let sized_record = sizing_sidecar.record_case(&case, &scope)?;
    assert!(sized_record.retained);
    let compressed_bytes = sized_record.compressed_bytes;
    let empty_member_bytes = sizing_sidecar
        .coverage()
        .retained_bytes
        .checked_sub(compressed_bytes)
        .ok_or("empty gzip member bytes exceed the retained total")?;
    let physical_bytes = sizing_sidecar.coverage().retained_bytes;
    let raw_bytes = sized_record.encoded_bytes;
    let sizing_coverage = sizing_sidecar.coverage();
    assert_eq!(sizing_coverage.encoding_version, ENCODING_VERSION);
    assert_eq!(sizing_coverage.retained_bytes, physical_bytes);
    assert_eq!(sizing_coverage.raw_retained_bytes, raw_bytes);

    let exact_directory = tempfile::tempdir()?;
    let mut exact_sidecar = sidecar_with_budget(exact_directory.path(), physical_bytes)?;
    let exact_record = exact_sidecar.record_case(&case, &scope)?;
    assert!(exact_record.retained);
    assert_eq!(exact_sidecar.coverage().retained_bytes, physical_bytes);

    let below_budget = physical_bytes
        .checked_sub(1)
        .ok_or("a gzip member must have a non-zero encoded length")?;
    let omitted_directory = tempfile::tempdir()?;
    let mut omitted_sidecar = sidecar_with_budget(omitted_directory.path(), below_budget)?;
    let omitted_record = omitted_sidecar.record_case(&case, &scope)?;
    let omitted_coverage = omitted_sidecar.coverage();
    assert!(!omitted_record.retained);
    assert_eq!(omitted_coverage.retained_bytes, empty_member_bytes);
    assert_eq!(omitted_coverage.omitted_bytes, compressed_bytes);
    assert_eq!(omitted_coverage.raw_omitted_bytes, raw_bytes);
    let omitted_path = omitted_directory.path().join(SIDECAR_FILE_NAME);
    assert_eq!(fs::metadata(&omitted_path)?.len(), empty_member_bytes);
    assert!(read_sidecar(&omitted_path)?.is_empty());
    Ok(())
}

#[test]
fn omitting_a_later_case_keeps_the_first_complete_and_verifiable() -> Result<(), Box<dyn Error>> {
    let first = case_with_receipt(b"first retained artifact")?;
    let second = repetitive_case()?;
    let scope = json!({"kind":"flow","flow_id":38});
    let sizing_dir = tempfile::tempdir()?;
    let mut sizing = sidecar_with_budget(sizing_dir.path(), u64::MAX)?;
    let first_record = sizing.record_case(&first, &scope)?;
    sizing.finish()?;
    let exact_budget = sizing.coverage().retained_bytes;
    let expected = read_sidecar_bytes(&sizing_dir.path().join(SIDECAR_FILE_NAME))?;

    let output_dir = tempfile::tempdir()?;
    let mut output = sidecar_with_budget(output_dir.path(), exact_budget)?;
    let retained = output.record_case(&first, &scope)?;
    let omitted = output.record_case(&second, &scope)?;
    output.finish()?;
    assert!(retained.retained);
    assert!(!omitted.retained);
    assert_eq!(retained.case_id, first_record.case_id);
    assert_eq!(output.coverage().retained_cases, 1);
    assert_eq!(output.coverage().omitted_cases, 1);
    assert_eq!(output.coverage().retained_bytes, exact_budget);
    assert_eq!(
        read_sidecar_bytes(&output_dir.path().join(SIDECAR_FILE_NAME))?,
        expected
    );
    Ok(())
}

#[test]
fn repetitive_evidence_fits_a_tighter_budget_without_changing_the_v2_record()
-> Result<(), Box<dyn Error>> {
    let case = repetitive_case()?;
    let scope = json!({"kind": "flow", "flow_id": 32});
    let sizing_directory = tempfile::tempdir()?;
    let mut sizing = sidecar_with_budget(sizing_directory.path(), u64::MAX)?;
    let first = sizing.record_case(&case, &scope)?;
    sizing.finish()?;
    let raw = read_sidecar_bytes(&sizing_directory.path().join(SIDECAR_FILE_NAME))?;
    let normalized =
        read_normalized_sidecar_bytes(&sizing_directory.path().join(SIDECAR_FILE_NAME))?;
    let mut fast = GzEncoder::new(Vec::new(), Compression::fast());
    io::copy(
        &mut BufReader::with_capacity(64 * 1024, Cursor::new(&raw)),
        &mut fast,
    )?;
    let fast_bytes = u64::try_from(fast.finish()?.len())?;
    assert!(
        first.compressed_bytes < fast_bytes,
        "repeated provenance should use fewer bytes than fast gzip"
    );

    let empty_member_bytes = sizing.coverage().retained_bytes - first.compressed_bytes;
    let budget = empty_member_bytes + fast_bytes - 1;
    let budget_directory = tempfile::tempdir()?;
    let mut budgeted = sidecar_with_budget(budget_directory.path(), budget)?;
    let second = budgeted.record_case(&case, &scope)?;
    budgeted.finish()?;
    assert!(
        second.retained,
        "the complete Case should fit the tighter budget"
    );
    assert_eq!(second.case_id, first.case_id);
    assert_eq!(second.encoded_bytes, u64::try_from(normalized.len())?);
    assert_eq!(budgeted.coverage().retained_cases, 1);
    assert_eq!(budgeted.coverage().omitted_cases, 0);
    assert_eq!(
        budgeted.coverage().raw_retained_bytes,
        u64::try_from(normalized.len())?
    );
    assert_eq!(
        budgeted.coverage().retained_bytes,
        fs::metadata(budget_directory.path().join(SIDECAR_FILE_NAME))?.len()
    );
    assert_eq!(
        read_sidecar_bytes(&budget_directory.path().join(SIDECAR_FILE_NAME))?,
        raw
    );

    let records = read_sidecar(&budget_directory.path().join(SIDECAR_FILE_NAME))?;
    let record = records.first().ok_or("retained Case is missing")?;
    assert_eq!(record.get("scope"), Some(&scope));
    assert_eq!(
        record.get("sources"),
        Some(&serde_json::to_value(case.sources())?)
    );
    assert_eq!(
        record.get("nodes"),
        Some(&serde_json::to_value(case.nodes())?)
    );
    assert_eq!(
        record.get("edges"),
        Some(&serde_json::to_value(case.edges())?)
    );
    assert_eq!(
        record.get("limitations"),
        Some(&serde_json::to_value(case.limitations())?)
    );
    assert_receipt_case(record)?;
    Ok(())
}

#[test]
fn evidence_budget_omits_a_whole_case_and_leaves_no_artifact_node_reference()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let case = case_with_receipt(b"retained artifact")?;
    let mut sidecar = sidecar_with_budget(temporary.path(), 1)?;
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
    assert!(fs::read(temporary.path().join(SIDECAR_FILE_NAME))?.is_empty());
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

fn repetitive_case() -> Result<Case, Box<dyn Error>> {
    let mut case = case_with_receipt(b"complete recovered artifact")?;
    let source = case
        .sources()
        .first()
        .ok_or("fixture source is missing")?
        .id
        .clone();
    for index in 0..800_u64 {
        let node = case.add_node(
            "custom_protocol_frame",
            None,
            vec![SourceRange {
                source: source.clone(),
                packet: Some(index + 1),
                offset: index,
                length: 1,
            }],
            json!({
                "frame_index": index,
                "input_node": 1,
                "framing_rule": {"kind": "fixed_size", "bytes": 1},
                "stream_range": {"start": index, "end": index + 1},
            }),
        )?;
        case.add_edge(Edge {
            from: 1,
            to: node,
            relation: "candidate_framed_as".to_owned(),
            status: if index % 2 == 0 {
                EvidenceStatus::Hypothesis
            } else {
                EvidenceStatus::ConstraintFailed
            },
            reason: "the same framing rule describes each source range".to_owned(),
        })?;
    }
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

fn read_sidecar_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let normalized = read_normalized_sidecar_bytes(path)?;
    let mut canonical = Vec::new();
    l2_workbench::evidence::decode_published_evidence(
        ENCODING_VERSION,
        Cursor::new(normalized),
        &mut canonical,
        l2_workbench::evidence::PublishedEvidenceLimits::new(u64::MAX, 32 * 1024 * 1024),
    )?;
    Ok(canonical)
}

fn read_normalized_sidecar_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut gzip_reader = MultiGzDecoder::new(fs::File::open(path)?);
    let mut jsonl_bytes = Vec::new();
    gzip_reader.read_to_end(&mut jsonl_bytes)?;
    Ok(jsonl_bytes)
}

fn read_sidecar(path: &Path) -> Result<Vec<Value>, Box<dyn Error>> {
    Ok(String::from_utf8(read_sidecar_bytes(path)?)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}
