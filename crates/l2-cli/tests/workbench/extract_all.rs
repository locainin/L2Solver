use super::support::{path_arg, run, save_case, stored_zip};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus};
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

struct RecoveredNodes {
    archive_input: u64,
    archive_structure: u64,
    der_input: u64,
    der_structure: u64,
    member: u64,
    record: u64,
}

#[test]
fn writes_recovered_artifacts() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (case, nodes) = recovered_case()?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    verify_recovered_files(&destination, &nodes)?;
    verify_recovered_summary(&destination, &output.stdout)?;
    verify_recovered_manifest(&destination, &case, &nodes)?;
    Ok(())
}

#[test]
fn record_objects_keep_validation_evidence() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let zip_bytes = stored_zip(b"member.txt", b"member bytes")?;
    let der_bytes = [0x30, 0x03, 0x04, 0x01, b'A'];
    let mut case = Case::new();
    let zip_input = case.add_bytes_node("record_object", &zip_bytes, Vec::new(), json!({}))?;
    let der_input = case.add_bytes_node("record_object", &der_bytes, Vec::new(), json!({}))?;
    let case = expand_selected(&case, zip_input)?;
    let case = expand_selected(&case, der_input)?;
    let zip_structure = structure_for_input(&case, "archive_structure", zip_input)?;
    let der_structure = structure_for_input(&case, "der_structure", der_input)?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(artifact_files(&destination)?.len(), 3);
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let zip_file = format!("artifact-{zip_input}-record.bin");
    let zip_node = first_manifest_node(find_manifest_artifact(&manifest, &zip_file)?)?;
    assert_validation_evidence(zip_node, "zip_structure", zip_structure);
    let der_file = format!("artifact-{der_input}-record.bin");
    let der_node = first_manifest_node(find_manifest_artifact(&manifest, &der_file)?)?;
    assert_validation_evidence(der_node, "der_structure", der_structure);
    assert_observed_edge(&case, zip_input, zip_structure, "parsed_as");
    assert_observed_edge(&case, der_input, der_structure, "parsed_as");
    Ok(())
}

#[test]
fn incomplete_record_assembly_keeps_structure_validation_independent() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let (case, candidate_id) = assembled_archive_case(directory.path(), None)?;
    let candidate = case
        .nodes()
        .iter()
        .find(|node| node.id == candidate_id)
        .ok_or("assembled archive candidate is missing")?;
    assert_eq!(candidate.kind, "record_candidate");
    assert_eq!(candidate.details.get("group_complete"), Some(&json!(false)));
    assert_eq!(
        candidate.details.get("assembly_complete"),
        Some(&json!(false))
    );

    let expanded = expand_selected(&case, candidate_id)?;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");
    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let file_name = format!("artifact-{candidate_id}-archive-input.zip");
    let provenance = first_manifest_node(find_manifest_artifact(&manifest, &file_name)?)?;
    assert_eq!(
        provenance
            .get("reconstruction_status")
            .and_then(Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        provenance
            .get("structural_validation_status")
            .and_then(Value::as_str),
        Some("validated")
    );
    assert_eq!(
        provenance.get("validated_as").and_then(Value::as_str),
        Some("zip_structure")
    );
    assert_eq!(
        provenance.get("completion_basis").and_then(Value::as_str),
        Some("observed_prefix_only")
    );
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Reconstruction: incomplete"));
    assert!(summary.contains("Structural validation: validated as \"zip_structure\""));
    Ok(())
}

#[test]
fn duplicate_record_archive_exports_incomplete_after_validation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (assembled, candidate_id, archive) = conflicting_duplicate_archive_case(directory.path())?;

    let expanded = expand_selected(&assembled, candidate_id)?;
    assert!(expanded.nodes().iter().any(|node| {
        node.kind == "archive_structure"
            && node.details.get("input_node").and_then(Value::as_u64) == Some(candidate_id)
    }));
    assert!(expanded.nodes().iter().any(|node| {
        node.kind == "archive_member"
            && node.details.get("archive_node").and_then(Value::as_u64) == Some(candidate_id)
    }));
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");
    let export_output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;
    assert!(
        export_output.status.success(),
        "{}",
        String::from_utf8_lossy(&export_output.stderr)
    );
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let file_name = format!("artifact-{candidate_id}-archive-input.zip");
    let provenance = first_manifest_node(find_manifest_artifact(&manifest, &file_name)?)?;
    assert_eq!(
        provenance
            .get("reconstruction_status")
            .and_then(Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        provenance
            .get("structural_validation_status")
            .and_then(Value::as_str),
        Some("validated")
    );
    assert_eq!(
        provenance.get("validated_as").and_then(Value::as_str),
        Some("zip_structure")
    );
    assert_eq!(
        fs::read(destination.join(&file_name))?,
        archive,
        "export should preserve the labeled partial candidate bytes exactly"
    );
    assert!(
        fs::read_to_string(destination.join("summary.txt"))?.contains("Reconstruction: incomplete")
    );
    Ok(())
}

fn conflicting_duplicate_archive_case(
    directory: &Path,
) -> Result<(Case, u64, Vec<u8>), Box<dyn Error>> {
    let schema_path = directory.join("record-schema.json");
    let archive = stored_zip(b"member.txt", b"member from conflicting records")?;
    let mut record_stream = vec![2];
    for payload in [archive.as_slice(), &[][..]] {
        record_stream.extend_from_slice(b"P1");
        record_stream.extend_from_slice(&0_u16.to_be_bytes());
        record_stream.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
        record_stream.extend_from_slice(payload);
    }
    let schema = json!({
        "records_offset":1,
        "count":{"kind":"field","field":{"offset":0,"width":1,"byte_order":"big_endian"}},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":0
    });
    fs::write(&schema_path, serde_json::to_vec(&schema)?)?;
    let mut source = Case::new();
    let input = source.add_bytes_node("candidate_stream", &record_stream, Vec::new(), json!({}))?;
    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema_path)?,
        ],
        &source.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let assembled = Case::from_json(&output.stdout)?;
    let candidate_id = assert_conflicting_record_candidate(&assembled, &archive)?;
    Ok((assembled, candidate_id, archive))
}

fn assert_conflicting_record_candidate(case: &Case, archive: &[u8]) -> Result<u64, Box<dyn Error>> {
    let candidate = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_candidate")
        .ok_or("conflicting record candidate is missing")?;
    assert_eq!(candidate.details.get("group_complete"), Some(&json!(false)));
    assert_eq!(
        candidate.details.get("assembly_complete"),
        Some(&json!(false))
    );
    let blob_id = candidate
        .blob
        .as_deref()
        .ok_or("candidate bytes are missing")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .ok_or("candidate blob is missing")?;
    assert_eq!(blob.bytes, archive);

    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_parse_receipt")
        .ok_or("record assembly receipt is missing")?;
    let receipt_blob_id = receipt.blob.as_deref().ok_or("receipt bytes are missing")?;
    let receipt_blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .ok_or("receipt blob is missing")?;
    let receipt_json: Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(
        receipt_json.pointer("/assembly/groups/0/duplicate_sequences"),
        Some(&json!([0]))
    );
    assert!(!case.nodes().iter().any(|node| node.kind == "record_object"));
    Ok(candidate.id)
}

#[test]
fn complete_record_assembly_is_reported_separately_from_structure() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (case, object_id) = assembled_archive_case(directory.path(), Some(0))?;
    let object = case
        .nodes()
        .iter()
        .find(|node| node.id == object_id)
        .ok_or("assembled archive object is missing")?;
    assert_eq!(object.kind, "record_object");
    assert_eq!(object.details.get("group_complete"), Some(&json!(true)));
    assert_eq!(object.details.get("assembly_complete"), Some(&json!(true)));

    let expanded = expand_selected(&case, object_id)?;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");
    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let record_prefix = format!("artifact-{object_id}-record.");
    let record = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| {
            artifacts.iter().find(|artifact| {
                artifact
                    .get("file")
                    .and_then(Value::as_str)
                    .is_some_and(|file| file.starts_with(&record_prefix))
            })
        })
        .ok_or("manifest record for assembled artifact is missing")?;
    let provenance = first_manifest_node(record)?;
    assert_eq!(
        provenance
            .get("reconstruction_status")
            .and_then(Value::as_str),
        Some("complete")
    );
    assert_eq!(
        provenance
            .get("structural_validation_status")
            .and_then(Value::as_str),
        Some("validated")
    );
    assert_eq!(
        provenance.get("validated_as").and_then(Value::as_str),
        Some("zip_structure")
    );
    Ok(())
}

fn verify_recovered_files(directory: &Path, nodes: &RecoveredNodes) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        fs::read(directory.join(format!(
            "artifact-{}-archive-input.zip",
            nodes.archive_input
        )))?,
        stored_zip(b"logs/session \xCE\xA9.log", &[0, 0xff, 0, b'A'])?
    );
    assert_eq!(
        fs::read(directory.join(format!("artifact-{}-der-input.der", nodes.der_input)))?,
        [0x30, 0x03, 0x04, 0x01, b'A']
    );
    assert_eq!(
        fs::read(directory.join(format!("artifact-{}-session Ω.log", nodes.member)))?,
        [0, 0xff, 0, b'A']
    );
    assert_eq!(
        fs::read(directory.join(format!("artifact-{}-record.txt", nodes.record)))?,
        b"a plain text record\n"
    );
    assert_eq!(artifact_files(directory)?.len(), 4);
    Ok(())
}

fn verify_recovered_summary(directory: &Path, stdout: &[u8]) -> Result<(), Box<dyn Error>> {
    let summary = fs::read_to_string(directory.join("summary.txt"))?;
    assert!(summary.contains("logs/session Ω.log"));
    assert!(summary.contains("archive-input.zip"));
    assert!(summary.contains("validated as \"zip_structure\""));
    assert!(summary.contains("validation evidence node"));
    assert!(summary.contains("Evidence retention: complete"));
    assert!(!summary.contains("sha256"));
    assert!(String::from_utf8_lossy(stdout).contains("Exported 4 recovered artifact files"));
    Ok(())
}

fn verify_recovered_manifest(
    directory: &Path,
    case: &Case,
    nodes: &RecoveredNodes,
) -> Result<(), Box<dyn Error>> {
    let manifest: Value = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("manifest artifacts are missing")?;
    assert_eq!(artifacts.len(), 4);

    let archive_file = format!("artifact-{}-archive-input.zip", nodes.archive_input);
    let archive_node = first_manifest_node(find_manifest_artifact(&manifest, &archive_file)?)?;
    assert_validation_evidence(archive_node, "zip_structure", nodes.archive_structure);

    let der_file = format!("artifact-{}-der-input.der", nodes.der_input);
    let der_node = first_manifest_node(find_manifest_artifact(&manifest, &der_file)?)?;
    assert_validation_evidence(der_node, "der_structure", nodes.der_structure);

    let member_file = format!("artifact-{}-session Ω.log", nodes.member);
    let member_node = first_manifest_node(find_manifest_artifact(&manifest, &member_file)?)?;
    assert_validation_evidence(member_node, "zip_member", nodes.archive_structure);
    assert_observed_edge(
        case,
        nodes.archive_input,
        nodes.archive_structure,
        "parsed_as",
    );
    assert_observed_edge(case, nodes.der_input, nodes.der_structure, "parsed_as");
    assert_observed_edge(case, nodes.archive_input, nodes.member, "contains_member");
    assert!(fs::read_to_string(directory.join("manifest.json"))?.contains("logs/session Ω.log"));
    Ok(())
}

fn assembled_archive_case(
    directory: &Path,
    terminal_sequence: Option<u16>,
) -> Result<(Case, u64), Box<dyn Error>> {
    let schema_path = directory.join("record-schema.json");
    let mut schema = json!({
        "records_offset":1,
        "count":{"kind":"field","field":{"offset":0,"width":1,"byte_order":"big_endian"}},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0
    });
    if let Some(terminal_sequence) = terminal_sequence {
        schema
            .as_object_mut()
            .ok_or("record schema is not an object")?
            .insert("terminal_sequence".to_owned(), json!(terminal_sequence));
    }
    fs::write(&schema_path, serde_json::to_vec(&schema)?)?;

    let archive = stored_zip(b"member.txt", b"record-assembled archive")?;
    let payload_length = u16::try_from(archive.len())?;
    let mut record_stream = vec![1, b'P', b'1'];
    record_stream.extend_from_slice(&0_u16.to_be_bytes());
    record_stream.extend_from_slice(&payload_length.to_be_bytes());
    record_stream.extend_from_slice(&archive);
    let mut source_case = Case::new();
    let input =
        source_case.add_bytes_node("candidate_stream", &record_stream, Vec::new(), json!({}))?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema_path)?,
        ],
        &source_case.to_json()?,
    )?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }

    let assembled_case = Case::from_json(&output.stdout)?;
    let expected_kind = if terminal_sequence.is_some() {
        "record_object"
    } else {
        "record_candidate"
    };
    let assembled = assembled_case
        .nodes()
        .iter()
        .find(|node| node.kind == expected_kind)
        .ok_or_else(|| format!("missing {expected_kind} from record assembly"))?;
    let assembled_id = assembled.id;
    Ok((assembled_case, assembled_id))
}

fn find_manifest_artifact<'a>(
    manifest: &'a Value,
    file_name: &str,
) -> Result<&'a Value, Box<dyn Error>> {
    manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| {
            artifacts
                .iter()
                .find(|artifact| artifact.get("file").and_then(Value::as_str) == Some(file_name))
        })
        .ok_or_else(|| format!("manifest record for {file_name:?} is missing").into())
}

fn first_manifest_node(record: &Value) -> Result<&Value, Box<dyn Error>> {
    record
        .get("nodes")
        .and_then(Value::as_array)
        .and_then(|nodes| nodes.first())
        .ok_or_else(|| "manifest node record is missing".into())
}

fn assert_validation_evidence(node: &Value, format: &str, evidence_node: u64) {
    assert_eq!(
        node.get("validated_as").and_then(Value::as_str),
        Some(format)
    );
    assert_eq!(
        node.get("validation_evidence_node").and_then(Value::as_u64),
        Some(evidence_node)
    );
}

fn assert_observed_edge(case: &Case, from: u64, to: u64, relation: &str) {
    assert!(case.edges().iter().any(|edge| {
        edge.from == from
            && edge.to == to
            && edge.relation == relation
            && edge.status == EvidenceStatus::Observed
    }));
}

#[test]
fn validated_png_and_trailer_exported() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = encoded_png()?;
    let mut input_bytes = png_bytes.clone();
    input_bytes.extend_from_slice(b"trailing carrier bytes");
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &input_bytes, Vec::new(), json!({}))?;
    let expanded = expand_selected(&case, input)?;
    let structure = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "png_structure")
        .ok_or("PNG structure node is missing")?;
    let structure_id = structure.id;
    let trailer = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "png_trailing_data")
        .ok_or("PNG trailer node is missing")?;
    let trailer_id = trailer.id;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = format!("artifact-{structure_id}-png.png");
    assert_eq!(fs::read(destination.join(&file))?, png_bytes);
    assert_eq!(
        fs::read(destination.join(format!("artifact-{trailer_id}-png-trailing-data.bin")))?,
        b"trailing carrier bytes"
    );
    assert_eq!(artifact_files(&destination)?.len(), 2);
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(manifest.pointer("/artifacts/0/file"), Some(&json!(file)));
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/validated_as"),
        Some(&json!("png_structure"))
    );
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/id"),
        Some(&json!(structure_id))
    );
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/validation_evidence_node"),
        Some(&json!(structure_id))
    );
    assert_eq!(
        manifest.pointer("/artifacts/1/nodes/0/validation_evidence_node"),
        Some(&json!(structure_id))
    );
    assert!(String::from_utf8(output.stdout)?.contains("Exported 2 recovered artifact files"));
    assert!(expanded.edges().iter().any(|edge| {
        edge.from == input
            && edge.to == structure_id
            && edge.relation == "parsed_as"
            && edge.status == EvidenceStatus::Observed
    }));
    assert!(expanded.edges().iter().any(|edge| {
        edge.from == structure_id
            && edge.to == trailer_id
            && edge.relation == "followed_by"
            && edge.status == EvidenceStatus::Observed
    }));
    Ok(())
}

#[test]
fn forged_png_trailer_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = encoded_png()?;
    let mut input_bytes = png_bytes;
    input_bytes.extend_from_slice(b"trusted trailer");
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &input_bytes, Vec::new(), json!({}))?;
    let mut expanded = expand_selected(&case, input)?;
    let structure = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "png_structure")
        .ok_or("PNG structure node is missing")?;
    let structure_id = structure.id;
    let trailer = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "png_trailing_data")
        .ok_or("PNG trailer node is missing")?;
    let trailer_details = trailer.details.clone();
    let forged_id = expanded.add_bytes_node(
        "png_trailing_data",
        b"forged trailer",
        Vec::new(),
        trailer_details,
    )?;
    expanded.add_edge(Edge {
        from: structure_id,
        to: forged_id,
        relation: "followed_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Forged trailer claim".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(artifact_files(&destination)?.len(), 2);
    assert!(
        !destination
            .join(format!("artifact-{forged_id}-png-trailing-data.bin"))
            .exists()
    );
    Ok(())
}

#[test]
fn png_parse_edge_required() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = encoded_png()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &png_bytes, Vec::new(), json!({}))?;
    let structure = case.add_bytes_node(
        "png_structure",
        &png_bytes,
        Vec::new(),
        json!({
            "input_node":input,
            "chunk_count":3,
            "bytes_after_iend":0,
            "iend_end_offset":png_bytes.len(),
            "object_range":{"offset":0,"length":png_bytes.len()}
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: "PNG structure remains unconfirmed".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(manifest.get("artifacts"), Some(&json!([])));
    Ok(())
}

#[test]
fn png_structure_evidence_required() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = encoded_png()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &png_bytes, Vec::new(), json!({}))?;
    let structure = case.add_bytes_node(
        "png_structure",
        &png_bytes,
        Vec::new(),
        json!({"input_node":input}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "PNG structure was inspected".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(manifest.get("artifacts"), Some(&json!([])));
    Ok(())
}

#[test]
fn forged_png_structure_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = b"\x89PNG\r\n\x1a\ntruncated";
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", png_bytes, Vec::new(), json!({}))?;
    let structure = case.add_bytes_node(
        "png_structure",
        png_bytes,
        Vec::new(),
        json!({
            "input_node":input,
            "chunk_count":3,
            "bytes_after_iend":0,
            "iend_end_offset":png_bytes.len(),
            "object_range":{"offset":0,"length":png_bytes.len()}
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Claimed PNG structure".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn png_signature_ignored() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let png_bytes = encoded_png()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &png_bytes, Vec::new(), json!({}))?;
    let blob = node_blob(&case, input)?;
    case.add_node(
        "file_signature_match",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node":input,
            "ambiguous":false,
            "extensions":["png"],
            "range":{"offset":0,"length":8}
        }),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(manifest.get("artifacts"), Some(&json!([])));
    Ok(())
}

fn recovered_case() -> Result<(Case, RecoveredNodes), Box<dyn Error>> {
    let mut case = Case::new();
    let member_bytes = [0, 0xff, 0, b'A'];
    let archive_bytes = stored_zip(b"logs/session \xCE\xA9.log", &member_bytes)?;
    let archive_input =
        case.add_bytes_node("record_candidate", &archive_bytes, Vec::new(), json!({}))?;
    let der_bytes = [0x30, 0x03, 0x04, 0x01, b'A'];
    let der_input = case.add_bytes_node("candidate_object", &der_bytes, Vec::new(), json!({}))?;
    let record = case.add_bytes_node(
        "record_object",
        b"a plain text record\n",
        Vec::new(),
        json!({}),
    )?;

    let archive_case = expand_selected(&case, archive_input)?;
    let expanded_case = expand_selected(&archive_case, der_input)?;
    let archive_structure = expanded_case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "archive_structure"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(archive_input)
        })
        .ok_or("validated archive structure is missing")?
        .id;
    let der_structure = expanded_case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "der_structure"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(der_input)
        })
        .ok_or("validated DER structure is missing")?
        .id;
    let member = expanded_case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "archive_member"
                && node.details.get("archive_node").and_then(Value::as_u64) == Some(archive_input)
        })
        .ok_or("validated archive member is missing")?
        .id;
    Ok((
        expanded_case,
        RecoveredNodes {
            archive_input,
            archive_structure,
            der_input,
            der_structure,
            member,
            record,
        },
    ))
}

fn structure_for_input(case: &Case, kind: &str, input: u64) -> Result<u64, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| {
            node.kind == kind
                && node.details.get("input_node").and_then(Value::as_u64) == Some(input)
        })
        .map(|node| node.id)
        .ok_or_else(|| format!("{kind} node for input {input} is missing").into())
}

fn add_parsed_structure(case: &mut Case, input: u64, kind: &str) -> Result<u64, Box<dyn Error>> {
    let blob = node_blob(case, input)?;
    let input_length = case
        .blobs()
        .iter()
        .find(|candidate| candidate.id == blob)
        .ok_or("input blob is missing")?
        .bytes
        .len();
    let details = if kind == "archive_structure" {
        json!({"input_node":input,"format":"zip","archive_size":input_length})
    } else {
        json!({
            "input_node":input,
            "value_count":1,
            "boundary_range":{"offset":0,"length":input_length}
        })
    };
    let structure = case.add_node(kind, Some(&blob), Vec::new(), details)?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The structure was parsed".to_owned(),
    })?;
    Ok(structure)
}

#[test]
fn exact_bytes_deduplicated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let first_record =
        case.add_bytes_node("record_object", b"same exact bytes", Vec::new(), json!({}))?;
    case.add_bytes_node("record_object", b"same exact bytes", Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(artifact_files(&destination)?.len(), 1);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Exported 1 recovered artifact file from 2 retained nodes"));
    assert_eq!(
        fs::read(destination.join(format!("artifact-{first_record}-record.txt")))?,
        b"same exact bytes"
    );
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(
        summary
            .contains("Files: 1; retained artifact nodes: 2; duplicate byte references grouped: 1")
    );
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("manifest artifacts are missing")?;
    let first = artifacts.first().ok_or("manifest artifact is missing")?;
    let nodes = first
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("artifact nodes are missing")?;
    assert_eq!(nodes.len(), 2);
    let first_node = nodes.first().ok_or("artifact node is missing")?;
    assert_eq!(
        first_node
            .get("reconstruction_status")
            .and_then(Value::as_str),
        Some("unknown")
    );
    assert_eq!(
        first_node
            .get("structural_validation_status")
            .and_then(Value::as_str),
        Some("not_checked")
    );
    Ok(())
}

#[test]
fn hypothesis_parse_not_promoted() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        b"unconfirmed archive",
        Vec::new(),
        json!({}),
    )?;
    let structure = case.add_node(
        "archive_structure",
        None,
        Vec::new(),
        json!({"input_node":input}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: "The archive interpretation is only a hypothesis".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(artifact_files(&destination)?.is_empty());
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(manifest.get("artifacts"), Some(&json!([])));
    Ok(())
}

#[test]
fn orphan_archive_member_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        b"forged member bytes",
        Vec::new(),
        json!({"utf8_name":"orphan.txt"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn orphan_png_trailer_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "png_trailing_data",
        b"unlinked trailer",
        Vec::new(),
        json!({}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn forged_archive_member_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"real.txt", b"real member bytes")?;
    let mut initial_case = Case::new();
    let input = initial_case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let mut case = expand_selected(&initial_case, input)?;
    let valid_member = case
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member")
        .ok_or("validated archive member is missing")?;
    let member_details = valid_member.details.clone();
    let valid_member_id = valid_member.id;
    let forged_member = case.add_bytes_node(
        "archive_member",
        b"forged member bytes",
        Vec::new(),
        member_details,
    )?;
    case.add_edge(Edge {
        from: input,
        to: forged_member,
        relation: "contains_member".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Unverified member claim".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(artifact_files(&destination)?.len(), 2);
    assert_eq!(
        fs::read(destination.join(format!("artifact-{input}-archive-input.zip")))?,
        archive
    );
    assert_eq!(
        fs::read(destination.join(format!("artifact-{valid_member_id}-real.txt")))?,
        b"real member bytes"
    );
    assert!(
        !destination
            .join(format!("artifact-{forged_member}-real.txt"))
            .exists()
    );
    Ok(())
}

#[test]
fn forged_zip_structure_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "record_candidate",
        b"PK\x03\x04 not a valid archive",
        Vec::new(),
        json!({}),
    )?;
    let structure = add_parsed_structure(&mut case, input, "archive_structure")?;
    let member = case.add_bytes_node(
        "archive_member",
        b"invented member bytes",
        Vec::new(),
        json!({
            "archive_node":input,
            "structure_node":structure,
            "entry_index":0,
            "utf8_name":"invented.txt"
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: member,
        relation: "contains_member".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Claimed archive member".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn forged_valid_zip_structure_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"member.txt", b"member bytes")?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let blob = node_blob(&case, input)?;
    let forged_structure = case.add_node(
        "archive_structure",
        Some(&blob),
        Vec::new(),
        json!({"input_node":input}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: forged_structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "This structure omits parser facts".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    assert!(case.edges().iter().any(|edge| {
        edge.from == input
            && edge.to == forged_structure
            && edge.relation == "parsed_as"
            && edge.status == EvidenceStatus::Observed
    }));
    Ok(())
}

#[test]
fn zip_member_metadata_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"member.txt", b"member bytes")?;
    let mut initial_case = Case::new();
    let input = initial_case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let mut case = expand_selected(&initial_case, input)?;
    let valid_member = case
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member")
        .ok_or("validated archive member is missing")?;
    let details = valid_member.details.clone();
    let mut forged_ids = Vec::new();
    for (field, value) in [
        ("raw_name_sha256", json!("sha256:forged")),
        ("raw_name_hex", json!("00")),
        ("raw_name_truncated", json!(true)),
        ("compression_method", json!(8)),
        ("encrypted", json!(true)),
    ] {
        let mut forged_details = details.clone();
        let Some(fields) = forged_details.as_object_mut() else {
            return Err("archive member details are not an object".into());
        };
        fields.insert(field.to_owned(), value);
        let forged_member = case.add_bytes_node(
            "archive_member",
            b"member bytes",
            Vec::new(),
            forged_details,
        )?;
        forged_ids.push(forged_member);
        case.add_edge(Edge {
            from: input,
            to: forged_member,
            relation: "contains_member".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "This member alters one parser fact".to_owned(),
        })?;
    }
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(artifact_files(&destination)?.len(), 2);
    for forged_id in forged_ids {
        assert!(
            !destination
                .join(format!("artifact-{forged_id}-member.txt"))
                .exists()
        );
    }
    Ok(())
}

#[test]
fn zip_structure_reference_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"member.txt", b"member bytes")?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let mismatched_input =
        case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let blob = node_blob(&case, input)?;
    let structure = case.add_node(
        "archive_structure",
        Some(&blob),
        Vec::new(),
        json!({"input_node":mismatched_input,"format":"zip","archive_size":archive.len()}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The observed edge points to a different input node".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn forged_der_structure_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", b"DER input", Vec::new(), json!({}))?;
    add_parsed_structure(&mut case, input, "der_structure")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn forged_valid_der_structure_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let der = [0x30, 0x03, 0x04, 0x01, b'A'];
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &der, Vec::new(), json!({}))?;
    let blob = node_blob(&case, input)?;
    let forged_structure = case.add_node(
        "der_structure",
        Some(&blob),
        Vec::new(),
        json!({"input_node":input}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: forged_structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "This structure omits parser facts".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    assert!(case.edges().iter().any(|edge| {
        edge.from == input
            && edge.to == forged_structure
            && edge.relation == "parsed_as"
            && edge.status == EvidenceStatus::Observed
    }));
    Ok(())
}

#[test]
fn der_structure_reference_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let der = [0x30, 0x03, 0x04, 0x01, b'A'];
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &der, Vec::new(), json!({}))?;
    let mismatched_input = case.add_bytes_node("candidate_object", &der, Vec::new(), json!({}))?;
    let blob = node_blob(&case, input)?;
    let structure = case.add_node(
        "der_structure",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node":mismatched_input,
            "value_count":1,
            "boundary_range":{"offset":0,"length":der.len()}
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The observed edge points to a different input node".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    Ok(())
}

#[test]
fn member_parent_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"member.txt", b"member bytes")?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let mut expanded = expand_selected(&case, input)?;
    let mismatched_parent =
        expanded.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let member = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member")
        .ok_or("validated archive member is missing")?;
    let member_id = member.id;
    let mut member_details = member.details.clone();
    let Some(details) = member_details.as_object_mut() else {
        return Err("archive member details are not an object".into());
    };
    details.insert("archive_node".to_owned(), json!(mismatched_parent));
    let forged_member = expanded.add_bytes_node(
        "archive_member",
        b"member bytes",
        Vec::new(),
        member_details,
    )?;
    expanded.add_edge(Edge {
        from: input,
        to: forged_member,
        relation: "contains_member".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The observed edge disagrees with the member parent".to_owned(),
    })?;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(artifact_files(&destination)?.len(), 2);
    assert!(
        destination
            .join(format!("artifact-{member_id}-member.txt"))
            .is_file()
    );
    assert!(
        !destination
            .join(format!("artifact-{forged_member}-member.txt"))
            .exists()
    );
    Ok(())
}

#[test]
fn incomplete_case_reported() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node("record_object", b"retained bytes", Vec::new(), json!({}))?;
    case.mark_incomplete("Some source bytes were omitted")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Exported 1 recovered artifact file from 1 retained node"));
    assert!(stdout.contains("Evidence retention is incomplete"));
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Evidence retention: incomplete"));
    assert!(destination.join("artifact-1-record.txt").is_file());
    Ok(())
}

#[test]
fn validated_signature_extension_preserved() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let bytes = encoded_png()?;
    let record = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
    let signature = add_signature_evidence(&mut case, record, &bytes, "png")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(destination.join(format!("artifact-{record}-record.png")))?,
        bytes.as_slice()
    );
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let provenance = manifest
        .pointer("/artifacts/0/nodes/0")
        .ok_or("record provenance is missing")?;
    assert_eq!(
        provenance
            .get("extension_evidence_node")
            .and_then(Value::as_u64),
        Some(signature)
    );
    assert!(provenance.get("validation_evidence_node").is_none());
    assert_eq!(
        provenance
            .get("structural_validation_status")
            .and_then(Value::as_str),
        Some("validated")
    );
    assert_eq!(
        provenance.get("validated_as").and_then(Value::as_str),
        Some("png_structure")
    );
    Ok(())
}

#[test]
fn invalid_png_extension_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let bytes = b"\x89PNG\r\n\x1a\ntruncated";
    let record = case.add_bytes_node("record_object", bytes, Vec::new(), json!({}))?;
    let signature = add_signature_evidence(&mut case, record, bytes, "png")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(
        fs::read(destination.join(format!("artifact-{record}-record.bin")))?,
        bytes
    );
    assert!(
        !destination
            .join(format!("artifact-{record}-record.png"))
            .exists()
    );
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/extension_evidence_node"),
        Some(&Value::from(signature))
    );
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/structural_validation_status"),
        Some(&Value::from("rejected"))
    );
    assert_eq!(
        manifest.pointer("/artifacts/0/nodes/0/structural_validation_format"),
        Some(&Value::from("png_structure"))
    );
    Ok(())
}

#[test]
fn invalid_zip_extension_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let bytes = b"PK\x03\x04not a valid archive";
    let record = case.add_bytes_node("record_object", bytes, Vec::new(), json!({}))?;
    add_signature_evidence(&mut case, record, bytes, "zip")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(
        fs::read(destination.join(format!("artifact-{record}-record.bin")))?,
        bytes
    );
    assert!(
        !destination
            .join(format!("artifact-{record}-record.zip"))
            .exists()
    );
    Ok(())
}

#[test]
fn signature_tampering_excluded() -> Result<(), Box<dyn Error>> {
    for tampering in ["blob", "range", "edge"] {
        let directory = tempfile::tempdir()?;
        let mut case = Case::new();
        let bytes = encoded_png()?;
        let record = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
        let mut details = signature_details(&case, record, &bytes, "png")?;
        let mut evidence_blob = node_blob(&case, record)?;
        if tampering == "range" {
            details
                .get_mut("range")
                .and_then(Value::as_object_mut)
                .ok_or("signature range is missing")?
                .insert("length".to_owned(), json!(7));
        }
        if tampering == "blob" {
            evidence_blob = case.add_blob(b"unrelated bytes")?;
        }
        let signature = case.add_node(
            "file_signature_match",
            Some(&evidence_blob),
            Vec::new(),
            details,
        )?;
        if tampering != "edge" {
            case.add_edge(Edge {
                from: record,
                to: signature,
                relation: String::from("contains_signature"),
                status: EvidenceStatus::Observed,
                reason: String::from("Signature bytes were observed in the input object"),
            })?;
        }
        let case_path = save_case(directory.path(), "case.json", &case)?;
        let destination = directory.path().join("artifacts");

        let output = run(
            &[
                "extract-all",
                path_arg(&case_path)?,
                "--directory",
                path_arg(&destination)?,
            ],
            &[],
        )?;

        assert!(output.status.success(), "tampering: {tampering}");
        assert!(
            destination
                .join(format!("artifact-{record}-record.bin"))
                .is_file()
        );
        assert!(
            !destination
                .join(format!("artifact-{record}-record.png"))
                .exists()
        );
        let manifest: Value =
            serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
        assert!(
            manifest
                .pointer("/artifacts/0/nodes/0/extension_evidence_node")
                .is_none(),
            "tampering: {tampering}"
        );
    }
    Ok(())
}

#[test]
fn interior_signature_ignored() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let bytes = vec![0; 1024];
    let record = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
    let blob = node_blob(&case, record)?;
    case.add_node(
        "file_signature_match",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node":record,
            "ambiguous":false,
            "extensions":["h5"],
            "range":{"offset":512,"length":8}
        }),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert_eq!(
        fs::read(destination.join(format!("artifact-{record}-record.bin")))?,
        bytes
    );
    assert!(
        !destination
            .join(format!("artifact-{record}-record.h5"))
            .exists()
    );
    Ok(())
}

#[test]
fn safe_archive_names_preserved() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let archive = stored_zip(b"../../outside/\xCE\xA9.bin", b"member bytes")?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &archive, Vec::new(), json!({}))?;
    let expanded = expand_selected(&case, input)?;
    let node = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member")
        .ok_or("validated archive member is missing")?
        .id;
    let case_path = save_case(directory.path(), "case.json", &expanded)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files = artifact_files(&destination)?;
    assert_eq!(files.len(), 2);
    let expected = format!("artifact-{node}-Ω.bin");
    let file = files
        .iter()
        .find(|file| file.file_name().and_then(|name| name.to_str()) == Some(expected.as_str()))
        .ok_or("safe member name was not preserved")?;
    assert_eq!(fs::read(file)?, b"member bytes");
    assert!(!directory.path().join("outside").exists());
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("../../outside/Ω.bin"));
    Ok(())
}

#[test]
fn incomplete_evidence_excluded() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    for kind in [
        "packet",
        "tcp_run",
        "record_parse_receipt",
        "record_candidate",
        "der_value",
        "png_structure",
        "png_chunk_payload",
        "file_signature_match",
    ] {
        case.add_bytes_node(kind, kind.as_bytes(), Vec::new(), json!({}))?;
    }
    case.add_bytes_node(
        "archive_member",
        b"directory",
        Vec::new(),
        json!({
            "utf8_name":"folder/",
            "is_directory":true
        }),
    )?;
    case.add_bytes_node(
        "archive_member",
        b"link target",
        Vec::new(),
        json!({
            "utf8_name":"linked-file.txt",
            "unix_mode":0o120_777
        }),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert!(output.status.success());
    assert!(artifact_files(&destination)?.is_empty());
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Files: 0"));
    for kind in ["packet", "tcp_run", "record_candidate", "png_chunk_payload"] {
        assert!(!summary.contains(kind));
    }
    Ok(())
}

#[test]
fn existing_directory_preserved() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        b"new",
        Vec::new(),
        json!({"utf8_name":"new.txt"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("artifacts");
    fs::create_dir(&destination)?;
    fs::write(destination.join("keep.txt"), b"preserve existing data")?;

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read(destination.join("keep.txt"))?,
        b"preserve existing data"
    );
    assert_eq!(fs::read_dir(&destination)?.count(), 1);
    Ok(())
}

#[test]
fn output_traversal_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        b"new",
        Vec::new(),
        json!({"utf8_name":"new.txt"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let destination = directory.path().join("..").join("escaped-artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!destination.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn output_symlink_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        b"new",
        Vec::new(),
        json!({"utf8_name":"new.txt"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let target = directory.path().join("target");
    let destination = directory.path().join("artifacts-link");
    fs::create_dir(&target)?;
    fs::write(target.join("keep.txt"), b"preserve")?;
    symlink(&target, &destination)?;

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(target.join("keep.txt"))?, b"preserve");
    assert_eq!(fs::read_dir(&target)?.count(), 1);
    assert!(fs::symlink_metadata(destination)?.file_type().is_symlink());
    Ok(())
}

#[cfg(unix)]
#[test]
fn parent_symlink_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        b"new",
        Vec::new(),
        json!({"utf8_name":"new.txt"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let target = directory.path().join("target");
    let link = directory.path().join("target-link");
    fs::create_dir(&target)?;
    symlink(&target, &link)?;
    let destination = link.join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!target.join("artifacts").exists());
    assert_eq!(fs::read_dir(target)?.count(), 0);
    Ok(())
}

#[test]
fn invalid_case_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let case_path = directory.path().join("invalid.json");
    fs::write(&case_path, b"not a case")?;
    let destination = directory.path().join("artifacts");

    let output = run(
        &[
            "extract-all",
            path_arg(&case_path)?,
            "--directory",
            path_arg(&destination)?,
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!destination.exists());
    Ok(())
}

fn node_blob(case: &Case, node_id: u64) -> Result<String, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.id == node_id)
        .and_then(|node| node.blob.clone())
        .ok_or_else(|| "node blob is missing".into())
}

fn signature_details(
    case: &Case,
    input_node: u64,
    bytes: &[u8],
    extension: &str,
) -> Result<Value, Box<dyn Error>> {
    let report = l2_workbench::artifact::scan_file_signatures(bytes);
    let signature = report
        .matches
        .iter()
        .find(|signature| signature.extensions.contains(&extension))
        .ok_or("requested signature is not present")?;
    let mut details = serde_json::to_value(signature)?;
    let object = details
        .as_object_mut()
        .ok_or("signature details are not an object")?;
    object.insert("input_node".to_owned(), json!(input_node));
    object.insert("input_sha256".to_owned(), json!(report.source_sha256));
    object.insert("input_blob".to_owned(), json!(node_blob(case, input_node)?));
    object.insert(
        "coordinate_base".to_owned(),
        json!("zero_based_from_byte_0_of_input_blob"),
    );
    object.insert(
        "unproven".to_owned(),
        json!([
            "complete_file_boundary",
            "structural_validity",
            "container_subtype",
            "delivery",
            "execution",
            "malicious_intent"
        ]),
    );
    Ok(details)
}

fn add_signature_evidence(
    case: &mut Case,
    input_node: u64,
    bytes: &[u8],
    extension: &str,
) -> Result<u64, Box<dyn Error>> {
    let input_blob = node_blob(case, input_node)?;
    let details = signature_details(case, input_node, bytes, extension)?;
    let signature = case.add_node(
        "file_signature_match",
        Some(&input_blob),
        Vec::new(),
        details,
    )?;
    case.add_edge(Edge {
        from: input_node,
        to: signature,
        relation: String::from("contains_signature"),
        status: EvidenceStatus::Observed,
        reason: String::from("Signature bytes were observed in the input object"),
    })?;
    Ok(signature)
}

fn artifact_files(directory: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("artifact-"))
        {
            files.push(path);
        }
    }
    Ok(files)
}

fn encoded_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&[1, 2, 3])?;
    Ok(bytes)
}

fn expand_selected(case: &Case, node: u64) -> Result<Case, Box<dyn Error>> {
    let output = run(
        &["expand", "-", "--node", &node.to_string()],
        &case.to_json()?,
    )?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(Case::from_json(&output.stdout)?)
}
