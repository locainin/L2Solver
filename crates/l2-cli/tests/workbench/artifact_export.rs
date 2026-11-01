use std::{
    collections::{HashMap, HashSet},
    io,
    path::Path,
};

use l2_workbench::{
    artifact::{
        ArtifactValidationFormat, ArtifactValidator,
        zip::{ZipArtifactEntry, ZipArtifactEntryMetadata, ZipArtifactReport},
    },
    evidence::{Case, Edge, EvidenceStatus},
};
use serde_json::json;

#[test]
fn rejects_unsafe_file_name_with_invalid_input_error() -> Result<(), Box<dyn std::error::Error>> {
    let error = super::validate_flat_file_name("nested/name")
        .err()
        .ok_or("unsafe artifact file name should be rejected")?;

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "artifact file name must be a safe flat name"
    );
    Ok(())
}

#[test]
fn shared_large_record_blob_is_classified_once_and_keeps_every_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let mut case = Case::new();
    let bytes = vec![b'a'; 2 * 1024 * 1024];
    let first = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
    let blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == first)
        .and_then(|node| node.blob.as_deref())
        .ok_or("record blob is missing")?
        .to_owned();
    for _ in 0..63 {
        case.add_node("record_object", Some(&blob_id), Vec::new(), json!({}))?;
    }

    let mut work = super::SelectionWorkCache::default();
    let selected = super::select_artifacts_with_cache(&case, &mut work)?;

    assert_eq!(selected.len(), 1);
    let artifact = selected
        .first()
        .ok_or("shared record artifact is missing")?;
    assert_eq!(artifact.bytes(), bytes);
    assert_eq!(artifact.provenance().len(), 64);
    assert!(
        Path::new(artifact.file_name())
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
    );
    assert_eq!(
        artifact
            .provenance()
            .iter()
            .map(|origin| origin.id)
            .collect::<Vec<_>>(),
        case.nodes().iter().map(|node| node.id).collect::<Vec<_>>()
    );
    assert_eq!(work.counts.text_classifications, 1);
    Ok(())
}

#[test]
fn selected_artifact_identity_matches_its_canonical_case_blob_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"selected content with a stable identity";
    let mut case = Case::new();
    let node_id = case.add_bytes_node("record_object", bytes, Vec::new(), json!({}))?;
    let blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("selected object blob is missing")?;
    let selected = super::select_artifacts(&case)?;
    let artifact = selected.first().ok_or("selected artifact is missing")?;

    assert_eq!(artifact.bytes(), bytes);
    assert_eq!(
        artifact.sha256(),
        blob_id
            .strip_prefix("sha256:")
            .ok_or("blob ID is not canonical")?
    );
    assert_eq!(artifact.sha256(), l2_workbench::sha256(bytes));
    Ok(())
}

#[test]
fn ordinary_selection_keeps_compatible_signature_evidence_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&[1, 2, 3])?;

    let mut case = Case::new();
    let record = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
    let record_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == record)
        .and_then(|node| node.blob.clone())
        .ok_or("record blob is missing")?;
    let signature_report = l2_workbench::artifact::scan_file_signatures(&bytes);
    let signature_match = signature_report
        .matches
        .iter()
        .find(|matched| matched.extensions.contains(&"png"))
        .ok_or("PNG signature match is missing")?;
    let mut signature_details = serde_json::to_value(signature_match)?;
    let details = signature_details
        .as_object_mut()
        .ok_or("signature details are not an object")?;
    details.insert("input_node".to_owned(), json!(record));
    details.insert(
        "input_sha256".to_owned(),
        json!(signature_report.source_sha256),
    );
    details.insert("input_blob".to_owned(), json!(record_blob));
    details.insert(
        "coordinate_base".to_owned(),
        json!("zero_based_from_byte_0_of_input_blob"),
    );
    let signature = case.add_node(
        "file_signature_match",
        Some(&record_blob),
        Vec::new(),
        signature_details,
    )?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: record,
        to: signature,
        relation: String::from("contains_signature"),
        status: EvidenceStatus::Observed,
        reason: String::from("Signature bytes were observed in the input object"),
    })?;

    let selected = super::select_artifacts(&case)?;
    let artifact = selected.first().ok_or("PNG record was not selected")?;
    let provenance = artifact
        .provenance()
        .first()
        .ok_or("artifact provenance is missing")?;

    assert!(
        Path::new(artifact.file_name())
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
    );
    assert_eq!(provenance.extension_evidence_node, Some(signature));
    assert_eq!(provenance.validated_as(), Some("png_structure"));
    Ok(())
}

#[test]
fn arbitrary_record_details_cannot_promote_garbage_to_validated_png()
-> Result<(), Box<dyn std::error::Error>> {
    use super::StructuralValidationStatus;

    let bytes = [0xff, 0x00, b'n', b'o', b't'];
    let mut case = Case::new();
    case.add_bytes_node(
        "record_object",
        &bytes,
        Vec::new(),
        json!({
            "analysis_validation": {
                "state": "validated",
                "format": "png",
                "boundary": "png_iend",
                "range": {"offset": 0, "length": bytes.len()}
            },
            "extension": "png"
        }),
    )?;
    let selected = super::select_artifacts(&case)?;
    let artifact = selected.first().ok_or("garbage record was not selected")?;

    assert!(
        Path::new(artifact.file_name())
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("bin"))
    );
    assert_eq!(
        artifact
            .provenance()
            .first()
            .ok_or("artifact provenance is missing")?
            .structural_validation
            .status(),
        StructuralValidationStatus::NotChecked
    );
    Ok(())
}

#[test]
fn analyzer_receipt_for_another_blob_cannot_promote_garbage_to_validated_png()
-> Result<(), Box<dyn std::error::Error>> {
    use super::{AnalyzerValidationReceipt, StructuralValidationStatus};
    use l2_workbench::artifact::{
        AnalysisBoundary, AnalysisFormat, ArtifactValidationState, FileRange, ValidationSummary,
    };

    let bytes = [0xff, 0x00, b'n', b'o', b't'];
    let mismatches = [
        (
            l2_workbench::sha256(b"different validated PNG bytes"),
            FileRange {
                offset: 0,
                length: bytes.len(),
            },
            AnalysisBoundary::PngIend,
        ),
        (
            l2_workbench::sha256(&bytes),
            FileRange {
                offset: 1,
                length: bytes.len() - 1,
            },
            AnalysisBoundary::PngIend,
        ),
        (
            l2_workbench::sha256(&bytes),
            FileRange {
                offset: 0,
                length: bytes.len(),
            },
            AnalysisBoundary::ZipEndRecord,
        ),
    ];

    for (sha256, range, boundary) in mismatches {
        let mut case = Case::new();
        let node_id = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
        let receipt = AnalyzerValidationReceipt::new(
            node_id,
            &sha256,
            bytes.len(),
            ValidationSummary {
                state: ArtifactValidationState::Validated,
                format: Some(AnalysisFormat::Png),
                boundary: Some(boundary),
                range: Some(range),
                structure_count: 3,
            },
        );
        let selected = super::select_artifacts_with_analyzer_receipts(&case, &[receipt])?;
        let artifact = selected.first().ok_or("garbage record was not selected")?;

        assert!(
            Path::new(artifact.file_name())
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("bin"))
        );
        assert_eq!(
            artifact
                .provenance()
                .first()
                .ok_or("artifact provenance is missing")?
                .structural_validation
                .status(),
            StructuralValidationStatus::NotChecked,
            "analyzer receipt mismatch {boundary:?} cannot validate this blob"
        );
    }
    Ok(())
}

#[test]
fn repeated_validation_is_cached_once_per_blob_and_format() -> Result<(), Box<dyn std::error::Error>>
{
    let validator = ArtifactValidator::default();
    let bytes = b"small arbitrary content";
    let mut case = Case::new();
    let node_id = case.add_bytes_node("candidate_object", bytes, Vec::new(), json!({}))?;
    let blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("validation blob is missing")?;
    let mut work = super::SelectionWorkCache::default();

    for format in [
        ArtifactValidationFormat::Der,
        ArtifactValidationFormat::Png,
        ArtifactValidationFormat::Zip,
    ] {
        work.validate_as(&validator, blob_id, format, bytes);
        work.validate_as(&validator, blob_id, format, bytes);
    }

    assert_eq!(work.counts.validation_calls, 3);
    assert_eq!(work.counts.validation_cache_hits, 3);
    Ok(())
}

#[test]
fn duplicate_der_structure_evidence_reuses_the_parsed_blob()
-> Result<(), Box<dyn std::error::Error>> {
    let mut case = Case::new();
    let der = [0x30, 0x03, 0x04, 0x01, b'A'];
    let input = case.add_bytes_node("candidate_object", &der, Vec::new(), json!({}))?;
    let blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == input)
        .and_then(|node| node.blob.as_deref())
        .ok_or("DER blob is missing")?
        .to_owned();
    let l2_workbench::artifact::ArtifactValidationOutcome::Validated {
        structure: l2_workbench::artifact::ArtifactStructure::Der(report),
        ..
    } = ArtifactValidator::default().validate_as(ArtifactValidationFormat::Der, &der)
    else {
        return Err("test DER did not validate".into());
    };
    for _ in 0..4 {
        let structure = case.add_node(
            "der_structure",
            Some(&blob_id),
            Vec::new(),
            json!({
                "input_node": input,
                "depth": 1,
                "value_count": report.nodes.len(),
                "boundary_range": {"offset": 0, "length": der.len()}
            }),
        )?;
        case.add_edge(Edge {
            from: input,
            to: structure,
            relation: "parsed_as".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "DER structure was parsed".to_owned(),
        })?;
    }

    let mut work = super::SelectionWorkCache::default();
    let selected = super::select_artifacts_with_cache(&case, &mut work)?;

    assert_eq!(selected.len(), 1);
    let artifact = selected
        .first()
        .ok_or("validated DER artifact is missing")?;
    assert_eq!(artifact.provenance().len(), 1);
    assert_eq!(
        artifact
            .provenance()
            .first()
            .ok_or("validated DER provenance is missing")?
            .validated_as(),
        Some("der_structure")
    );
    assert_eq!(work.counts.validation_calls, 1);
    assert_eq!(work.counts.validation_cache_hits, 3);
    Ok(())
}

#[test]
fn final_zip_member_uses_indexed_entry_lookup_with_the_same_export_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let final_index = 31;
    let report = synthetic_zip_report(final_index + 1)?;
    let ZipMemberCase {
        case,
        archive_id,
        structure_id,
        member_ids,
    } = case_with_zip_members(&report)?;
    let final_member_id = member_ids
        .get(final_index)
        .copied()
        .ok_or("final ZIP member node is missing")?;
    let structure = case
        .nodes()
        .iter()
        .find(|node| node.id == structure_id)
        .ok_or("archive structure is missing")?;
    let members: Vec<_> = case
        .nodes()
        .iter()
        .filter(|node| member_ids.contains(&node.id))
        .collect();
    let members_by_archive = HashMap::from([(archive_id, members)]);
    let contains_member_edges: HashSet<_> = member_ids
        .iter()
        .map(|member_id| (archive_id, *member_id))
        .collect();
    let bytes_by_id: HashMap<&str, &[u8]> = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect();
    let mut specs = HashMap::new();

    super::add_validated_archive_members(
        archive_id,
        &[structure],
        &members_by_archive,
        &contains_member_edges,
        &report,
        &bytes_by_id,
        &mut specs,
    );

    assert_eq!(specs.len(), report.entries.len());
    let selected = specs
        .get(&final_member_id)
        .ok_or("final ZIP member was not selected")?;
    let selected_path = Path::new(&selected.file_name);
    let expected_stem = format!("artifact-{final_member_id}-final");
    assert_eq!(
        selected_path.file_stem().and_then(std::ffi::OsStr::to_str),
        Some(expected_stem.as_str())
    );
    assert!(
        selected_path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
    );
    let archive_path = Path::new(
        selected
            .archive_path
            .as_deref()
            .ok_or("final ZIP member path is missing")?,
    );
    assert_eq!(archive_path.parent().and_then(Path::to_str), Some("folder"));
    assert_eq!(
        archive_path.file_stem().and_then(std::ffi::OsStr::to_str),
        Some("final")
    );
    assert!(
        archive_path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
    );
    assert_eq!(
        selected.structural_validation.status(),
        super::StructuralValidationStatus::Validated
    );
    Ok(())
}

fn synthetic_zip_report(
    member_count: usize,
) -> Result<ZipArtifactReport, Box<dyn std::error::Error>> {
    let final_index = member_count
        .checked_sub(1)
        .ok_or("test ZIP needs at least one member")?;
    let entries = (0..member_count)
        .map(|index| {
            let content = format!("member-{index} bytes").into_bytes();
            let raw_name = if index == final_index {
                b"folder/final.txt".to_vec()
            } else {
                format!("folder/member-{index}.bin").into_bytes()
            };
            let content_length = u64::try_from(content.len())?;
            Ok(ZipArtifactEntry {
                metadata: ZipArtifactEntryMetadata {
                    index,
                    raw_name,
                    is_directory: false,
                    compression_method: 0,
                    encrypted: false,
                    compressed_size: content_length,
                    expanded_size: content_length,
                    crc32: 0,
                    local_header_offset: u64::try_from(index)?,
                    unix_mode: None,
                },
                content: Some(content),
                omission: None,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let expanded_bytes = entries
        .iter()
        .filter_map(|entry| entry.content.as_ref())
        .map(Vec::len)
        .sum();
    Ok(ZipArtifactReport {
        archive_sha256: String::new(),
        archive_size: 0,
        depth: 0,
        entry_count: entries.len(),
        extracted_entry_count: entries.len(),
        expanded_byte_count: expanded_bytes,
        expanded_work_byte_count: expanded_bytes,
        omitted_entry_count: 0,
        entries,
        omissions: Vec::new(),
    })
}

struct ZipMemberCase {
    case: Case,
    archive_id: u64,
    structure_id: u64,
    member_ids: Vec<u64>,
}

fn case_with_zip_members(
    report: &ZipArtifactReport,
) -> Result<ZipMemberCase, Box<dyn std::error::Error>> {
    let mut case = Case::new();
    let archive_id = case.add_bytes_node("candidate_object", b"archive", Vec::new(), json!({}))?;
    let archive_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == archive_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("archive blob is missing")?
        .to_owned();
    let structure_id = case.add_node(
        "archive_structure",
        Some(&archive_blob),
        Vec::new(),
        json!({}),
    )?;
    let mut member_ids = Vec::with_capacity(report.entries.len());
    for entry in &report.entries {
        let metadata = &entry.metadata;
        let member_bytes = entry
            .content
            .as_deref()
            .ok_or("test ZIP member content is missing")?;
        let raw_name_preview = super::encode_hex(&metadata.raw_name);
        let utf8_name = String::from_utf8(metadata.raw_name.clone())?;
        member_ids.push(case.add_bytes_node(
            "archive_member",
            member_bytes,
            Vec::new(),
            json!({
                "archive_node": archive_id,
                "structure_node": structure_id,
                "entry_index": metadata.index,
                "raw_name_length": metadata.raw_name.len(),
                "raw_name_sha256": l2_workbench::sha256(&metadata.raw_name),
                "raw_name_hex": raw_name_preview,
                "raw_name_truncated": false,
                "is_directory": metadata.is_directory,
                "compression_method": metadata.compression_method,
                "encrypted": metadata.encrypted,
                "unix_mode": metadata.unix_mode,
                "utf8_name": utf8_name,
                "compressed_size": metadata.compressed_size,
                "expanded_size": metadata.expanded_size,
                "crc32": metadata.crc32,
                "local_header_offset": metadata.local_header_offset
            }),
        )?);
    }
    Ok(ZipMemberCase {
        case,
        archive_id,
        structure_id,
        member_ids,
    })
}
