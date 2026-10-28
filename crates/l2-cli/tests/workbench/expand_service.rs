use super::{ExpansionError, ExpansionFailureKind, ExpansionLimits, ExpansionService};
use l2_workbench::evidence::{Case, EvidenceStatus};
use serde_json::json;
use std::error::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[test]
fn service_expands_valid_png() -> Result<(), Box<dyn Error>> {
    let bytes = png(&[])?;
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let outcome = service.expand_selected(root)?;

    assert!(outcome.complete);
    assert!(outcome.rejections.is_empty());
    assert!(outcome.created_nodes.iter().any(|id| {
        service
            .case()
            .nodes()
            .iter()
            .any(|node| node.id == *id && node.kind == "png_structure")
    }));
    Ok(())
}

#[test]
fn strict_rejects_root() -> Result<(), Box<dyn Error>> {
    let bytes = invalid_png();
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let result = service.expand_selected(root);

    assert!(matches!(
        result,
        Err(ExpansionError::Rejected(ref rejection))
            if rejection.node == root && rejection.format == "png"
    ));
    Ok(())
}

#[test]
fn probe_records_rejection() -> Result<(), Box<dyn Error>> {
    let bytes = invalid_png();
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let strict_result = service.expand_selected(root);
    assert!(matches!(
        strict_result,
        Err(ExpansionError::Rejected(ref rejection)) if rejection.node == root
    ));

    let outcome = service.probe_candidate(root)?;

    assert!(outcome.complete);
    assert!(service.case().collection_complete());
    assert_eq!(outcome.rejections.len(), 1);
    let rejection = outcome
        .rejections
        .first()
        .ok_or("candidate rejection is missing")?;
    assert_eq!(rejection.node, root);
    assert_eq!(rejection.format, "png");
    let issue = service
        .case()
        .nodes()
        .iter()
        .find(|node| node.kind == "artifact_parse_issue")
        .ok_or("parse issue node is missing")?;
    assert_eq!(issue.details.get("parent_node"), Some(&json!(root)));
    assert!(service.case().edges().iter().any(|edge| {
        edge.from == root
            && edge.to == issue.id
            && edge.relation == "failed_to_parse"
            && edge.status == EvidenceStatus::ConstraintFailed
    }));
    Ok(())
}

#[test]
fn probe_continues_after_corruption() -> Result<(), Box<dyn Error>> {
    let corrupt = corrupt_png_crc()?;
    let valid = [0x30, 0x03, 0x04, 0x01, b'x'];
    let mut case = Case::new();
    let corrupt_root = add_candidate(&mut case, &corrupt)?;
    let valid_root = add_candidate(&mut case, &valid)?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let rejected = service.probe_candidate(corrupt_root)?;
    let expanded = service.probe_candidate(valid_root)?;

    assert_eq!(rejected.rejections.len(), 1);
    assert!(rejected.complete);
    assert!(expanded.complete);
    let structure = service
        .case()
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "der_structure"
                && node.details.get("input_node") == Some(&json!(valid_root))
        })
        .ok_or("valid candidate was not expanded after the rejected candidate")?;
    assert!(expanded.created_nodes.contains(&structure.id));
    assert!(service.case().edges().iter().any(|edge| {
        edge.from == valid_root && edge.to == structure.id && edge.relation == "parsed_as"
    }));
    Ok(())
}

#[test]
fn nested_rejections_stay_complete() -> Result<(), Box<dyn Error>> {
    let embedded = invalid_png();
    let bytes = png(&[(*b"thMb", embedded.as_slice())])?;
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let outcome = service.expand_selected(root)?;

    assert!(outcome.complete);
    assert!(service.case().collection_complete());
    assert_eq!(outcome.rejections.len(), 1);
    assert!(
        service
            .case()
            .nodes()
            .iter()
            .any(|node| node.kind == "artifact_parse_issue")
    );
    Ok(())
}

#[test]
fn prior_omissions_stay_incomplete() -> Result<(), Box<dyn Error>> {
    let bytes = invalid_png();
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    case.mark_incomplete("earlier resource omission")?;
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let outcome = service.probe_candidate(root)?;

    assert!(outcome.complete);
    assert!(!service.case().collection_complete());
    Ok(())
}

#[test]
fn resource_omission_marks_incomplete() -> Result<(), Box<dyn Error>> {
    let bytes = png(&[])?;
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut configured = limits();
    configured.objects = 1;
    let mut service = ExpansionService::new(&mut case, configured, None);

    let outcome = service.expand_selected(root)?;

    assert!(!outcome.complete);
    assert!(!service.case().collection_complete());
    assert!(outcome.rejections.is_empty());
    assert!(outcome.created_nodes.iter().any(|id| {
        service.case().nodes().iter().any(|node| {
            node.id == *id
                && node.kind == "artifact_expansion_omission"
                && node.details.get("reason") == Some(&json!("png_chunk_limit"))
        })
    }));
    Ok(())
}

#[test]
fn invalid_limits_remain_failures() -> Result<(), Box<dyn Error>> {
    let bytes = png(&[])?;
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let mut configured = limits();
    configured.objects = 0;
    let mut service = ExpansionService::new(&mut case, configured, None);

    let result = service.probe_candidate(root);

    assert!(matches!(
        result,
        Err(ExpansionError::Failure(failure))
            if failure.kind == ExpansionFailureKind::Invariant
    ));
    assert!(
        !service
            .case()
            .nodes()
            .iter()
            .any(|node| node.kind == "artifact_parse_issue")
    );
    Ok(())
}

#[test]
fn created_nodes_keep_provenance() -> Result<(), Box<dyn Error>> {
    let bytes = png(&[])?;
    let mut case = Case::new();
    let root = add_candidate(&mut case, &bytes)?;
    let input_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == root)
        .and_then(|node| node.blob.as_deref())
        .ok_or("input blob is missing")?
        .to_owned();
    let mut service = ExpansionService::new(&mut case, limits(), None);

    let outcome = service.expand_selected(root)?;

    let structure = service
        .case()
        .nodes()
        .iter()
        .find(|node| node.kind == "png_structure")
        .ok_or("PNG structure node is missing")?;
    assert!(outcome.created_nodes.contains(&structure.id));
    assert_eq!(structure.blob.as_deref(), Some(input_blob.as_str()));
    assert_eq!(structure.details.get("input_node"), Some(&json!(root)));
    let parsed_as = service
        .case()
        .edges()
        .iter()
        .find(|edge| edge.from == root && edge.to == structure.id && edge.relation == "parsed_as")
        .ok_or("input-to-structure provenance edge is missing")?;
    assert_eq!(parsed_as.status, EvidenceStatus::Observed);
    Ok(())
}

fn add_candidate(case: &mut Case, bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node("candidate_object", bytes, Vec::new(), json!({}))?)
}

fn limits() -> ExpansionLimits {
    ExpansionLimits {
        depth: 8,
        objects: 64,
        input_bytes: 4096,
        archive_entries: 64,
        member_bytes: 4096,
        zip_work_bytes: 4096,
        retained_bytes: 4096,
    }
}

fn invalid_png() -> Vec<u8> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    bytes.extend_from_slice(b"broken chunk data");
    bytes
}

fn corrupt_png_crc() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = png(&[])?;
    let checksum_byte = bytes.get_mut(32).ok_or("PNG checksum byte is missing")?;
    *checksum_byte ^= 1;
    Ok(bytes)
}

fn png(extra: &[([u8; 4], &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    let mut header = [0_u8; 13];
    header[..4].copy_from_slice(&1_u32.to_be_bytes());
    header[4..8].copy_from_slice(&1_u32.to_be_bytes());
    header[8..13].copy_from_slice(&[8, 2, 0, 0, 0]);
    add_chunk(&mut bytes, *b"IHDR", &header)?;
    for (kind, data) in extra {
        add_chunk(&mut bytes, *kind, data)?;
    }
    add_chunk(&mut bytes, *b"IEND", &[])?;
    Ok(bytes)
}

fn add_chunk(output: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) -> Result<(), Box<dyn Error>> {
    output.extend_from_slice(&u32::try_from(data.len())?.to_be_bytes());
    output.extend_from_slice(&kind);
    output.extend_from_slice(data);
    let checksum = crc32fast::hash(&[kind.as_slice(), data].concat());
    output.extend_from_slice(&checksum.to_be_bytes());
    Ok(())
}
