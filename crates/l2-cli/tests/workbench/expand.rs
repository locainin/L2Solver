use super::support::{path_arg, run, save_case, stored_zip, stored_zip_entries};
use crc32fast::hash as crc32;
use l2_workbench::evidence::Case;
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error, fs};

#[test]
fn expand_recovers_trailer_der_values() -> Result<(), Box<dyn Error>> {
    let der = [
        0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x04, 0x03, b'a', b'b', b'c',
    ];
    let mut nested_png = png(&[]);
    nested_png.extend_from_slice(&der);
    let outer_png = png(&[(*b"thMb", nested_png.as_slice())]);
    let archive = stored_zip(b"media/sample.png", &outer_png)?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &archive,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let member = find_node(&result, "archive_member")?;
    assert_eq!(
        member.details.get("raw_name_hex"),
        Some(&Value::String(
            "6d656469612f73616d706c652e706e67".to_owned()
        ))
    );
    assert_eq!(
        result
            .nodes()
            .iter()
            .filter(|node| node.kind == "png_structure")
            .count(),
        2
    );
    let embedded_png = result
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "png_structure"
                && node.details.get("bytes_after_iend") == Some(&serde_json::json!(der.len()))
        })
        .ok_or("missing embedded PNG structure")?;
    assert_eq!(blob_bytes(&result, embedded_png)?, png(&[]));
    assert_eq!(
        embedded_png.details.get("iend_end_offset"),
        Some(&serde_json::json!(blob_bytes(&result, embedded_png)?.len()))
    );
    let trailer = find_node(&result, "png_trailing_data")?;
    assert_eq!(blob_bytes(&result, trailer)?, der);
    assert!(result.nodes().iter().any(|node| {
        node.kind == "der_value"
            && node.details.get("oid") == Some(&Value::String("1.2.3".to_owned()))
    }));
    let octets = result
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "der_value"
                && node.details.get("tag_number") == Some(&serde_json::json!(4))
        })
        .ok_or("missing DER octet string")?;
    assert_eq!(blob_bytes(&result, octets)?, b"abc");
    assert!(result.edges().iter().any(|edge| {
        edge.from == input && edge.to == member.id && edge.relation == "contains_member"
    }));
    Ok(())
}

#[test]
fn expand_scopes_png_evidence_performed() -> Result<(), Box<dyn Error>> {
    // A structural scan deliberately accepts this signature-to-IEND envelope without image data
    let image = png(&[]);
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &image,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let structure = find_node(&result, "png_structure")?;
    let edge = result
        .edges()
        .iter()
        .find(|edge| edge.from == input && edge.to == structure.id && edge.relation == "parsed_as")
        .ok_or("PNG structure edge is missing")?;
    assert_eq!(
        edge.reason,
        "The retained bytes have the PNG signature, checked chunk boundaries and type-code bits, matching chunk CRCs, one leading 13-byte IHDR, and an empty IEND; image-data validity was not tested"
    );
    assert!(!edge.reason.contains("valid PNG"));
    assert!(!edge.reason.contains("valid chunk sequence"));
    Ok(())
}

#[test]
fn expand_not_real_canonical_der() -> Result<(), Box<dyn Error>> {
    let invalid_real = [0x09, 0x01, 0xff];
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &invalid_real,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    assert!(
        !result
            .nodes()
            .iter()
            .any(|node| node.kind == "der_structure")
    );
    Ok(())
}

#[test]
fn expand_depth_malformed_anchored_formats() -> Result<(), Box<dyn Error>> {
    let inner = stored_zip(b"payload.bin", b"payload")?;
    let outer = stored_zip(b"nested.zip", &inner)?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &outer,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let limited = run(
        &[
            "expand",
            "-",
            "--node",
            &input.to_string(),
            "--max-depth",
            "0",
        ],
        &case.to_json()?,
    )?;
    assert_eq!(limited.status.code(), Some(3));
    let result = Case::from_json(&limited.stdout)?;
    assert!(!result.collection_complete());
    assert!(result.nodes().iter().any(|node| {
        node.kind == "artifact_expansion_omission"
            && node.details.get("reason") == Some(&Value::String("depth_limit".to_owned()))
    }));

    let mut malformed_case = Case::new();
    let malformed = malformed_case.add_bytes_node(
        "candidate_object",
        b"\x89PNG\r\n\x1a\ntruncated",
        Vec::new(),
        serde_json::json!({}),
    )?;
    let rejected = run(
        &["expand", "-", "--node", &malformed.to_string()],
        &malformed_case.to_json()?,
    )?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("PNG"));
    Ok(())
}

#[test]
fn nested_zip_budget_completes() -> Result<(), Box<dyn Error>> {
    let payload = b"ordinary nested member";
    let inner = stored_zip(b"payload.bin", payload)?;
    let outer = stored_zip(b"nested.zip", &inner)?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &outer,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expanded = Case::from_json(&output.stdout)?;
    assert!(expanded.collection_complete());
    let member = find_byte_node(&expanded, "archive_member", payload)
        .ok_or("nested ZIP member bytes are missing")?;
    assert_eq!(blob_bytes(&expanded, member)?, payload);
    Ok(())
}

#[test]
fn nested_outputs_keep_order_and_provenance() -> Result<(), Box<dyn Error>> {
    const NESTED_ARCHIVES: usize = 48;

    let nested_archives = nested_archive_fixtures(NESTED_ARCHIVES)?;
    let outer_entries = nested_archives
        .iter()
        .map(|fixture| (fixture.name.as_slice(), fixture.archive.as_slice()))
        .collect::<Vec<_>>();
    let outer = stored_zip_entries(&outer_entries)?;
    let mut case = Case::new();
    let root = case.add_bytes_node("candidate_object", &outer, Vec::new(), json!({}))?;
    let output = run(
        &["expand", "-", "--node", &root.to_string()],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expanded = Case::from_json(&output.stdout)?;
    assert!(expanded.collection_complete());
    assert_nested_outputs(&expanded, root, &nested_archives)
}

fn nested_archive_fixtures(count: usize) -> Result<Vec<NestedArchiveFixture>, Box<dyn Error>> {
    let mut fixtures = Vec::with_capacity(count);
    for index in 0..count {
        let name = format!("nested-{index:02}.zip").into_bytes();
        let payload_name = format!("payload-{index:02}.bin").into_bytes();
        let payload = format!("nested payload {index:02}").into_bytes();
        let archive = stored_zip(&payload_name, &payload)?;
        fixtures.push(NestedArchiveFixture {
            name,
            payload_name,
            payload,
            archive,
        });
    }
    Ok(fixtures)
}

#[track_caller]
fn assert_nested_outputs(
    expanded: &Case,
    root: u64,
    fixtures: &[NestedArchiveFixture],
) -> Result<(), Box<dyn Error>> {
    let outer_members = expanded
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "archive_member" && node.details.get("archive_node") == Some(&json!(root))
        })
        .collect::<Vec<_>>();
    assert_eq!(outer_members.len(), fixtures.len());
    let structures_by_input = expanded
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_structure")
        .filter_map(|node| {
            node.details
                .get("input_node")
                .and_then(Value::as_u64)
                .map(|input| (input, node))
        })
        .collect::<HashMap<_, _>>();
    let nested_members_by_archive = expanded
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "archive_member" && node.details.get("archive_node") != Some(&json!(root))
        })
        .filter_map(|node| {
            node.details
                .get("archive_node")
                .and_then(Value::as_u64)
                .map(|archive| (archive, node))
        })
        .collect::<HashMap<_, _>>();
    let edges_by_identity = expanded
        .edges()
        .iter()
        .map(|edge| ((edge.from, edge.to, edge.relation.as_str()), edge.status))
        .collect::<HashMap<_, _>>();
    assert_eq!(structures_by_input.len(), fixtures.len() + 1);
    assert_eq!(nested_members_by_archive.len(), fixtures.len());
    for (member, fixture) in outer_members.iter().zip(fixtures) {
        assert_eq!(
            member.details.get("utf8_name"),
            Some(&json!(String::from_utf8_lossy(&fixture.name).into_owned()))
        );
        assert_eq!(blob_bytes(expanded, member)?, fixture.archive);
        assert_eq!(
            edges_by_identity.get(&(root, member.id, "contains_member")),
            Some(&l2_workbench::evidence::EvidenceStatus::Observed)
        );

        let nested_structure = structures_by_input
            .get(&member.id)
            .copied()
            .ok_or("nested archive structure is missing")?;
        assert_eq!(
            edges_by_identity.get(&(member.id, nested_structure.id, "parsed_as")),
            Some(&l2_workbench::evidence::EvidenceStatus::Observed)
        );

        let leaf = nested_members_by_archive
            .get(&member.id)
            .copied()
            .ok_or("nested archive member is missing")?;
        assert_eq!(
            leaf.details.get("utf8_name"),
            Some(&json!(
                String::from_utf8_lossy(&fixture.payload_name).into_owned()
            ))
        );
        assert_eq!(blob_bytes(expanded, leaf)?, fixture.payload);
        assert_eq!(
            edges_by_identity.get(&(member.id, leaf.id, "contains_member")),
            Some(&l2_workbench::evidence::EvidenceStatus::Observed)
        );
    }
    Ok(())
}

struct NestedArchiveFixture {
    name: Vec<u8>,
    payload_name: Vec<u8>,
    payload: Vec<u8>,
    archive: Vec<u8>,
}

#[test]
fn duplicate_paths_keep_provenance() -> Result<(), Box<dyn Error>> {
    let payload = b"identical nested member bytes";
    let expanded = expand_duplicate_nested_archives(payload)?;
    let leaf_ids = assert_nested_duplicate_paths(&expanded, payload)?;
    assert_exported_duplicate_payload(
        &expanded,
        payload,
        &leaf_ids,
        &["left/leaf.txt", "right/leaf.txt"],
    )
}

fn expand_duplicate_nested_archives(payload: &[u8]) -> Result<Case, Box<dyn Error>> {
    let left_archive = stored_zip(b"left/leaf.txt", payload)?;
    let right_archive = stored_zip(b"right/leaf.txt", payload)?;
    let outer =
        stored_zip_entries(&[(b"left.zip", &left_archive), (b"right.zip", &right_archive)])?;
    let mut case = Case::new();
    let root = case.add_bytes_node("candidate_object", &outer, Vec::new(), json!({}))?;
    let output = run(
        &["expand", "-", "--node", &root.to_string()],
        &case.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expanded = Case::from_json(&output.stdout)?;
    assert!(expanded.collection_complete());
    assert_nested_archive_parents(&expanded, root, &left_archive, &right_archive)?;
    Ok(expanded)
}

fn assert_nested_archive_parents(
    case: &Case,
    root: u64,
    left_archive: &[u8],
    right_archive: &[u8],
) -> Result<[u64; 2], Box<dyn Error>> {
    let left = archive_member_named(case, "left.zip")?;
    let right = archive_member_named(case, "right.zip")?;
    assert_ne!(left.id, right.id);
    assert_eq!(blob_bytes(case, left)?, left_archive);
    assert_eq!(blob_bytes(case, right)?, right_archive);
    assert_contains_member_edge(case, root, left.id);
    assert_contains_member_edge(case, root, right.id);
    Ok([left.id, right.id])
}

fn archive_member_named<'a>(
    case: &'a Case,
    name: &str,
) -> Result<&'a l2_workbench::evidence::Node, Box<dyn Error>> {
    let mut matching = case.nodes().iter().filter(|node| {
        node.kind == "archive_member"
            && node.details.get("utf8_name").and_then(Value::as_str) == Some(name)
    });
    let member = matching.next().ok_or("nested archive member is missing")?;
    assert!(matching.next().is_none());
    Ok(member)
}

fn assert_nested_duplicate_paths(case: &Case, payload: &[u8]) -> Result<Vec<u64>, Box<dyn Error>> {
    let parent_ids = [
        archive_member_named(case, "left.zip")?.id,
        archive_member_named(case, "right.zip")?.id,
    ];
    let payload_blob_id = format!("sha256:{}", l2_workbench::sha256(payload));
    let leaves: Vec<_> = case
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "archive_member" && node.blob.as_deref() == Some(payload_blob_id.as_str())
        })
        .collect();
    assert_eq!(leaves.len(), 2);

    let mut ids = Vec::new();
    let mut paths = Vec::new();
    for leaf in leaves {
        let parent = leaf
            .details
            .get("archive_node")
            .and_then(Value::as_u64)
            .ok_or("nested leaf archive parent is missing")?;
        assert!(parent_ids.contains(&parent));
        assert_eq!(blob_bytes(case, leaf)?, payload);
        assert_contains_member_edge(case, parent, leaf.id);
        paths.push(
            leaf.details
                .get("utf8_name")
                .and_then(Value::as_str)
                .ok_or("nested leaf archive path is missing")?,
        );
        ids.push(leaf.id);
    }
    paths.sort_unstable();
    assert_eq!(paths, ["left/leaf.txt", "right/leaf.txt"]);
    ids.sort_unstable();
    Ok(ids)
}

fn assert_contains_member_edge(case: &Case, parent: u64, member: u64) {
    assert!(case.edges().iter().any(|edge| {
        edge.from == parent && edge.to == member && edge.relation == "contains_member"
    }));
}

fn assert_exported_duplicate_payload(
    expanded: &Case,
    payload: &[u8],
    expected_leaf_ids: &[u64],
    expected_leaf_paths: &[&str],
) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let case_path = save_case(temporary.path(), "expanded.json", expanded)?;
    let destination = temporary.path().join("artifacts");
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

    let mut payload_file = None;
    for entry in fs::read_dir(&destination)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("artifact-"))
            && fs::read(&path)? == payload
        {
            assert!(payload_file.replace(path).is_none());
        }
    }
    let payload_file = payload_file.ok_or("shared payload artifact file is missing")?;
    assert_eq!(fs::read(&payload_file)?, payload);

    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("artifact manifest entries are missing")?;
    let payload_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact
                .get("nodes")
                .and_then(Value::as_array)
                .is_some_and(|nodes| {
                    let mut ids: Vec<_> = nodes
                        .iter()
                        .filter_map(|node| node.get("id").and_then(Value::as_u64))
                        .collect();
                    ids.sort_unstable();
                    ids == expected_leaf_ids
                })
        })
        .ok_or("shared payload artifact is missing from the manifest")?;
    assert_eq!(
        payload_artifact.get("file").and_then(Value::as_str),
        payload_file.file_name().and_then(|name| name.to_str())
    );
    assert_eq!(
        payload_artifact.get("byte_length"),
        Some(&json!(payload.len()))
    );
    let provenance = payload_artifact
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("shared payload provenance is missing")?;
    assert_eq!(provenance.len(), 2);
    let mut manifest_paths: Vec<_> = provenance
        .iter()
        .filter_map(|node| node.get("archive_path").and_then(Value::as_str))
        .collect();
    manifest_paths.sort_unstable();
    assert_eq!(manifest_paths, expected_leaf_paths);
    Ok(())
}

#[test]
fn duplicate_content_consumes_budget() -> Result<(), Box<dyn Error>> {
    let payload = b"same bytes from both nested archives";
    let first = stored_zip(b"first.bin", payload)?;
    let second = stored_zip(b"other.bin", payload)?;
    let root = stored_zip_entries(&[(b"first.zip", &first), (b"other.zip", &second)])?;
    let operation_budget = first
        .len()
        .checked_add(second.len())
        .and_then(|total| total.checked_add(payload.len()))
        .ok_or("ZIP work budget overflowed")?;
    let mut case = Case::new();
    let input =
        case.add_bytes_node("candidate_object", &root, Vec::new(), serde_json::json!({}))?;

    let output = run_expand_with_archive_budget(&case, input, operation_budget)?;

    assert_eq!(output.status.code(), Some(3));
    let expanded = Case::from_json(&output.stdout)?;
    assert!(!expanded.collection_complete());
    let mut retained_payload_count = 0;
    for node in expanded
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_member")
    {
        if blob_bytes(&expanded, node)? == payload {
            retained_payload_count += 1;
        }
    }
    assert_eq!(retained_payload_count, 1);
    let omission_count = expanded
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_member_omission")
        .count();
    assert_eq!(omission_count, 1);
    let omission = expanded
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member_omission")
        .ok_or("second nested archive omission is missing")?;
    assert_eq!(
        omission.details.get("zip_reason"),
        Some(&serde_json::json!("operation_expanded_byte_limit"))
    );
    assert!(expanded.limitations().iter().any(|limitation| {
        limitation.contains(&format!(
            "operation-wide ZIP work limit of {operation_budget} declared byte(s)"
        ))
    }));
    Ok(())
}

#[test]
fn zip_budget_exact_boundary() -> Result<(), Box<dyn Error>> {
    let payload = b"boundary";
    let inner = stored_zip(b"payload.bin", payload)?;
    let outer = stored_zip(b"nested.zip", &inner)?;
    let exact_budget = inner
        .len()
        .checked_add(payload.len())
        .ok_or("ZIP work budget overflowed")?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &outer,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let exact = run_expand_with_archive_budget(&case, input, exact_budget)?;
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    let exact_case = Case::from_json(&exact.stdout)?;
    assert!(exact_case.collection_complete());
    let exact_member = find_byte_node(&exact_case, "archive_member", payload)
        .ok_or("exact-boundary ZIP member is missing")?;
    assert_eq!(blob_bytes(&exact_case, exact_member)?, payload);

    let below = run_expand_with_archive_budget(&case, input, exact_budget - 1)?;
    assert_eq!(below.status.code(), Some(3));
    let below_case = Case::from_json(&below.stdout)?;
    assert!(!below_case.collection_complete());
    assert!(below_case.nodes().iter().any(|node| {
        node.kind == "archive_member_omission"
            && node.details.get("zip_reason")
                == Some(&serde_json::json!("operation_expanded_byte_limit"))
    }));
    Ok(())
}

fn run_expand_with_archive_budget(
    case: &Case,
    node: u64,
    budget: usize,
) -> Result<std::process::Output, Box<dyn Error>> {
    let node = node.to_string();
    let budget = budget.to_string();
    run(
        &[
            "expand",
            "-",
            "--node",
            &node,
            "--max-zip-work-bytes",
            &budget,
        ],
        &case.to_json()?,
    )
}

#[test]
fn expand_incomplete_chunk_budget_exhausted() -> Result<(), Box<dyn Error>> {
    let image = png(&[]);
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &image,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "expand",
            "-",
            "--node",
            &input.to_string(),
            "--max-objects",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    assert!(!result.collection_complete());
    assert!(result.nodes().iter().any(|node| {
        node.kind == "artifact_expansion_omission"
            && node.details.get("reason") == Some(&serde_json::json!("png_chunk_limit"))
    }));
    Ok(())
}

#[test]
fn expand_incomplete_node_budget_exhausted() -> Result<(), Box<dyn Error>> {
    let der = [0x30, 0x03, 0x04, 0x01, b'A'];
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &der, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "expand",
            "-",
            "--node",
            &input.to_string(),
            "--max-objects",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    assert!(!result.collection_complete());
    assert!(result.nodes().iter().any(|node| {
        node.kind == "artifact_expansion_omission"
            && node.details.get("reason") == Some(&serde_json::json!("der_node_limit"))
    }));
    Ok(())
}

#[test]
fn expand_counts_budget_prioritizes_structure() -> Result<(), Box<dyn Error>> {
    let archive = stored_zip(b"payload.bin", b"payload")?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &archive,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let initial_nodes = case.nodes().len();

    let output = run(
        &[
            "expand",
            "-",
            "--node",
            &input.to_string(),
            "--max-objects",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    assert_eq!(result.nodes().len() - initial_nodes, 1);
    assert!(
        result
            .nodes()
            .iter()
            .any(|node| node.kind == "archive_structure")
    );
    assert!(!result.nodes().iter().any(|node| {
        node.kind == "file_signature_match"
            && node.details.get("input_node").and_then(Value::as_u64) == Some(input)
    }));
    assert!(
        result
            .limitations()
            .iter()
            .any(|limitation| { limitation.contains("signature observations were omitted") })
    );
    Ok(())
}

#[test]
fn expand_recovers_arbitrary_prepended_bytes() -> Result<(), Box<dyn Error>> {
    let archive = stored_zip(b"member.dat", b"member bytes")?;
    // The prefix intentionally has no file signature so dispatch cannot depend on its format
    let mut prefixed = vec![0xa5; 17];
    prefixed.extend_from_slice(&archive);
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &prefixed,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let member = find_node(&result, "archive_member")?;
    assert_eq!(blob_bytes(&result, member)?, b"member bytes");
    assert_eq!(
        member.details.get("utf8_name"),
        Some(&serde_json::json!("member.dat"))
    );
    Ok(())
}

#[test]
fn expand_corrupt_without_integrity_passed() -> Result<(), Box<dyn Error>> {
    let member_name = b"corrupt.bin";
    let mut archive = stored_zip(member_name, b"payload")?;
    let member_data_offset = 30_usize
        .checked_add(member_name.len())
        .ok_or("ZIP member data offset overflowed")?;
    let first_data_byte = archive
        .get_mut(member_data_offset)
        .ok_or("ZIP member data is missing")?;
    *first_data_byte ^= 1;

    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &archive,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    assert!(!result.collection_complete());
    let omissions: Vec<_> = result
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_member_omission")
        .collect();
    assert_eq!(omissions.len(), 1);
    let omission = omissions.first().ok_or("member omission is missing")?;
    assert_eq!(
        omission
            .details
            .get("entry")
            .and_then(|entry| entry.get("entry_index")),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        omission.details.get("zip_reason"),
        Some(&serde_json::json!({
            "entry_data_failure": {
                "index": 0,
                "failure": "crc_mismatch"
            }
        }))
    );

    let aggregate_omissions: Vec<_> = result
        .nodes()
        .iter()
        .filter(|node| node.kind == "zip_aggregate_omission")
        .collect();
    assert_eq!(aggregate_omissions.len(), 1);
    let aggregate = aggregate_omissions
        .first()
        .ok_or("aggregate omission is missing")?;
    assert_eq!(
        aggregate.details.get("omitted_entry_count"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        aggregate
            .details
            .get("omission_counts")
            .and_then(|counts| counts.get("member_data_failure")),
        Some(&serde_json::json!(1))
    );

    assert_corrupt_zip_edge_reason(&result, input)?;
    Ok(())
}

fn assert_corrupt_zip_edge_reason(case: &Case, input: u64) -> Result<(), Box<dyn Error>> {
    let structure = find_node(case, "archive_structure")?;
    let parsed_edge = case
        .edges()
        .iter()
        .find(|edge| edge.from == input && edge.to == structure.id && edge.relation == "parsed_as")
        .ok_or("ZIP structure edge is missing")?;
    assert!(parsed_edge.reason.contains(
        "0 member(s) passed local-header, descriptor when present, size, boundary, and CRC checks"
    ));
    assert!(
        parsed_edge
            .reason
            .contains("1 failed or could not complete per-member checks")
    );
    assert!(!parsed_edge.reason.contains("all 1 member(s) passed"));
    Ok(())
}

#[test]
fn expand_invalid_incomplete_member_evidence() -> Result<(), Box<dyn Error>> {
    let archive = stored_zip_with_bad_descriptor(b"descriptor.bin", b"payload")?;
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_object",
        &archive,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &["expand", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let result = Case::from_json(&output.stdout)?;
    assert!(!result.collection_complete());
    let omission = result
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member_omission")
        .ok_or("descriptor omission is missing")?;
    assert_eq!(
        omission.details.get("zip_reason"),
        Some(&serde_json::json!({
            "entry_data_failure": {
                "index": 0,
                "failure": "data_descriptor_mismatch"
            }
        }))
    );
    let structure = find_node(&result, "archive_structure")?;
    let parsed_edge = result
        .edges()
        .iter()
        .find(|edge| edge.from == input && edge.to == structure.id && edge.relation == "parsed_as")
        .ok_or("ZIP structure edge is missing")?;
    assert!(parsed_edge.reason.contains("descriptor when present"));
    assert!(
        parsed_edge
            .reason
            .contains("1 failed or could not complete per-member checks")
    );
    Ok(())
}

fn find_node<'a>(
    case: &'a Case,
    kind: &str,
) -> Result<&'a l2_workbench::evidence::Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == kind)
        .ok_or_else(|| format!("missing {kind} node").into())
}

fn blob_bytes<'a>(
    case: &'a Case,
    node: &l2_workbench::evidence::Node,
) -> Result<&'a [u8], Box<dyn Error>> {
    let blob = node.blob.as_deref().ok_or("node has no byte blob")?;
    Ok(case
        .blobs()
        .iter()
        .find(|candidate| candidate.id == blob)
        .ok_or("missing node blob")?
        .bytes
        .as_slice())
}

fn find_byte_node<'a>(
    case: &'a Case,
    kind: &str,
    bytes: &[u8],
) -> Option<&'a l2_workbench::evidence::Node> {
    let blob_id = format!("sha256:{}", l2_workbench::sha256(bytes));
    case.nodes()
        .iter()
        .find(|node| node.kind == kind && node.blob.as_deref() == Some(blob_id.as_str()))
}

fn png(extra_chunks: &[([u8; 4], &[u8])]) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1_u32.to_be_bytes());
    ihdr.extend_from_slice(&1_u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_chunk(&mut bytes, *b"IHDR", &ihdr);
    for (kind, payload) in extra_chunks {
        png_chunk(&mut bytes, *kind, payload);
    }
    png_chunk(&mut bytes, *b"IEND", &[]);
    bytes
}

fn png_chunk(output: &mut Vec<u8>, kind: [u8; 4], payload: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    output.extend_from_slice(&kind);
    output.extend_from_slice(payload);
    let mut checksum_input = kind.to_vec();
    checksum_input.extend_from_slice(payload);
    output.extend_from_slice(&crc32(&checksum_input).to_be_bytes());
}

fn stored_zip_with_bad_descriptor(name: &[u8], content: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = stored_zip(name, content)?;
    let descriptor_start = 30_usize
        .checked_add(name.len())
        .and_then(|offset| offset.checked_add(content.len()))
        .ok_or("ZIP member boundary overflowed")?;
    let old_eocd = bytes.len().checked_sub(22).ok_or("ZIP EOCD is missing")?;
    let central_start = old_eocd
        .checked_sub(
            46_usize
                .checked_add(name.len())
                .ok_or("central header overflowed")?,
        )
        .ok_or("ZIP central header is missing")?;

    bytes
        .get_mut(6..8)
        .ok_or("local flags are missing")?
        .copy_from_slice(&(1_u16 << 3).to_le_bytes());
    bytes
        .get_mut(14..26)
        .ok_or("local size fields are missing")?
        .fill(0);
    bytes
        .get_mut(central_start + 8..central_start + 10)
        .ok_or("central flags are missing")?
        .copy_from_slice(&(1_u16 << 3).to_le_bytes());

    let checksum = crc32(content);
    let compressed_size = u32::try_from(content.len())?;
    let mut descriptor = Vec::new();
    push_u32(&mut descriptor, 0x0807_4b50);
    push_u32(&mut descriptor, checksum ^ 1);
    push_u32(&mut descriptor, compressed_size);
    push_u32(&mut descriptor, compressed_size);
    bytes.splice(descriptor_start..descriptor_start, descriptor);

    let new_eocd = old_eocd.checked_add(16).ok_or("EOCD offset overflowed")?;
    let directory_offset = u32::try_from(
        descriptor_start
            .checked_add(16)
            .ok_or("directory offset overflowed")?,
    )?;
    bytes
        .get_mut(new_eocd + 16..new_eocd + 20)
        .ok_or("central directory offset is missing")?
        .copy_from_slice(&directory_offset.to_le_bytes());
    Ok(bytes)
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
