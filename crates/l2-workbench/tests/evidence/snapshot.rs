use l2_workbench::{
    evidence::{
        Case, CaseSnapshotLimits, EvidenceError, EvidenceStatus, MAX_CASE_JSON_BYTES, SourceRange,
    },
    sha256,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, BufRead, Read, Write},
};

const LARGE_BLOB_BYTES: usize = 48 * 1024 * 1024;

#[test]
fn snapshot_graph_keeps_the_existing_record_bytes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let id = case.add_bytes_node("sample", b"x", Vec::new(), json!({}))?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: id,
        to: id,
        relation: "supports".into(),
        status: EvidenceStatus::Observed,
        reason: "observed once".into(),
    })?;
    case.add_limitation("scope")?;
    let (graph, pack) = encode_snapshot(&case, small_limits())?;
    assert_eq!(pack, b"x");
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(graph.as_slice()).read_to_string(&mut decoded)?;
    let blob = format!("sha256:{}", sha256(b"x"));
    let expected = format!(
        concat!(
            "{{\"record\":\"header\",\"value\":{{\"format_version\":1,\"schema_version\":1,\"collection_complete\":true,\"resource_limits\":{{\"blob_bytes\":null}},\"source_count\":0,\"blob_count\":1,\"node_count\":1,\"edge_count\":1,\"limitation_count\":1,\"blob_pack_bytes\":1}}}}\n",
            "{{\"record\":\"blob\",\"value\":{{\"id\":\"{blob}\",\"offset\":0,\"length\":1}}}}\n",
            "{{\"record\":\"node\",\"value\":{{\"id\":1,\"kind\":\"sample\",\"blob\":\"{blob}\",\"ranges\":[],\"details\":{{}}}}}}\n",
            "{{\"record\":\"edge\",\"value\":{{\"from\":1,\"to\":1,\"relation\":\"supports\",\"status\":\"observed\",\"reason\":\"observed once\"}}}}\n",
            "{{\"record\":\"limitation\",\"value\":\"scope\"}}\n"
        ),
        blob = blob
    );
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn snapshot_roundtrip_preserves_escaped_graph_text() -> Result<(), Box<dyn Error>> {
    let bytes = b"quoted text fixture";
    let mut case = Case::with_blob_limit(bytes.len() + 1)?;
    let blob_id = case.add_blob(bytes)?;
    let content_id = sha256(bytes);
    let source_length = u64::try_from(bytes.len())?;
    let source_id = case.add_source(
        "capture\"quoted.bin",
        r"capture\kind",
        source_length,
        &content_id,
        Some(&blob_id),
    )?;
    case.add_source(
        "capture\"alias.bin",
        r"capture\kind",
        source_length,
        &content_id,
        Some(&blob_id),
    )?;
    let first = case.add_node(
        r#"node"kind\part"#,
        Some(&blob_id),
        Vec::new(),
        json!({"note":"ordinary structured text"}),
    )?;
    let second = case.add_node("other_node", Some(&blob_id), Vec::new(), json!({}))?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: first,
        to: second,
        relation: r#"quoted"relation\part"#.to_owned(),
        status: EvidenceStatus::Observed,
        reason: r#"reason with "quotes" and \ backslashes"#.to_owned(),
    })?;
    case.add_limitation(r#"limitation with "quotes" and \ backslashes"#)?;

    let limits = small_limits();
    let (graph, blob_pack) = encode_snapshot(&case, limits)?;
    let (decoded, _usage) = Case::from_snapshot(graph.as_slice(), blob_pack.as_slice(), limits)?;

    assert_eq!(decoded, case);
    assert_eq!(
        decoded.sources().first().map(|source| source.id.as_str()),
        Some(source_id.as_str())
    );
    Ok(())
}

#[test]
fn snapshot_roundtrip_preserves_exact_case_when_json_exceeds_default_limit()
-> Result<(), Box<dyn Error>> {
    let bytes = vec![0xA7; LARGE_BLOB_BYTES];
    let case = case_with_shared_blob(&bytes)?;
    let canonical_size = count_json_bytes(&case)?;
    assert!(
        canonical_size > u64::try_from(MAX_CASE_JSON_BYTES)?,
        "the fixture must exceed the ordinary Case JSON limit"
    );

    let limits = CaseSnapshotLimits::new(
        u64::try_from(LARGE_BLOB_BYTES + 2 * 1024 * 1024)?,
        u64::try_from(LARGE_BLOB_BYTES + 2 * 1024 * 1024)?,
    );
    let mut graph = Vec::new();
    let mut blob_pack = Vec::new();
    let usage = case.write_snapshot(&mut graph, &mut blob_pack, limits)?;

    assert_eq!(usage.blob_pack_bytes, u64::try_from(bytes.len())?);
    assert_eq!(blob_pack, bytes);
    assert!(usage.graph_bytes < u64::try_from(MAX_CASE_JSON_BYTES)?);
    assert!(usage.graph_decoded_bytes > 0);

    let (decoded, read_usage) =
        Case::from_snapshot(graph.as_slice(), blob_pack.as_slice(), limits)?;
    assert_eq!(read_usage, usage);
    assert_eq!(decoded, case);
    assert_eq!(decoded.blob_byte_limit(), Some(LARGE_BLOB_BYTES + 1));
    let blob_id = format!("sha256:{}", sha256(&bytes));
    assert_eq!(
        decoded.blob(&blob_id).map(|blob| blob.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    Ok(())
}

#[test]
fn snapshot_pack_rejects_same_size_blob_corruption() -> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(b"exact content-addressed blob")?;
    let limits = small_limits();
    let (graph, mut blob_pack) = encode_snapshot(&case, limits)?;
    let first = blob_pack
        .first_mut()
        .ok_or("the fixture blob pack is unexpectedly empty")?;
    *first ^= 0x01;

    assert!(matches!(
        Case::from_snapshot(graph.as_slice(), blob_pack.as_slice(), limits),
        Err(EvidenceError::HashMismatch)
    ));
    Ok(())
}

#[test]
fn snapshot_rejects_short_and_trailing_blob_packs() -> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(b"a small exact blob")?;
    let limits = small_limits();
    let (graph, blob_pack) = encode_snapshot(&case, limits)?;

    let shortened_pack = blob_pack
        .get(..blob_pack.len() - 1)
        .ok_or("the fixture blob pack unexpectedly has no bytes")?;
    assert!(Case::from_snapshot(graph.as_slice(), shortened_pack, limits).is_err());

    let mut trailing = blob_pack;
    trailing.push(0);
    assert!(Case::from_snapshot(graph.as_slice(), trailing.as_slice(), limits).is_err());
    Ok(())
}

#[test]
fn snapshot_rejects_trailing_compressed_bytes_and_additional_gzip_members()
-> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(b"one exact graph")?;
    let limits = small_limits();
    let (graph, blob_pack) = encode_snapshot(&case, limits)?;

    let shortened_graph = graph
        .get(..graph.len().saturating_sub(1))
        .ok_or("the fixture graph unexpectedly has no bytes")?;
    assert!(Case::from_snapshot(shortened_graph, blob_pack.as_slice(), limits).is_err());

    let mut trailing_bytes = graph.clone();
    trailing_bytes.extend_from_slice(b"trailing bytes");
    assert!(matches!(
        Case::from_snapshot(trailing_bytes.as_slice(), blob_pack.as_slice(), limits),
        Err(EvidenceError::InvalidJson)
    ));

    let second_member = gzip_bytes(b"not another graph record")?;
    let mut multiple_members = graph;
    multiple_members.extend_from_slice(&second_member);
    assert!(matches!(
        Case::from_snapshot(multiple_members.as_slice(), blob_pack.as_slice(), limits),
        Err(EvidenceError::InvalidJson)
    ));
    Ok(())
}

#[test]
fn snapshot_rejects_header_counts_and_offsets_outside_their_declared_ranges()
-> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(b"one blob")?;
    let limits = small_limits();
    let (graph, blob_pack) = encode_snapshot(&case, limits)?;
    let records = decode_graph_records(&graph)?;

    let mut oversized_count = records.clone();
    oversized_count
        .first_mut()
        .and_then(|record| record.get_mut("value"))
        .and_then(Value::as_object_mut)
        .ok_or("snapshot header fixture is missing its value object")?
        .insert("node_count".to_owned(), json!(u64::MAX));
    let malformed_graph = encode_graph_records(&oversized_count)?;
    assert!(Case::from_snapshot(malformed_graph.as_slice(), blob_pack.as_slice(), limits).is_err());

    let mut invalid_offset = records;
    invalid_offset
        .get_mut(2)
        .and_then(|record| record.get_mut("value"))
        .and_then(Value::as_object_mut)
        .ok_or("snapshot blob fixture is missing its value object")?
        .insert("offset".to_owned(), json!(1));
    let malformed_graph = encode_graph_records(&invalid_offset)?;
    assert!(Case::from_snapshot(malformed_graph.as_slice(), blob_pack.as_slice(), limits).is_err());
    Ok(())
}

#[test]
fn snapshot_zero_length_blob_roundtrips_without_advancing_the_pack_offset()
-> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(&[])?;
    let limits = small_limits();
    let (graph, blob_pack) = encode_snapshot(&case, limits)?;

    assert!(blob_pack.is_empty());
    let (decoded, _usage) = Case::from_snapshot(graph.as_slice(), blob_pack.as_slice(), limits)?;
    assert_eq!(decoded, case);
    Ok(())
}

#[test]
fn snapshot_reader_bounds_gzip_expansion_before_parsing_records() -> Result<(), Box<dyn Error>> {
    let graph = gzip_bytes(&vec![b'x'; 8 * 1024 * 1024])?;
    let limits = CaseSnapshotLimits::new(1024 * 1024, 1024);

    assert!(matches!(
        Case::from_snapshot(graph.as_slice(), &[][..], limits),
        Err(EvidenceError::CaseTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn snapshot_write_and_read_obey_both_physical_and_decoded_limits() -> Result<(), Box<dyn Error>> {
    let case = case_with_shared_blob(b"bounded snapshot bytes")?;
    let (graph, blob_pack) = encode_snapshot(&case, small_limits())?;
    let physical_size = u64::try_from(graph.len() + blob_pack.len())?;

    let too_small_physical = CaseSnapshotLimits::new(physical_size - 1, 1024);
    let mut graph_output = Vec::new();
    let mut pack_output = Vec::new();
    assert!(matches!(
        case.write_snapshot(&mut graph_output, &mut pack_output, too_small_physical),
        Err(EvidenceError::CaseTooLarge { .. })
    ));

    let too_small_decoded = CaseSnapshotLimits::new(1024 * 1024, 1);
    assert!(matches!(
        Case::from_snapshot(graph.as_slice(), blob_pack.as_slice(), too_small_decoded),
        Err(EvidenceError::CaseTooLarge { .. })
    ));
    Ok(())
}

fn case_with_shared_blob(bytes: &[u8]) -> Result<Case, EvidenceError> {
    let mut case = Case::with_blob_limit(bytes.len() + 1)?;
    let blob_id = case.add_blob(bytes)?;
    let source_id = case.add_source(
        "capture.bin",
        "capture",
        u64::try_from(bytes.len()).map_err(|_| EvidenceError::ArithmeticOverflow {
            field: "fixture source length",
        })?,
        &sha256(bytes),
        Some(&blob_id),
    )?;
    let first_node = case.add_node(
        "raw_capture",
        Some(&blob_id),
        if bytes.is_empty() {
            Vec::new()
        } else {
            vec![SourceRange {
                source: source_id,
                packet: None,
                offset: 0,
                length: u64::try_from(bytes.len()).map_err(|_| {
                    EvidenceError::ArithmeticOverflow {
                        field: "fixture range length",
                    }
                })?,
            }]
        },
        json!({"role":"exact fixture payload"}),
    )?;
    let second_node = case.add_node(
        "same_blob_reference",
        Some(&blob_id),
        Vec::new(),
        json!({"role":"shared content id"}),
    )?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: first_node,
        to: second_node,
        relation: "same_bytes".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "both nodes reference one content-addressed blob".to_owned(),
    })?;
    Ok(case)
}

fn count_json_bytes(case: &Case) -> Result<u64, EvidenceError> {
    struct Counter(u64);

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("fixture JSON count overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter(0);
    case.write_json(&mut counter)?;
    Ok(counter.0)
}

const fn small_limits() -> CaseSnapshotLimits {
    CaseSnapshotLimits::new(1024 * 1024, 1024 * 1024)
}

fn encode_snapshot(
    case: &Case,
    limits: CaseSnapshotLimits,
) -> Result<(Vec<u8>, Vec<u8>), EvidenceError> {
    let mut graph = Vec::new();
    let mut blob_pack = Vec::new();
    case.write_snapshot(&mut graph, &mut blob_pack, limits)?;
    Ok((graph, blob_pack))
}

fn decode_graph_records(graph: &[u8]) -> Result<Vec<Value>, Box<dyn Error>> {
    let decoder = flate2::read::GzDecoder::new(graph);
    let mut records = Vec::new();
    for line in io::BufReader::new(decoder).lines() {
        records.push(serde_json::from_str(&line?)?);
    }
    Ok(records)
}

fn encode_graph_records(records: &[Value]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for record in records {
        serde_json::to_writer(&mut encoder, record)?;
        encoder.write_all(b"\n")?;
    }
    Ok(encoder.finish()?)
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}
