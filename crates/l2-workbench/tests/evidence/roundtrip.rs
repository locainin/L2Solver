use base64::Engine as _;
use l2_workbench::{
    evidence::{
        Case, EvidenceError, EvidenceStatus, MAX_BLOB_TOTAL_BYTES, MAX_CASE_JSON_BYTES, SourceRange,
    },
    sha256,
};
use serde_json::{Value, json};
use std::{error::Error, io};

#[test]
fn case_round_hashes_ranges_statuses() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"A literal address is only a value";
    let blob = case.add_blob(bytes)?;
    let source_length = u64::try_from(bytes.len())?;
    let source = case.add_source(
        "config.txt",
        "text",
        source_length,
        &sha256(bytes),
        Some(&blob),
    )?;
    let node = case.add_node(
        "literal_string",
        Some(&blob),
        vec![SourceRange {
            source,
            packet: None,
            offset: 2,
            length: 7,
        }],
        json!({ "role": "observed bytes" }),
    )?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: node,
        to: node,
        relation: "supports".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: "literal matches a separately observed value".to_owned(),
    })?;

    let encoded = case.to_json()?;
    let document: serde_json::Value = serde_json::from_slice(&encoded)?;
    assert!(
        document.get("resource_limits").is_none(),
        "unlimited schema-v1 cases must remain readable by strict legacy readers"
    );
    assert_eq!(
        document
            .get("blobs")
            .and_then(serde_json::Value::as_array)
            .and_then(|blobs| blobs.first())
            .and_then(|blob| blob.get("bytes_base64"))
            .and_then(serde_json::Value::as_str),
        Some(
            base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .as_str()
        )
    );
    let decoded = Case::from_json(&encoded)?;
    assert_eq!(decoded, case);
    Ok(())
}

#[test]
fn case_stream_loadable_complete_document() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node(
        "retained_bytes",
        b"streamed case bytes",
        Vec::new(),
        json!({"source":"synthetic"}),
    )?;
    let mut encoded = Vec::new();

    case.write_json(&mut encoded)?;

    assert_eq!(Case::from_json(&encoded)?, case);
    Ok(())
}

#[test]
fn case_stream_writer_output_failures() {
    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic output failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    assert_eq!(
        Case::new().write_json(&mut FailingWriter),
        Err(EvidenceError::WriteFailed)
    );
}

#[test]
fn case_round_monotonic_collection_completeness() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    assert!(case.collection_complete());
    case.mark_incomplete("Some retained observations were omitted")?;
    assert!(!case.collection_complete());
    case.mark_incomplete("A later operation retained only a bounded subset")?;
    assert!(!case.collection_complete());

    let encoded = case.to_json()?;
    let decoded = Case::from_json(&encoded)?;
    assert!(!decoded.collection_complete());
    assert!(
        decoded
            .limitations()
            .iter()
            .any(|item| { item == "Some retained observations were omitted" })
    );
    assert!(
        decoded
            .limitations()
            .iter()
            .any(|item| { item == "A later operation retained only a bounded subset" })
    );
    Ok(())
}

#[test]
fn loader_requires_collection_completeness_value() -> Result<(), Box<dyn Error>> {
    let case = Case::new();
    let mut document: serde_json::Value = serde_json::from_slice(&case.to_json()?)?;
    document
        .as_object_mut()
        .ok_or("serialized case is not an object")?
        .remove("collection_complete");
    let encoded = serde_json::to_vec(&document)?;

    assert!(Case::from_json(&encoded).is_err());
    Ok(())
}

#[test]
fn loader_tampered_hash_dangling_references() {
    let tampered_hash = format!(
        r#"{{"schema_version":1,"collection_complete":true,"sources":[],"blobs":[{{"id":"sha256:{}","bytes_base64":"AQ=="}}],"nodes":[],"edges":[],"limitations":[]}}"#,
        "0".repeat(64)
    );
    assert!(Case::from_json(tampered_hash.as_bytes()).is_err());

    let dangling_reference = format!(
        r#"{{"schema_version":1,"collection_complete":true,"sources":[],"blobs":[],"nodes":[{{"id":1,"kind":"literal","blob":null,"ranges":[{{"source":"sha256:{}","packet":null,"offset":0,"length":1}}],"details":{{}}}}],"edges":[],"limitations":[]}}"#,
        "0".repeat(64)
    );
    assert!(Case::from_json(dangling_reference.as_bytes()).is_err());
}

#[test]
fn loader_noncanonical_unattached_source_identifier() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_source("input.bin", "file", 1, &"0".repeat(64), None)?;
    let mut document: Value = serde_json::from_slice(&case.to_json()?)?;
    let source = document
        .get_mut("sources")
        .and_then(Value::as_array_mut)
        .and_then(|sources| sources.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or("serialized source is missing")?;
    source.insert("id".to_owned(), json!("not-a-content-id"));

    assert!(Case::from_json(&serde_json::to_vec(&document)?).is_err());
    Ok(())
}

#[test]
fn loader_invalid_legacy_blob_encodings() {
    let hash = "sha256:".to_owned() + &"0".repeat(64);
    for bytes_base64 in ["AQ=", "AR=="] {
        let document = serde_json::json!({
            "schema_version": 1,
            "collection_complete": true,
            "sources": [],
            "blobs": [{"id": hash.clone(), "bytes_base64": bytes_base64}],
            "nodes": [],
            "edges": [],
            "limitations": [],
        });
        assert!(Case::from_json(&document.to_string().into_bytes()).is_err());
    }

    let legacy_document = serde_json::json!({
        "schema_version": 1,
        "collection_complete": true,
        "sources": [],
        "blobs": [{"id": hash, "bytes": [1]}],
        "nodes": [],
        "edges": [],
        "limitations": [],
    });
    assert!(Case::from_json(&legacy_document.to_string().into_bytes()).is_err());
}

#[test]
fn loader_honors_explicit_blob_limit() -> Result<(), Box<dyn Error>> {
    let decoded_length = MAX_BLOB_TOTAL_BYTES / 2 + 4;
    let mut document = json!({
        "schema_version": 1, "collection_complete": true, "sources": [],
        "resource_limits": {"blob_bytes": MAX_BLOB_TOTAL_BYTES},
        "blobs": [], "nodes": [], "edges": [], "limitations": [],
    });
    // Each half is valid on its own; only the combined retained-byte total is too large
    for (index, fill) in [0_u8, u8::MAX].into_iter().enumerate() {
        let mut half = Case::new();
        half.add_bytes_node(
            "retained",
            &vec![fill; decoded_length],
            Vec::new(),
            json!({}),
        )?;
        let value: Value = serde_json::from_slice(&half.to_json()?)?;
        document
            .get_mut("blobs")
            .and_then(Value::as_array_mut)
            .ok_or("missing blobs")?
            .push(
                value
                    .pointer("/blobs/0")
                    .ok_or("missing half blob")?
                    .clone(),
            );
        let mut node = value
            .pointer("/nodes/0")
            .ok_or("missing half node")?
            .clone();
        *node.get_mut("id").ok_or("missing node ID")? = json!(index + 1);
        document
            .get_mut("nodes")
            .and_then(Value::as_array_mut)
            .ok_or("missing nodes")?
            .push(node);
    }
    let encoded = serde_json::to_vec(&document)?;
    assert!(encoded.len() < MAX_CASE_JSON_BYTES);
    assert!(matches!(
        Case::from_json(&encoded),
        Err(l2_workbench::evidence::EvidenceError::QuotaExceeded {
            field: "blob bytes",
            maximum: MAX_BLOB_TOTAL_BYTES,
        })
    ));
    Ok(())
}

#[test]
fn loader_zero_persisted_blob_limit() {
    let document = br#"{"schema_version":1,"collection_complete":true,"resource_limits":{"blob_bytes":0},"sources":[],"blobs":[],"nodes":[],"edges":[],"limitations":[]}"#;

    assert!(matches!(
        Case::from_json(document),
        Err(
            l2_workbench::evidence::EvidenceError::InvalidResourceLimit {
                field: "blob bytes"
            }
        )
    ));
}

#[test]
fn loader_preflights_decoding_blob_data() {
    let document = format!(
        r#"{{"schema_version":1,"collection_complete":true,"resource_limits":{{"blob_bytes":1}},"sources":[],"blobs":[{{"id":"sha256:{}","bytes_base64":"!!!!"}}],"nodes":[],"edges":[],"limitations":[]}}"#,
        "0".repeat(64)
    );

    assert!(matches!(
        Case::from_json(document.as_bytes()),
        Err(l2_workbench::evidence::EvidenceError::QuotaExceeded {
            field: "blob bytes",
            maximum: 1
        })
    ));
}

#[test]
fn explicit_blob_default_round_trips() -> Result<(), Box<dyn Error>> {
    let maximum = MAX_BLOB_TOTAL_BYTES + 1;
    let mut case = Case::with_blob_limit(maximum)?;
    case.add_bytes_node("retained", b"bytes", Vec::new(), json!({}))?;

    let restored = Case::from_json(&case.to_json()?)?;

    assert_eq!(restored.blob_byte_limit(), Some(maximum));
    assert_eq!(restored, case);
    Ok(())
}

#[test]
fn single_blob_aggregate_budget() -> Result<(), Box<dyn Error>> {
    let mut case = Case::with_blob_limit(MAX_BLOB_TOTAL_BYTES)?;
    let bytes = vec![u8::MAX; MAX_BLOB_TOTAL_BYTES];
    case.add_bytes_node("retained", &bytes, Vec::new(), json!({}))?;

    let encoded = case.to_json()?;

    assert!(encoded.len() < MAX_CASE_JSON_BYTES);
    let restored = Case::from_json(&encoded)?;
    assert_eq!(
        restored.blobs().first().map(|blob| blob.bytes.len()),
        Some(bytes.len())
    );
    Ok(())
}

#[test]
fn validation_rejects_unreferenced_content_blobs() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_blob(b"not referenced")?;
    assert!(case.validate().is_err());
    Ok(())
}

#[test]
fn case_validity_not_stream_budget() -> Result<(), Box<dyn Error>> {
    let mut document = vec![b' '; l2_workbench::evidence::MAX_CASE_JSON_BYTES + 1];
    document.extend_from_slice(&Case::new().to_json()?);

    let restored = Case::from_json(&document)?;

    assert_eq!(restored, Case::new());
    Ok(())
}
