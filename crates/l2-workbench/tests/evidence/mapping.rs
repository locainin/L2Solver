use l2_workbench::evidence::{
    ByteMapping, Case, CheckedByteMappingCursor, EvidenceError, MAX_BLOB_TOTAL_BYTES, MAX_NODES,
    SourceRange, clip_byte_mappings,
};
use serde_json::json;
use std::error::Error;

fn mappings(case: &mut Case) -> Result<Vec<ByteMapping>, Box<dyn Error>> {
    let source = case.add_source("bytes.bin", "file", 4, &"1".repeat(64), None)?;
    Ok(vec![
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.clone(),
                packet: None,
                offset: 0,
                length: 1,
            },
        },
        ByteMapping {
            offset: 1,
            range: SourceRange {
                source,
                packet: None,
                offset: 3,
                length: 1,
            },
        },
    ])
}

fn mapping_shapes(mappings: &[ByteMapping]) -> Vec<(usize, SourceRange)> {
    mappings
        .iter()
        .map(|mapping| (mapping.offset, mapping.range.clone()))
        .collect()
}

#[test]
fn clipping_maps_selected_slice() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source_mappings = mappings(&mut case)?;

    let clipped = clip_byte_mappings(&source_mappings, 1..2)?;

    let [mapping] = clipped.as_slice() else {
        return Err("expected one clipped mapping".into());
    };
    assert_eq!(mapping.offset, 0);
    assert_eq!(mapping.range.offset, 3);
    assert_eq!(mapping.range.length, 1);
    assert_eq!(mapping.range.packet, None);
    Ok(())
}

#[test]
fn clipping_preserves_source_boundaries() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source_mappings = mappings(&mut case)?;

    let clipped = clip_byte_mappings(&source_mappings, 0..2)?;

    let [first, second] = clipped.as_slice() else {
        return Err("expected both clipped source mappings".into());
    };
    assert_eq!(first.offset, 0);
    assert_eq!(first.range.offset, 0);
    assert_eq!(first.range.length, 1);
    assert_eq!(second.offset, 1);
    assert_eq!(second.range.offset, 3);
    assert_eq!(second.range.length, 1);
    Ok(())
}

#[test]
fn outside_slice_remains_unmapped() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source_mappings = mappings(&mut case)?;

    assert!(clip_byte_mappings(&source_mappings, 2..3)?.is_empty());
    Ok(())
}

#[test]
fn clipping_rejects_overflow() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source_mappings = mappings(&mut case)?;

    assert!(matches!(
        clip_byte_mappings(
            &source_mappings,
            std::ops::Range {
                start: usize::MAX,
                end: 1,
            }
        ),
        Err(EvidenceError::InvalidSourceRange)
    ));
    let [first_mapping, ..] = source_mappings.as_slice() else {
        return Err("test source mapping is missing".into());
    };
    let mut overflowing_output = first_mapping.clone();
    overflowing_output.offset = usize::MAX;
    assert!(matches!(
        clip_byte_mappings(&[overflowing_output], 0..1),
        Err(EvidenceError::InvalidSourceRange)
    ));
    let mut overflowing_source = first_mapping.clone();
    overflowing_source.range.offset = u64::MAX;
    overflowing_source.range.length = 1;
    assert!(matches!(
        clip_byte_mappings(&[overflowing_source], 0..1),
        Err(EvidenceError::InvalidSourceRange)
    ));
    Ok(())
}

#[test]
fn cursor_matches_many_frames() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("bytes.bin", "file", 1_000, &"1".repeat(64), None)?;
    let mut source_mappings = Vec::new();
    for offset in (0..900).step_by(3) {
        source_mappings.push(ByteMapping {
            offset,
            range: SourceRange {
                source: source.clone(),
                packet: Some(u64::try_from(offset / 3 + 1)?),
                offset: u64::try_from(offset + 100)?,
                length: 2,
            },
        });
    }
    let mut cursor = CheckedByteMappingCursor::new(&source_mappings)?
        .ok_or("monotonic mapping offsets should create a cursor")?;
    for frame_start in 0..300 {
        let frame = frame_start * 3..frame_start * 3 + 3;
        let actual = cursor
            .clip_range(frame.clone())?
            .ok_or("monotonic frame range should remain supported")?;
        assert_eq!(
            mapping_shapes(&actual),
            mapping_shapes(&clip_byte_mappings(&source_mappings, frame)?),
            "frame {frame_start} differs from the canonical clipper"
        );
    }
    Ok(())
}

#[test]
fn cursor_handles_crossing_gaps() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("bytes.bin", "file", 1_000, &"2".repeat(64), None)?;
    let source_mappings = vec![
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.clone(),
                packet: Some(1),
                offset: 20,
                length: 9,
            },
        },
        ByteMapping {
            offset: 12,
            range: SourceRange {
                source: source.clone(),
                packet: Some(2),
                offset: 80,
                length: 3,
            },
        },
        ByteMapping {
            offset: 16,
            range: SourceRange {
                source,
                packet: Some(3),
                offset: 180,
                length: 6,
            },
        },
    ];
    let mut cursor = CheckedByteMappingCursor::new(&source_mappings)?
        .ok_or("monotonic mapping offsets should create a cursor")?;

    for frame in [0..4, 4..7, 7..10, 10..13, 13..16, 16..18, 18..20, 20..22] {
        let actual = cursor
            .clip_range(frame.clone())?
            .ok_or("monotonic frame range should remain supported")?;
        assert_eq!(
            mapping_shapes(&actual),
            mapping_shapes(&clip_byte_mappings(&source_mappings, frame)?)
        );
    }
    Ok(())
}

#[test]
fn cursor_falls_back_unsorted() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("bytes.bin", "file", 10, &"3".repeat(64), None)?;
    let source_mappings = vec![
        ByteMapping {
            offset: 5,
            range: SourceRange {
                source: source.clone(),
                packet: None,
                offset: 5,
                length: 2,
            },
        },
        ByteMapping {
            offset: 1,
            range: SourceRange {
                source,
                packet: None,
                offset: 1,
                length: 2,
            },
        },
    ];

    assert!(CheckedByteMappingCursor::new(&source_mappings)?.is_none());
    let range = 0..8;
    let clipped = clip_byte_mappings(&source_mappings, range)?;
    assert_eq!(
        clipped
            .iter()
            .map(|mapping| mapping.offset)
            .collect::<Vec<_>>(),
        [5, 1]
    );
    Ok(())
}

#[test]
fn cursor_falls_back_overlapping() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("bytes.bin", "file", 10, &"4".repeat(64), None)?;
    let source_id = source.clone();
    let source_mappings = vec![
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.clone(),
                packet: None,
                offset: 0,
                length: 8,
            },
        },
        ByteMapping {
            offset: 5,
            range: SourceRange {
                source,
                packet: None,
                offset: 20,
                length: 3,
            },
        },
    ];

    assert!(CheckedByteMappingCursor::new(&source_mappings)?.is_none());
    let clipped = clip_byte_mappings(&source_mappings, 4..7)?;
    assert_eq!(
        mapping_shapes(&clipped),
        vec![
            (
                0,
                SourceRange {
                    source: source_id.clone(),
                    packet: None,
                    offset: 4,
                    length: 3,
                },
            ),
            (
                1,
                SourceRange {
                    source: source_id,
                    packet: None,
                    offset: 20,
                    length: 2,
                },
            ),
        ]
    );
    Ok(())
}

#[test]
fn cursor_rejects_overflow() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("bytes.bin", "file", 10, &"4".repeat(64), None)?;
    let overflowing_output = ByteMapping {
        offset: usize::MAX,
        range: SourceRange {
            source: source.clone(),
            packet: None,
            offset: 0,
            length: 1,
        },
    };
    let overflowing_source = ByteMapping {
        offset: 0,
        range: SourceRange {
            source,
            packet: None,
            offset: u64::MAX,
            length: 1,
        },
    };

    for mapping in [overflowing_output, overflowing_source] {
        assert!(matches!(
            CheckedByteMappingCursor::new(std::slice::from_ref(&mapping)),
            Err(EvidenceError::InvalidSourceRange)
        ));
        assert!(matches!(
            clip_byte_mappings(std::slice::from_ref(&mapping), 0..1),
            Err(EvidenceError::InvalidSourceRange)
        ));
    }
    Ok(())
}

#[test]
fn mapped_bytes_add_receipt() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mapping = mappings(&mut case)?;
    let id = case.add_mapped_bytes_node("recovered", b"AB", &mapping, json!({}))?;
    assert_eq!(case.nodes().len(), 2);
    assert_eq!(
        case.edges()
            .first()
            .map(|edge| (edge.from, edge.to, edge.relation.as_str())),
        Some((id, id + 1, "mapped_by"))
    );
    let receipt = case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == case.nodes().get(1).and_then(|node| node.blob.as_ref()))
        .ok_or("missing receipt")?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&receipt.bytes)?,
        serde_json::to_value(&mapping)?
    );
    case.validate()?;
    Ok(())
}

#[test]
fn byte_mapping_deserialization_rejects_unknown_and_malformed_fields() -> Result<(), Box<dyn Error>>
{
    let mapping = ByteMapping {
        offset: 4,
        range: SourceRange {
            source: format!("sha256:{}", "a".repeat(64)),
            packet: Some(3),
            offset: 100,
            length: 2,
        },
    };
    let encoded = serde_json::to_vec(&mapping)?;
    let decoded: ByteMapping = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.offset, 4);
    assert_eq!(decoded.range, mapping.range);

    let mut unknown_field: serde_json::Value = serde_json::from_slice(&encoded)?;
    unknown_field
        .as_object_mut()
        .ok_or("mapping did not serialize as an object")?
        .insert("unexpected".to_owned(), json!(true));
    assert!(serde_json::from_value::<ByteMapping>(unknown_field).is_err());

    let mut malformed_field: serde_json::Value = serde_json::from_slice(&encoded)?;
    malformed_field
        .as_object_mut()
        .ok_or("mapping did not serialize as an object")?
        .insert("offset".to_owned(), json!("4"));
    assert!(serde_json::from_value::<ByteMapping>(malformed_field).is_err());
    Ok(())
}

#[test]
fn receipt_failure_is_atomic() -> Result<(), Box<dyn Error>> {
    let mut case = Case::with_blob_limit(MAX_BLOB_TOTAL_BYTES)?;
    let mapping = mappings(&mut case)?;
    case.add_bytes_node(
        "retained",
        &vec![0; MAX_BLOB_TOTAL_BYTES - 2],
        Vec::new(),
        json!({}),
    )?;
    let before = case.clone();
    assert!(
        case.add_mapped_bytes_node("recovered", b"AB", &mapping, json!({}))
            .is_err()
    );
    assert_eq!(case, before);
    case.validate()?;
    Ok(())
}

#[test]
fn node_failure_is_atomic() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mapping = mappings(&mut case)?;
    for _ in 0..MAX_NODES - 1 {
        case.add_node("retained", None, Vec::new(), json!({}))?;
    }
    let before = case.clone();
    assert!(
        case.add_mapped_bytes_node("recovered", b"AB", &mapping, json!({}))
            .is_err()
    );
    assert_eq!(case, before);
    Ok(())
}
