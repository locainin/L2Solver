use super::super::decode::{DecodeError, decode_packets};
use serde_json::{Value, json};
use std::error::Error;

#[test]
fn decoded_json_reference() -> Result<(), Box<dyn Error>> {
    let bytes = br#"[{"_source":{"layers":{
        "frame":{"frame.number":"1"},
        "values":[true,false,null,-7,1.25,"line\n\u00e9"],
        "duplicate":{"key":"old","key":"new"},
        "tcp":{"tcp.reassembled.data":"abc"}
    }}}]"#;
    let reference: Value = serde_json::from_slice(bytes)?;

    let packets = decode_packets(bytes, bytes.len(), 1024 * 1024)?;

    let packet = packets.first().ok_or("decoded packet missing")?;
    assert_eq!(Some(&packet.fields), reference.pointer("/0/_source/layers"));
    assert_eq!(packet.fields.pointer("/duplicate/key"), Some(&json!("new")));
    assert!(packet.reassembled_fields.contains("tcp.reassembled.data"));
    Ok(())
}

#[test]
fn raw_capacity_exact_admission_limit() -> Result<(), Box<dyn Error>> {
    assert_eq!(decode_packets(b"[]", 2, 2)?.len(), 0);
    assert!(matches!(
        decode_packets(b"[]", 3, 2),
        Err(DecodeError::MemoryLimit {
            limit: 2,
            used: 0,
            requested: 3
        })
    ));
    Ok(())
}

#[test]
fn short_escape_large_whitespace_admission() -> Result<(), Box<dyn Error>> {
    let mut bytes =
        br#"[{"_source":{"layers":{"frame":{"frame.number":"1"},"text":"\n"}}}]"#.to_vec();
    bytes.resize(262_300, b' ');

    let packets = decode_packets(&bytes, bytes.capacity(), 1024 * 1024)?;

    let packet = packets.first().ok_or("decoded packet missing")?;
    assert_eq!(packet.fields.get("text"), Some(&json!("\n")));
    Ok(())
}

#[test]
fn escaped_quote_and_unicode_scratch_admission() -> Result<(), Box<dyn Error>> {
    let mut bytes =
        b"[{\"_source\":{\"layers\":{\"frame\":{\"frame.number\":1},\"first\":\"".to_vec();
    bytes.extend_from_slice(b"\\\\");
    bytes.extend_from_slice(b"\",\"text\":\"");
    bytes.extend_from_slice(b"\\\"");
    for _ in 0..10_000 {
        bytes.extend_from_slice(b"\\uD83D\\uDE00");
    }
    bytes.extend_from_slice(br#""}}}]"#);

    let reference: Value = serde_json::from_slice(&bytes)?;
    let packets = decode_packets(&bytes, bytes.len(), 2 * 1024 * 1024)?;
    assert_eq!(
        packets.first().map(|packet| &packet.fields),
        reference.pointer("/0/_source/layers")
    );
    let result = decode_packets(&bytes, bytes.len(), bytes.len() + 1024);
    assert!(matches!(
        result,
        Err(DecodeError::MemoryLimit { used, requested, .. })
            if used == bytes.len() && requested >= 360_000
    ));
    Ok(())
}

#[test]
fn unfinished_escaped_string_scratch_admission() {
    let bytes = br#"[{"_source":{"layers":{"frame":{"frame.number":1},"text":"line\n"#;
    assert!(matches!(
        decode_packets(bytes, bytes.len(), bytes.len() + 1),
        Err(DecodeError::MemoryLimit { used, requested, .. })
            if used == bytes.len() && requested >= 24
    ));
    assert!(matches!(
        decode_packets(bytes, bytes.len(), 1024 * 1024),
        Err(DecodeError::Json(_))
    ));
}

#[test]
fn malformed_json_error_class() -> Result<(), Box<dyn Error>> {
    let error = decode_packets(b"[", 1, 1024)
        .err()
        .ok_or("truncated JSON was accepted")?;
    assert!(matches!(&error, DecodeError::Json(_)));
    assert!(error.to_string().contains("invalid TShark JSON"));
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}

#[test]
fn packet_array_diagnostic() -> Result<(), Box<dyn Error>> {
    let error = decode_packets(b"{}", 2, 1024)
        .err()
        .ok_or("packet object was accepted")?;
    assert!(error.to_string().contains("an array of TShark packets"));
    Ok(())
}

#[test]
fn nesting_boundary() -> Result<(), Box<dyn Error>> {
    for (arrays, accepted) in [(92, true), (93, false)] {
        let mut payload = Value::Null;
        for _ in 0..arrays {
            payload = Value::Array(vec![payload]);
        }
        // The packet, source and layers objects occupy the first three levels
        let input = json!([{"_source":{"layers":{
            "frame":{"frame.number":1}, "payload":payload
        }}}]);
        let bytes = serde_json::to_vec(&input)?;
        let result = decode_packets(&bytes, bytes.len(), 1024 * 1024);
        if accepted {
            assert_eq!(result?.len(), 1, "{arrays} nested arrays");
        } else {
            assert!(matches!(result, Err(DecodeError::NestingLimit)));
        }
    }
    Ok(())
}

#[test]
fn serialized_packet_bytes_stable() -> Result<(), Box<dyn Error>> {
    let bytes = br#"[{"_source":{"layers":{"frame":{"frame.number":1}}}},{"_source":{"layers":{"frame":{"frame.number":2}}}}]"#;

    let packets = decode_packets(bytes, bytes.len(), 1024 * 1024)?;

    assert_eq!(
        serde_json::to_vec(&packets)?,
        br#"[{"packet_number":1,"tool_derived":true,"fields":{"frame":{"frame.number":1}},"reassembled_fields":[]},{"packet_number":2,"tool_derived":true,"fields":{"frame":{"frame.number":2}},"reassembled_fields":[]}]"#
    );
    Ok(())
}
