use std::error::Error;

pub fn sampled_non_vlan_scope(value: &serde_json::Value) {
    assert_eq!(value.pointer("/scope/vlan"), Some(&serde_json::Value::Null));
    assert_eq!(
        value
            .pointer("/scope/scope_validation")
            .and_then(serde_json::Value::as_str),
        Some("sampled")
    );
}

pub fn frame_hex(value: &serde_json::Value, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let encoded = value
        .get("frame_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing captured frame")?;
    assert_eq!(encoded.len(), expected.len() * 2);
    for (pair, byte) in encoded.as_bytes().chunks_exact(2).zip(expected) {
        assert_eq!(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?, *byte);
    }
    Ok(())
}
