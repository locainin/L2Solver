#[path = "../src/bounded_json.rs"]
mod bounded_json;

use std::io::Cursor;

#[test]
fn enforces_json_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
    let value: Vec<u8> = bounded_json::read(Cursor::new(b"[1]"), 3)?;
    assert_eq!(value, [1]);
    assert!(bounded_json::read::<Vec<u8>>(Cursor::new(b"[1] "), 3).is_err());
    assert!(bounded_json::read::<Vec<u8>>(Cursor::new(b"[1]x"), 4).is_err());
    Ok(())
}

#[test]
fn rejects_malformed_json_inputs() {
    let nested = format!("{}0{}", "[".repeat(150), "]".repeat(150));
    assert!(bounded_json::read::<serde_json::Value>(Cursor::new(nested), 1024).is_err());
    assert!(bounded_json::read::<Vec<u8>>(Cursor::new(b"[1"), 3).is_err());
    assert!(bounded_json::read::<Vec<u8>>(std::io::repeat(b' '), 8).is_err());
}
