use super::HashingReader;
use sha2::{Digest, Sha256};
use std::io::Read;

#[test]
fn hashing_reader_through_clean_eof() -> Result<(), Box<dyn std::error::Error>> {
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut output = Vec::new();
    let mut reader = HashingReader {
        inner: &b"1234"[..],
        hash: &mut hash,
        length: &mut length,
    };
    reader.read_to_end(&mut output)?;
    assert_eq!(length, 4);
    assert_eq!(output, b"1234");
    assert_eq!(
        format!("{:x}", hash.finalize()),
        l2_workbench::sha256(b"1234")
    );
    Ok(())
}
