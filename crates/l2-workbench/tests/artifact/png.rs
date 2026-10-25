use std::error::Error;

use l2_workbench::artifact::{self, FileRange, PNG_SIGNATURE, PngError, PngLimits};

#[test]
fn png_unknown_ranges_bytes_iend() -> Result<(), Box<dyn Error>> {
    let payload = [0x21, 0x22, 0x23];
    let bytes = png_with_private_payload(&payload)?;
    let expected_payload_offset = PNG_SIGNATURE.len() + encoded_chunk_length(13)? + 8;
    let report = artifact::parse_png(&bytes, PngLimits::default())?;

    assert_eq!(report.chunks.len(), 3);
    let private_chunk = report
        .chunks
        .get(1)
        .ok_or("missing generic private chunk")?;
    assert_eq!(private_chunk.payload, payload);
    assert_eq!(private_chunk.payload_range.offset, expected_payload_offset);
    assert_eq!(private_chunk.payload_range.length, payload.len());
    assert!(private_chunk.is_private());
    assert!(!private_chunk.is_critical());
    assert!(private_chunk.is_safe_to_copy());
    assert_eq!(report.bytes_after_iend, b"tail");
    assert_eq!(
        report.bytes_after_iend_range,
        FileRange {
            offset: bytes.len() - 4,
            length: 4
        }
    );
    Ok(())
}

#[test]
fn png_nested_signature_chunk_payload() -> Result<(), Box<dyn Error>> {
    let nested = minimal_png()?;
    let bytes = png_with_private_payload(&nested)?;
    let report = artifact::parse_png(&bytes, PngLimits::default())?;
    let nested_chunks: Vec<_> = report.nested_png_chunks().collect();

    assert_eq!(nested_chunks.len(), 1);
    assert_eq!(
        nested_chunks.first().map(|chunk| chunk.payload),
        Some(nested.as_slice())
    );
    let nested_chunk = nested_chunks
        .first()
        .ok_or("missing nested PNG candidate")?;
    let nested_report = artifact::parse_png(nested_chunk.payload, PngLimits::default())?;
    assert_eq!(nested_report.chunks.len(), 2);
    Ok(())
}

#[test]
fn png_bad_invalid_chunk_type() -> Result<(), Box<dyn Error>> {
    let mut bad_signature = minimal_png()?;
    if let Some(first) = bad_signature.first_mut() {
        *first ^= 0xff;
    }
    assert!(matches!(
        artifact::parse_png(&bad_signature, PngLimits::default()),
        Err(PngError::InvalidSignature)
    ));

    let mut truncated = PNG_SIGNATURE.to_vec();
    truncated.extend_from_slice(&u32::MAX.to_be_bytes());
    truncated.extend_from_slice(b"abCd");
    assert!(matches!(
        artifact::parse_png(&truncated, PngLimits::default()),
        Err(PngError::TruncatedChunk)
    ));

    let mut bad_crc = minimal_png()?;
    let crc_offset = PNG_SIGNATURE.len() + encoded_chunk_length(13)? - 1;
    if let Some(last_crc_byte) = bad_crc.get_mut(crc_offset) {
        *last_crc_byte ^= 0xff;
    }
    assert!(matches!(
        artifact::parse_png(&bad_crc, PngLimits::default()),
        Err(PngError::InvalidChecksum { .. })
    ));

    let bad_type = png_with_chunk_type(*b"ab1d", &[])?;
    assert!(matches!(
        artifact::parse_png(&bad_type, PngLimits::default()),
        Err(PngError::InvalidChunkType { .. })
    ));
    let bad_reserved_bit = png_with_chunk_type(*b"abcd", &[])?;
    assert!(matches!(
        artifact::parse_png(&bad_reserved_bit, PngLimits::default()),
        Err(PngError::InvalidChunkType { .. })
    ));
    Ok(())
}

#[test]
fn png_requires_zero_length_iend() -> Result<(), Box<dyn Error>> {
    let mut missing_ihdr = PNG_SIGNATURE.to_vec();
    missing_ihdr.extend_from_slice(&encode_chunk(*b"abCd", &[])?);
    missing_ihdr.extend_from_slice(&encode_chunk(*b"IEND", &[])?);
    assert!(matches!(
        artifact::parse_png(&missing_ihdr, PngLimits::default()),
        Err(PngError::IhdrNotFirst)
    ));

    let mut missing_iend = PNG_SIGNATURE.to_vec();
    missing_iend.extend_from_slice(&encode_chunk(*b"IHDR", &ihdr_payload())?);
    assert!(matches!(
        artifact::parse_png(&missing_iend, PngLimits::default()),
        Err(PngError::MissingIend)
    ));

    let mut nonempty_iend = PNG_SIGNATURE.to_vec();
    nonempty_iend.extend_from_slice(&encode_chunk(*b"IHDR", &ihdr_payload())?);
    nonempty_iend.extend_from_slice(&encode_chunk(*b"IEND", &[0x00])?);
    assert!(matches!(
        artifact::parse_png(&nonempty_iend, PngLimits::default()),
        Err(PngError::InvalidIendLength)
    ));

    let mut wrong_ihdr_length = PNG_SIGNATURE.to_vec();
    wrong_ihdr_length.extend_from_slice(&encode_chunk(*b"IHDR", &[0x01])?);
    wrong_ihdr_length.extend_from_slice(&encode_chunk(*b"IEND", &[])?);
    assert!(matches!(
        artifact::parse_png(&wrong_ihdr_length, PngLimits::default()),
        Err(PngError::InvalidIhdrLength)
    ));
    Ok(())
}

#[test]
fn png_enforces_input_chunk_budgets() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_png()?;
    let too_small = PngLimits {
        max_input_bytes: bytes.len() - 1,
        ..PngLimits::default()
    };
    assert!(matches!(
        artifact::parse_png(&bytes, too_small),
        Err(PngError::InputTooLarge { .. })
    ));

    let no_chunks = PngLimits {
        max_chunks: 1,
        ..PngLimits::default()
    };
    assert!(matches!(
        artifact::parse_png(&bytes, no_chunks),
        Err(PngError::TooManyChunks { .. })
    ));
    Ok(())
}

fn png_with_private_payload(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    bytes.extend_from_slice(&encode_chunk(*b"IHDR", &ihdr_payload())?);
    bytes.extend_from_slice(&encode_chunk(*b"abCd", payload)?);
    bytes.extend_from_slice(&encode_chunk(*b"IEND", &[])?);
    bytes.extend_from_slice(b"tail");
    Ok(bytes)
}

fn png_with_chunk_type(chunk_type: [u8; 4], payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    bytes.extend_from_slice(&encode_chunk(*b"IHDR", &ihdr_payload())?);
    bytes.extend_from_slice(&encode_chunk(chunk_type, payload)?);
    bytes.extend_from_slice(&encode_chunk(*b"IEND", &[])?);
    Ok(bytes)
}

pub(super) fn minimal_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = PNG_SIGNATURE.to_vec();
    bytes.extend_from_slice(&encode_chunk(*b"IHDR", &ihdr_payload())?);
    bytes.extend_from_slice(&encode_chunk(*b"IEND", &[])?);
    Ok(bytes)
}

const fn ihdr_payload() -> [u8; 13] {
    [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]
}

fn encode_chunk(chunk_type: [u8; 4], payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = u32::try_from(payload.len())?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&chunk_type);
    crc.update(payload);
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&length.to_be_bytes());
    chunk.extend_from_slice(&chunk_type);
    chunk.extend_from_slice(payload);
    chunk.extend_from_slice(&crc.finalize().to_be_bytes());
    Ok(chunk)
}

fn encoded_chunk_length(payload_length: usize) -> Result<usize, Box<dyn Error>> {
    payload_length
        .checked_add(12)
        .ok_or_else(|| "chunk length overflow".into())
}
