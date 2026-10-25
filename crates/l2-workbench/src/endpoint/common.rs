use crate::{evidence::SourceRange, sha256};
use std::{error::Error, fmt};

/// Maximum number of detailed records retained by one native adapter
pub const MAX_ENDPOINT_RECORDS: usize = 65_536;

/// Failure to parse or validate a native endpoint source
#[derive(Debug)]
pub struct EndpointImportError(String);

impl fmt::Display for EndpointImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EndpointImportError {}

pub(super) fn source_id(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

pub(super) fn source_length(bytes: &[u8]) -> Result<u64, EndpointImportError> {
    u64::try_from(bytes.len()).map_err(|_| error("source length exceeds u64"))
}

pub(super) fn source_range(
    source: &str,
    offset: usize,
    length: usize,
) -> Result<SourceRange, EndpointImportError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| error("source range overflows"))?;
    let _ = end;
    Ok(SourceRange {
        source: source.to_owned(),
        packet: None,
        offset: u64::try_from(offset).map_err(|_| error("source offset exceeds u64"))?,
        length: u64::try_from(length).map_err(|_| error("source range length exceeds u64"))?,
    })
}

pub(super) fn read_bytes(
    bytes: &[u8],
    offset: usize,
    length: usize,
) -> Result<&[u8], EndpointImportError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| error("source offset overflows"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| error("source range exceeds input"))
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EndpointImportError> {
    let raw = read_bytes(bytes, offset, 2)?;
    let array = raw
        .try_into()
        .map_err(|_| error("16-bit field is truncated"))?;
    Ok(u16::from_le_bytes(array))
}

pub(super) fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, EndpointImportError> {
    read_bytes(bytes, offset, 1)?
        .first()
        .copied()
        .ok_or_else(|| error("8-bit field is truncated"))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EndpointImportError> {
    let raw = read_bytes(bytes, offset, 4)?;
    let array = raw
        .try_into()
        .map_err(|_| error("32-bit field is truncated"))?;
    Ok(u32::from_le_bytes(array))
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EndpointImportError> {
    let raw = read_bytes(bytes, offset, 8)?;
    let array = raw
        .try_into()
        .map_err(|_| error("64-bit field is truncated"))?;
    Ok(u64::from_le_bytes(array))
}

pub(super) fn read_u128(bytes: &[u8], offset: usize) -> Result<u128, EndpointImportError> {
    let raw = read_bytes(bytes, offset, 16)?;
    let array = raw
        .try_into()
        .map_err(|_| error("128-bit field is truncated"))?;
    Ok(u128::from_le_bytes(array))
}

pub(super) fn error(message: &str) -> EndpointImportError {
    EndpointImportError(message.to_owned())
}
