//! Portable bitmap encoding for exact unreachable-pixel masks

use l2_workbench::artifact::PixelCoordinate;
use std::error::Error;

pub(super) fn encode_pbm(
    width: u32,
    height: u32,
    coordinates: &[PixelCoordinate],
    maximum_bytes: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let header = format!("P4\n{width} {height}\n");
    let row_bytes = usize::try_from(width)?.div_ceil(8);
    let body_bytes = row_bytes
        .checked_mul(usize::try_from(height)?)
        .ok_or("reachability mask size overflow")?;
    let total = header
        .len()
        .checked_add(body_bytes)
        .ok_or("reachability mask size overflow")?;
    if total > maximum_bytes {
        return Err(format!(
            "reachability mask requires {total} bytes; maximum is {maximum_bytes}"
        )
        .into());
    }

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total)?;
    if bytes.capacity() > maximum_bytes {
        return Err(format!(
            "reachability mask allocated {} bytes; maximum is {maximum_bytes}",
            bytes.capacity()
        )
        .into());
    }
    bytes.extend_from_slice(header.as_bytes());
    bytes.resize(total, 0);

    // PBM stores one black pixel as a high-order-first set bit
    for coordinate in coordinates {
        if coordinate.x >= width || coordinate.y >= height {
            return Err("unreachable pixel lies outside the decoded image".into());
        }
        let row = usize::try_from(coordinate.y)?;
        let column = usize::try_from(coordinate.x)?;
        let byte_offset = row
            .checked_mul(row_bytes)
            .and_then(|offset| offset.checked_add(column / 8))
            .and_then(|offset| offset.checked_add(header.len()))
            .ok_or("reachability mask offset overflow")?;
        let byte = bytes
            .get_mut(byte_offset)
            .ok_or("reachability mask offset is outside the output")?;
        *byte |= 0x80_u8 >> (column % 8);
    }
    Ok(bytes)
}
