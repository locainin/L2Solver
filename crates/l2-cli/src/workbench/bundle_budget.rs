use std::{error::Error, io};

pub(super) const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub(super) fn charge_document(total: u64, length: usize) -> Result<u64, Box<dyn Error>> {
    // Each prefix starts at zero or comes from an accepted charge
    let remaining = MAX_BUNDLE_BYTES - total;
    let length = u64::try_from(length)?;
    if length > remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bundle exceeds the aggregate document byte limit",
        )
        .into());
    }
    Ok(total + length)
}
