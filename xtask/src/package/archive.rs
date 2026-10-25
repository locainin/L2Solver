//! Deterministic ZIP assembly

use super::{Entry, MAX_ARCHIVE_BYTES, MAX_FILES, PackageError};
use sha2::{Digest, Sha256};

const UTF8_NAMES: u16 = 0x0800;

pub(super) fn build_zip(entries: &[Entry]) -> Result<Vec<u8>, PackageError> {
    if entries.len() > MAX_FILES {
        return Err(PackageError::TooManyFiles {
            count: entries.len(),
            maximum: MAX_FILES,
        });
    }
    let archive_capacity = checked_archive_size(
        entries
            .iter()
            .map(|entry| (entry.path.len(), entry.bytes.len())),
    )?;
    // The exact final size is known before either ZIP buffer is allocated
    let mut archive = Vec::with_capacity(archive_capacity);
    let mut central = Vec::new();
    for entry in entries {
        let name = entry.path.as_bytes();
        let name_length =
            u16::try_from(name.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
        let size =
            u32::try_from(entry.bytes.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
        let offset =
            u32::try_from(archive.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
        let crc = crc32(&entry.bytes);

        write_u32(&mut archive, 0x0403_4b50);
        write_u16(&mut archive, 20);
        write_u16(&mut archive, UTF8_NAMES);
        write_u16(&mut archive, 0);
        write_u16(&mut archive, 0);
        write_u16(&mut archive, 0x0021);
        write_u32(&mut archive, crc);
        write_u32(&mut archive, size);
        write_u32(&mut archive, size);
        write_u16(&mut archive, name_length);
        write_u16(&mut archive, 0);
        archive.extend_from_slice(name);
        archive.extend_from_slice(&entry.bytes);

        write_u32(&mut central, 0x0201_4b50);
        write_u16(&mut central, 20);
        write_u16(&mut central, 20);
        write_u16(&mut central, UTF8_NAMES);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0x0021);
        write_u32(&mut central, crc);
        write_u32(&mut central, size);
        write_u32(&mut central, size);
        write_u16(&mut central, name_length);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u32(&mut central, 0);
        write_u32(&mut central, offset);
        central.extend_from_slice(name);
    }
    let central_offset =
        u32::try_from(archive.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
    let central_size =
        u32::try_from(central.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
    let entry_count =
        u16::try_from(entries.len()).map_err(|_| PackageError::ArchiveFieldOverflow)?;
    archive.extend_from_slice(&central);
    write_u32(&mut archive, 0x0605_4b50);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, entry_count);
    write_u16(&mut archive, entry_count);
    write_u32(&mut archive, central_size);
    write_u32(&mut archive, central_offset);
    write_u16(&mut archive, 0);
    Ok(archive)
}

pub(super) fn checked_archive_size(
    entries: impl IntoIterator<Item = (usize, usize)>,
) -> Result<usize, PackageError> {
    const LOCAL_HEADER_BYTES: usize = 30;
    const CENTRAL_HEADER_BYTES: usize = 46;
    const END_RECORD_BYTES: usize = 22;

    let mut total = END_RECORD_BYTES;
    for (name_bytes, data_bytes) in entries {
        if u16::try_from(name_bytes).is_err() || u32::try_from(data_bytes).is_err() {
            return Err(PackageError::ArchiveFieldOverflow);
        }
        total = total
            .checked_add(LOCAL_HEADER_BYTES)
            .and_then(|value| value.checked_add(name_bytes))
            .and_then(|value| value.checked_add(data_bytes))
            .and_then(|value| value.checked_add(CENTRAL_HEADER_BYTES))
            .and_then(|value| value.checked_add(name_bytes))
            .ok_or(PackageError::ArchiveTooLarge {
                size: usize::MAX,
                maximum: MAX_ARCHIVE_BYTES,
            })?;
        if total > MAX_ARCHIVE_BYTES {
            return Err(PackageError::ArchiveTooLarge {
                size: total,
                maximum: MAX_ARCHIVE_BYTES,
            });
        }
    }
    Ok(total)
}

pub(super) fn digest_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

pub(super) fn render_manifest(number: u32, entries: &[Entry], archive_sha256: &str) -> String {
    let mut output = format!(
        "L2Solver review package\nmanifest_format: 1\nreview: {number}\narchive: review-{number}.zip\narchive_sha256: {archive_sha256}\nfiles: {}\n\npath\tbytes\tsha256\n",
        entries.len()
    );
    for entry in entries {
        output.push_str(&entry.path);
        output.push('\t');
        output.push_str(&entry.bytes.len().to_string());
        output.push('\t');
        output.push_str(&entry.sha256);
        output.push('\n');
    }
    output
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let bit = crc & 1;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xedb8_8320;
            }
        }
    }
    !crc
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '?',
    }
}
