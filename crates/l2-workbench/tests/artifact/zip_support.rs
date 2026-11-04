use crc32fast::hash;
use flate2::{Compression, write::DeflateEncoder};
use std::error::Error;
use std::io::Write;

pub(super) fn entry_count_limited_zip() -> Vec<u8> {
    let mut bytes = b"PK\x03\x04PK\x05\x06".to_vec();
    bytes.extend_from_slice(&[0_u8; 4]);
    bytes.extend_from_slice(&4097_u16.to_le_bytes());
    bytes.extend_from_slice(&4097_u16.to_le_bytes());
    bytes.extend_from_slice(&[0_u8; 10]);
    bytes
}

pub(super) struct FixtureEntry<'a> {
    name: &'a [u8],
    uncompressed_size: usize,
    compressed_bytes: Vec<u8>,
    compressed_size: Option<usize>,
    method: u16,
    flags: u16,
    crc32: u32,
    descriptor: Option<FixtureDataDescriptor>,
}

#[derive(Clone, Copy)]
pub(super) enum DescriptorFormat {
    ClassicSigned,
    ClassicUnsigned,
}

#[derive(Clone, Copy)]
struct FixtureDataDescriptor {
    format: DescriptorFormat,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
}

impl<'a> FixtureEntry<'a> {
    pub(super) fn stored(name: &'a [u8], content: &'a [u8]) -> Self {
        Self {
            name,
            uncompressed_size: content.len(),
            compressed_bytes: content.to_vec(),
            compressed_size: None,
            method: 0,
            flags: 0,
            crc32: hash(content),
            descriptor: None,
        }
    }

    pub(super) fn deflated(name: &'a [u8], content: &[u8], compressed_bytes: Vec<u8>) -> Self {
        Self {
            name,
            uncompressed_size: content.len(),
            compressed_bytes,
            compressed_size: None,
            method: 8,
            flags: 0,
            crc32: hash(content),
            descriptor: None,
        }
    }

    pub(super) const fn with_method(mut self, method: u16) -> Self {
        self.method = method;
        self
    }

    pub(super) const fn with_crc(mut self, crc32: u32) -> Self {
        self.crc32 = crc32;
        self
    }

    pub(super) const fn with_declared_sizes(
        mut self,
        compressed_size: usize,
        expanded_size: usize,
    ) -> Self {
        self.compressed_size = Some(compressed_size);
        self.uncompressed_size = expanded_size;
        self
    }

    pub(super) const fn encrypted(mut self) -> Self {
        self.flags |= 1;
        self
    }

    pub(super) fn with_data_descriptor(mut self, format: DescriptorFormat) -> Self {
        let compressed_size = self.compressed_size.unwrap_or(self.compressed_bytes.len());
        self.flags |= 1 << 3;
        self.descriptor = Some(FixtureDataDescriptor {
            format,
            crc32: self.crc32,
            compressed_size: u32::try_from(compressed_size).unwrap_or(u32::MAX),
            uncompressed_size: u32::try_from(self.uncompressed_size).unwrap_or(u32::MAX),
        });
        self
    }

    pub(super) const fn with_data_descriptor_values(
        mut self,
        format: DescriptorFormat,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
    ) -> Self {
        self.flags |= 1 << 3;
        self.descriptor = Some(FixtureDataDescriptor {
            format,
            crc32,
            compressed_size,
            uncompressed_size,
        });
        self
    }

    const fn data_crc32(&self) -> u32 {
        self.crc32
    }
}

pub(super) fn deflate(content: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    Ok(encoder.finish()?)
}

pub(super) fn build_zip(entries: &[FixtureEntry<'_>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut archive = Vec::new();
    let mut central_entries = Vec::new();

    for entry in entries {
        let local_offset = u32::try_from(archive.len())?;
        let compressed_length = entry
            .compressed_size
            .unwrap_or(entry.compressed_bytes.len());
        let compressed_size = u32::try_from(compressed_length)?;
        let uncompressed_size = u32::try_from(entry.uncompressed_size)?;
        write_u32(&mut archive, 0x0403_4b50);
        write_u16(&mut archive, 20);
        write_u16(&mut archive, entry.flags);
        write_u16(&mut archive, entry.method);
        write_u16(&mut archive, 0);
        write_u16(&mut archive, 0);
        if entry.descriptor.is_some() {
            write_u32(&mut archive, 0);
            write_u32(&mut archive, 0);
            write_u32(&mut archive, 0);
        } else {
            write_u32(&mut archive, entry.data_crc32());
            write_u32(&mut archive, compressed_size);
            write_u32(&mut archive, uncompressed_size);
        }
        write_u16(&mut archive, u16::try_from(entry.name.len())?);
        write_u16(&mut archive, 0);
        archive.extend_from_slice(entry.name);
        archive.extend_from_slice(&entry.compressed_bytes);
        if let Some(descriptor) = entry.descriptor {
            if matches!(descriptor.format, DescriptorFormat::ClassicSigned) {
                write_u32(&mut archive, 0x0807_4b50);
            }
            write_u32(&mut archive, descriptor.crc32);
            write_u32(&mut archive, descriptor.compressed_size);
            write_u32(&mut archive, descriptor.uncompressed_size);
        }

        write_u32(&mut central_entries, 0x0201_4b50);
        write_u16(&mut central_entries, 20);
        write_u16(&mut central_entries, 20);
        write_u16(&mut central_entries, entry.flags);
        write_u16(&mut central_entries, entry.method);
        write_u16(&mut central_entries, 0);
        write_u16(&mut central_entries, 0);
        write_u32(&mut central_entries, entry.data_crc32());
        write_u32(&mut central_entries, compressed_size);
        write_u32(&mut central_entries, uncompressed_size);
        write_u16(&mut central_entries, u16::try_from(entry.name.len())?);
        write_u16(&mut central_entries, 0);
        write_u16(&mut central_entries, 0);
        write_u16(&mut central_entries, 0);
        write_u16(&mut central_entries, 0);
        write_u32(&mut central_entries, 0);
        write_u32(&mut central_entries, local_offset);
        central_entries.extend_from_slice(entry.name);
    }

    let central_directory_offset = u32::try_from(archive.len())?;
    let central_directory_size = u32::try_from(central_entries.len())?;
    archive.extend_from_slice(&central_entries);
    write_u32(&mut archive, 0x0605_4b50);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, u16::try_from(entries.len())?);
    write_u16(&mut archive, u16::try_from(entries.len())?);
    write_u32(&mut archive, central_directory_size);
    write_u32(&mut archive, central_directory_offset);
    write_u16(&mut archive, 0);
    Ok(archive)
}

pub(super) fn append_central_record(
    archive: &mut Vec<u8>,
    record: &[u8],
) -> Result<(), Box<dyn Error>> {
    let old_eocd = archive.len().checked_sub(22).ok_or("ZIP EOCD is missing")?;
    let old_size = u32::from_le_bytes(
        archive
            .get(old_eocd + 12..old_eocd + 16)
            .ok_or("ZIP central directory size is missing")?
            .try_into()?,
    );
    archive.splice(old_eocd..old_eocd, record.iter().copied());
    let new_eocd = old_eocd
        .checked_add(record.len())
        .ok_or("ZIP EOCD offset overflowed")?;
    let new_size = old_size
        .checked_add(u32::try_from(record.len())?)
        .ok_or("ZIP central directory size overflowed")?;
    archive
        .get_mut(new_eocd + 12..new_eocd + 16)
        .ok_or("ZIP central directory size is missing")?
        .copy_from_slice(&new_size.to_le_bytes());
    Ok(())
}

pub(super) fn prepend_central_record(
    archive: &mut Vec<u8>,
    record: &[u8],
) -> Result<(), Box<dyn Error>> {
    let old_eocd = archive.len().checked_sub(22).ok_or("ZIP EOCD is missing")?;
    let directory_offset = usize::try_from(u32::from_le_bytes(
        archive
            .get(old_eocd + 16..old_eocd + 20)
            .ok_or("ZIP central directory offset is missing")?
            .try_into()?,
    ))?;
    let old_size = u32::from_le_bytes(
        archive
            .get(old_eocd + 12..old_eocd + 16)
            .ok_or("ZIP central directory size is missing")?
            .try_into()?,
    );
    archive.splice(directory_offset..directory_offset, record.iter().copied());
    let new_eocd = old_eocd
        .checked_add(record.len())
        .ok_or("ZIP EOCD offset overflowed")?;
    let new_size = old_size
        .checked_add(u32::try_from(record.len())?)
        .ok_or("ZIP central directory size overflowed")?;
    archive
        .get_mut(new_eocd + 12..new_eocd + 16)
        .ok_or("ZIP central directory size is missing")?
        .copy_from_slice(&new_size.to_le_bytes());
    Ok(())
}

pub(super) fn add_optional_zip64_footer(archive: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    let eocd = archive.len().checked_sub(22).ok_or("ZIP EOCD is missing")?;
    let entries = u16::from_le_bytes(
        archive
            .get(eocd + 10..eocd + 12)
            .ok_or("ZIP entry count is missing")?
            .try_into()?,
    );
    let directory_size = u32::from_le_bytes(
        archive
            .get(eocd + 12..eocd + 16)
            .ok_or("ZIP central directory size is missing")?
            .try_into()?,
    );
    let directory_offset = u32::from_le_bytes(
        archive
            .get(eocd + 16..eocd + 20)
            .ok_or("ZIP central directory offset is missing")?
            .try_into()?,
    );
    let mut footer = Vec::new();
    write_u32(&mut footer, 0x0606_4b50);
    write_u64(&mut footer, 44);
    write_u16(&mut footer, 45);
    write_u16(&mut footer, 45);
    write_u32(&mut footer, 0);
    write_u32(&mut footer, 0);
    write_u64(&mut footer, u64::from(entries));
    write_u64(&mut footer, u64::from(entries));
    write_u64(&mut footer, u64::from(directory_size));
    write_u64(&mut footer, u64::from(directory_offset));
    write_u32(&mut footer, 0x0706_4b50);
    write_u32(&mut footer, 0);
    write_u64(&mut footer, u64::try_from(eocd)?);
    write_u32(&mut footer, 1);
    archive.splice(eocd..eocd, footer);
    Ok(())
}

pub(super) fn zip64_count_archive(entry_count: u64) -> Vec<u8> {
    let mut archive = Vec::new();
    write_u32(&mut archive, 0x0606_4b50);
    write_u64(&mut archive, 44);
    write_u16(&mut archive, 45);
    write_u16(&mut archive, 45);
    write_u32(&mut archive, 0);
    write_u32(&mut archive, 0);
    write_u64(&mut archive, entry_count);
    write_u64(&mut archive, entry_count);
    write_u64(&mut archive, 0);
    write_u64(&mut archive, 0);

    write_u32(&mut archive, 0x0706_4b50);
    write_u32(&mut archive, 0);
    write_u64(&mut archive, 0);
    write_u32(&mut archive, 1);

    write_u32(&mut archive, 0x0605_4b50);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, u16::MAX);
    write_u16(&mut archive, u16::MAX);
    write_u32(&mut archive, u32::MAX);
    write_u32(&mut archive, u32::MAX);
    write_u16(&mut archive, 0);
    archive
}

pub(super) fn zip64_data_descriptor_archive(
    name: &[u8],
    content: &[u8],
    signed: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut archive = Vec::new();
    let name_length = u16::try_from(name.len())?;
    let extra_length = 20_u16;
    let size = u64::try_from(content.len())?;
    let checksum = hash(content);

    // ZIP64 local sizes use sentinel values and zero-valued size placeholders with bit 3
    write_u32(&mut archive, 0x0403_4b50);
    write_u16(&mut archive, 45);
    write_u16(&mut archive, 1 << 3);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u32(&mut archive, 0);
    write_u32(&mut archive, u32::MAX);
    write_u32(&mut archive, u32::MAX);
    write_u16(&mut archive, name_length);
    write_u16(&mut archive, extra_length);
    archive.extend_from_slice(name);
    write_u16(&mut archive, 0x0001);
    write_u16(&mut archive, 16);
    write_u64(&mut archive, 0);
    write_u64(&mut archive, 0);
    archive.extend_from_slice(content);
    if signed {
        write_u32(&mut archive, 0x0807_4b50);
    }
    write_u32(&mut archive, checksum);
    write_u64(&mut archive, size);
    write_u64(&mut archive, size);

    let directory_offset = u64::try_from(archive.len())?;
    let mut directory = Vec::new();
    write_u32(&mut directory, 0x0201_4b50);
    write_u16(&mut directory, 45);
    write_u16(&mut directory, 45);
    write_u16(&mut directory, 1 << 3);
    write_u16(&mut directory, 0);
    write_u16(&mut directory, 0);
    write_u16(&mut directory, 0);
    write_u32(&mut directory, checksum);
    write_u32(&mut directory, u32::MAX);
    write_u32(&mut directory, u32::MAX);
    write_u16(&mut directory, name_length);
    write_u16(&mut directory, 28);
    write_u16(&mut directory, 0);
    write_u16(&mut directory, 0);
    write_u16(&mut directory, 0);
    write_u32(&mut directory, 0);
    write_u32(&mut directory, u32::MAX);
    directory.extend_from_slice(name);
    write_u16(&mut directory, 0x0001);
    write_u16(&mut directory, 24);
    write_u64(&mut directory, size);
    write_u64(&mut directory, size);
    write_u64(&mut directory, 0);
    let directory_size = u64::try_from(directory.len())?;
    archive.extend_from_slice(&directory);

    let zip64_eocd_offset = u64::try_from(archive.len())?;
    write_u32(&mut archive, 0x0606_4b50);
    write_u64(&mut archive, 44);
    write_u16(&mut archive, 45);
    write_u16(&mut archive, 45);
    write_u32(&mut archive, 0);
    write_u32(&mut archive, 0);
    write_u64(&mut archive, 1);
    write_u64(&mut archive, 1);
    write_u64(&mut archive, directory_size);
    write_u64(&mut archive, directory_offset);
    write_u32(&mut archive, 0x0706_4b50);
    write_u32(&mut archive, 0);
    write_u64(&mut archive, zip64_eocd_offset);
    write_u32(&mut archive, 1);
    write_u32(&mut archive, 0x0605_4b50);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, 0);
    write_u16(&mut archive, u16::MAX);
    write_u16(&mut archive, u16::MAX);
    write_u32(&mut archive, u32::MAX);
    write_u32(&mut archive, u32::MAX);
    write_u16(&mut archive, 0);

    Ok(archive)
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
