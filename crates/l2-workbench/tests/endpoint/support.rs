use std::fmt::{self, Write as _};

/// Build one valid generic USN V2 record
pub fn usn_v2_record(usn: u64, name: &str) -> Result<Vec<u8>, FixtureError> {
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut record = vec![0_u8; 60 + encoded.len()];
    let record_len = u32::try_from(record.len())?;
    let name_len = u16::try_from(encoded.len())?;
    put_u32(&mut record, 0, record_len)?;
    put_u16(&mut record, 4, 2)?;
    put_u16(&mut record, 6, 0)?;
    put_u64(&mut record, 8, 17)?;
    put_u64(&mut record, 16, 8)?;
    put_u64(&mut record, 24, usn)?;
    put_u64(&mut record, 32, 100)?;
    put_u32(&mut record, 40, 0x0000_8000)?;
    put_u32(&mut record, 52, 0x20)?;
    put_u16(&mut record, 56, name_len)?;
    put_u16(&mut record, 58, 60)?;
    put_bytes(&mut record, 60, &encoded)?;
    Ok(record)
}

/// Build one valid generic USN V3 record
pub fn usn_v3_record(usn: u64, name: &str) -> Result<Vec<u8>, FixtureError> {
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut record = vec![0_u8; 76 + encoded.len()];
    let record_len = u32::try_from(record.len())?;
    let name_len = u16::try_from(encoded.len())?;
    put_u32(&mut record, 0, record_len)?;
    put_u16(&mut record, 4, 3)?;
    put_u16(&mut record, 6, 0)?;
    put_u128(&mut record, 8, 17)?;
    put_u128(&mut record, 24, 8)?;
    put_u64(&mut record, 40, usn)?;
    put_u64(&mut record, 48, 100)?;
    put_u32(&mut record, 56, 0x0000_8000)?;
    put_u32(&mut record, 68, 0x20)?;
    put_u16(&mut record, 72, name_len)?;
    put_u16(&mut record, 74, 76)?;
    put_bytes(&mut record, 76, &encoded)?;
    Ok(record)
}

/// Build one valid generic MFT FILE record
pub fn mft_record(si_creation_time: u64) -> Result<Vec<u8>, FixtureError> {
    let mut record = vec![0_u8; 1024];
    put_bytes(&mut record, 0, b"FILE")?;
    put_u16(&mut record, 4, 48)?;
    put_u16(&mut record, 6, 3)?;
    put_u16(&mut record, 16, 1)?;
    put_u16(&mut record, 20, 56)?;
    put_u16(&mut record, 22, 1)?;
    put_u32(&mut record, 24, 240)?;
    put_u32(&mut record, 28, 1024)?;
    put_u32(&mut record, 44, 1)?;
    put_u16(&mut record, 48, 0xaaaa)?;
    put_u16(&mut record, 50, 0x1111)?;
    put_u16(&mut record, 52, 0x2222)?;
    put_si(&mut record, 56, si_creation_time)?;
    put_filename(&mut record, 128, "alpha.bin", 100)?;
    put_u32(&mut record, 236, u32::MAX)?;
    put_u16(&mut record, 510, 0xaaaa)?;
    put_u16(&mut record, 1022, 0xaaaa)?;
    Ok(record)
}

/// Build one generic Sysmon XML event
pub fn sysmon_event_xml() -> String {
    "<Events><Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>2</EventID><EventRecordID>18</EventRecordID><TimeCreated SystemTime=\"2025-01-02T00:00:00.0000000Z\"/></System><EventData><Data Name=\"UtcTime\">2025-01-02T00:00:00.0000000Z</Data><Data Name=\"ProcessGuid\">{A}</Data><Data Name=\"ProcessId\">12</Data><Data Name=\"Image\">worker.exe</Data><Data Name=\"TargetFilename\">C:\\Temp\\alpha.bin</Data><Data Name=\"PreviousCreationUtcTime\">2025-01-01T00:00:00.0000000Z</Data><Data Name=\"CreationUtcTime\">2025-01-02T00:00:00.0000000Z</Data></EventData></Event></Events>".to_owned()
}

/// Build one generic EVTX file envelope with a single record
pub fn evtx_file() -> Result<Vec<u8>, FixtureError> {
    let mut file = vec![0_u8; 4096 + 65_536];
    put_bytes(&mut file, 0, b"ElfFile\0")?;
    put_u32(&mut file, 32, 128)?;
    put_u16(&mut file, 36, 1)?;
    put_u16(&mut file, 38, 3)?;
    put_u16(&mut file, 40, 4096)?;
    put_u16(&mut file, 42, 1)?;
    put_bytes(&mut file, 4096, b"ElfChnk\0")?;
    put_u64(&mut file, 4096 + 24, 7)?;
    put_u64(&mut file, 4096 + 32, 7)?;
    put_u32(&mut file, 4096 + 40, 128)?;
    put_u32(&mut file, 4096 + 44, 512)?;
    put_u32(&mut file, 4096 + 48, 544)?;
    put_bytes(&mut file, 4096 + 512, b"**\0\0")?;
    put_u32(&mut file, 4096 + 516, 32)?;
    put_u64(&mut file, 4096 + 520, 7)?;
    put_u64(&mut file, 4096 + 528, 13)?;
    put_u32(&mut file, 4096 + 540, 32)?;
    let records_crc = {
        let chunk = file
            .get(4096..)
            .ok_or(FixtureError("EVTX chunk is missing"))?;
        crc(chunk
            .get(512..544)
            .ok_or(FixtureError("EVTX records are missing"))?)
    };
    put_u32(&mut file, 4096 + 52, records_crc)?;
    let chunk_header_crc = {
        let chunk = file
            .get(4096..)
            .ok_or(FixtureError("EVTX chunk is missing"))?;
        crc_parts(
            chunk
                .get(..120)
                .ok_or(FixtureError("EVTX chunk header is missing"))?,
            chunk
                .get(128..512)
                .ok_or(FixtureError("EVTX chunk header is truncated"))?,
        )
    };
    put_u32(&mut file, 4096 + 124, chunk_header_crc)?;
    let header = file
        .get(..120)
        .ok_or(FixtureError("EVTX header is truncated"))?;
    let header_crc = crc(header);
    put_u32(&mut file, 124, header_crc)?;
    Ok(file)
}

/// Build one complete outbound UDP strace line
pub fn strace_sendto_line(endpoints: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = String::with_capacity(payload.len().saturating_mul(4));
    for byte in payload {
        let _ = write!(encoded, "\\x{byte:02x}");
    }
    format!(
        "412 sendto(5<UDP:[{endpoints}]>, \"{encoded}\", {}, 0, NULL, 0) = {}\n",
        payload.len(),
        payload.len()
    )
    .into_bytes()
}

/// Write one little-endian 16-bit field within a fixture
pub fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FixtureError> {
    put_bytes(bytes, offset, &value.to_le_bytes())
}

/// Write one little-endian 32-bit field within a fixture
pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FixtureError> {
    put_bytes(bytes, offset, &value.to_le_bytes())
}

/// Write one little-endian 64-bit field within a fixture
pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), FixtureError> {
    put_bytes(bytes, offset, &value.to_le_bytes())
}

fn put_u128(bytes: &mut [u8], offset: usize, value: u128) -> Result<(), FixtureError> {
    put_bytes(bytes, offset, &value.to_le_bytes())
}

fn put_si(record: &mut [u8], offset: usize, creation_time: u64) -> Result<(), FixtureError> {
    put_u32(record, offset, 0x10)?;
    put_u32(record, offset + 4, 72)?;
    put_u32(record, offset + 16, 48)?;
    put_u16(record, offset + 20, 24)?;
    put_u64(record, offset + 24, creation_time)?;
    put_u64(record, offset + 32, 200)?;
    put_u64(record, offset + 40, 300)?;
    put_u64(record, offset + 48, 400)?;
    Ok(())
}

fn put_filename(
    record: &mut [u8],
    offset: usize,
    name: &str,
    creation_time: u64,
) -> Result<(), FixtureError> {
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let value_len = 66 + encoded.len();
    put_u32(record, offset, 0x30)?;
    put_u32(record, offset + 4, u32::try_from(24 + value_len)?)?;
    put_u32(record, offset + 16, u32::try_from(value_len)?)?;
    put_u16(record, offset + 20, 24)?;
    put_u64(record, offset + 24, 0)?;
    put_u64(record, offset + 32, creation_time)?;
    put_u64(record, offset + 40, 200)?;
    put_u64(record, offset + 48, 300)?;
    put_u64(record, offset + 56, 400)?;
    let name_length = u8::try_from(name.encode_utf16().count())?;
    let name_slot = record
        .get_mut(offset + 24 + 64)
        .ok_or(FixtureError("filename length slot missing"))?;
    *name_slot = name_length;
    let namespace_slot = record
        .get_mut(offset + 24 + 65)
        .ok_or(FixtureError("filename namespace slot missing"))?;
    *namespace_slot = 1;
    put_bytes(record, offset + 24 + 66, &encoded)?;
    Ok(())
}

fn crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn crc_parts(first: &[u8], second: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize()
}

fn put_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), FixtureError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(FixtureError("fixture range overflow"))?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or(FixtureError("fixture range outside buffer"))?;
    target.copy_from_slice(value);
    Ok(())
}

#[derive(Debug)]
/// Generic checked fixture builder failure
pub struct FixtureError(
    /// Short reason that a requested fixture could not be built
    pub &'static str,
);

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for FixtureError {}

impl From<std::num::TryFromIntError> for FixtureError {
    fn from(_: std::num::TryFromIntError) -> Self {
        Self("fixture integer is out of range")
    }
}
