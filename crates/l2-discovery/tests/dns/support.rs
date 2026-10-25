use std::ops::Range;

pub fn header(
    id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    for value in [id, flags, questions, answers, authorities, additionals] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

pub fn labels(parts: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let mut encoded = Vec::new();
    for part in parts {
        // Each ordinary DNS label is capped at 63 octets
        let length =
            u8::try_from(part.len()).map_err(|_| "label length does not fit in one byte")?;
        if length > 63 {
            return Err("label exceeds the DNS label limit");
        }
        encoded.push(length);
        encoded.extend_from_slice(part);
    }
    encoded.push(0);
    Ok(encoded)
}

pub fn append_question(bytes: &mut Vec<u8>, encoded_name: &[u8], qtype: u16, qclass: u16) {
    bytes.extend_from_slice(encoded_name);
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&qclass.to_be_bytes());
}

pub fn append_record(
    bytes: &mut Vec<u8>,
    encoded_owner: &[u8],
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Result<Range<usize>, &'static str> {
    // Capture the byte range before appending RDATA for provenance assertions
    let rdata_length =
        u16::try_from(rdata.len()).map_err(|_| "RDATA length does not fit in u16")?;
    bytes.extend_from_slice(encoded_owner);
    bytes.extend_from_slice(&rr_type.to_be_bytes());
    bytes.extend_from_slice(&class.to_be_bytes());
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&rdata_length.to_be_bytes());
    let start = bytes.len();
    bytes.extend_from_slice(rdata);
    let end = bytes.len();
    Ok(start..end)
}

pub const fn root_name() -> [u8; 1] {
    [0]
}

pub fn pointer(target: usize) -> Result<[u8; 2], &'static str> {
    // The top two bits mark a pointer and the remaining bits hold its prior offset
    if target > 0x3fff {
        return Err("DNS compression target exceeds the 14-bit pointer limit");
    }
    let pointer =
        0xc000_u16 | u16::try_from(target).map_err(|_| "pointer target does not fit in u16")?;
    Ok(pointer.to_be_bytes())
}

pub fn range_bytes(payload: &[u8], start: usize, end: usize) -> Result<&[u8], &'static str> {
    payload
        .get(start..end)
        .ok_or("test fixture range is outside the payload")
}

pub struct MultiSectionRecordFixture {
    pub bytes: Vec<u8>,
    pub rdata_ranges: [Range<usize>; 6],
    pub aaaa_address: [u8; 16],
    pub cname_wire: Vec<u8>,
    pub question_wire: Vec<u8>,
}

pub fn multi_section_record_fixture() -> Result<MultiSectionRecordFixture, &'static str> {
    let mut bytes = header(0x8a30, 0xa803, 1, 2, 2, 2);
    let question_wire = labels(&[b"Host", b"Example"])?;
    let question_offset = bytes.len();
    append_question(&mut bytes, &question_wire, 1, 1);
    let owner = root_name();

    // This owner points back to the question name; later records use the root owner
    let compressed_owner = pointer(question_offset)?;
    let a_range = append_record(&mut bytes, &compressed_owner, 1, 1, 60, &[192, 0, 2, 7])?;
    let aaaa_address = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
    let aaaa_range = append_record(&mut bytes, &owner, 28, 1, 120, &aaaa_address)?;
    let cname_wire = labels(&[b"Alias", b"Example"])?;
    let cname_range = append_record(&mut bytes, &owner, 5, 1, 30, &cname_wire)?;
    let ns_range = append_record(&mut bytes, &owner, 2, 1, 300, &pointer(question_offset)?)?;
    let ptr_range = append_record(&mut bytes, &owner, 12, 1, 300, &pointer(question_offset)?)?;
    let opt_range = append_record(&mut bytes, &owner, 41, 1232, 0, &[])?;

    Ok(MultiSectionRecordFixture {
        bytes,
        rdata_ranges: [
            a_range,
            aaaa_range,
            cname_range,
            ns_range,
            ptr_range,
            opt_range,
        ],
        aaaa_address,
        cname_wire,
        question_wire,
    })
}
