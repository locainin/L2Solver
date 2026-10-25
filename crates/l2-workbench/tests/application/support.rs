use l2_workbench::application::{ByteRange, ParseContext};

pub const COMPLETE: ParseContext = ParseContext {
    start_known: true,
    end_observed: true,
};

pub const OPEN_END: ParseContext = ParseContext {
    start_known: true,
    end_observed: false,
};

pub const UNKNOWN_START: ParseContext = ParseContext {
    start_known: false,
    end_observed: true,
};

pub fn locate(haystack: &[u8], needle: &[u8]) -> Result<ByteRange, &'static str> {
    let offset = haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or("fixture bytes are missing")?;
    Ok(ByteRange {
        offset,
        length: needle.len(),
    })
}

pub fn slice(source: &[u8], range: ByteRange) -> Result<&[u8], &'static str> {
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or("range overflow")?;
    source
        .get(range.offset..end)
        .ok_or("range is outside the source")
}

pub fn dns_query() -> Vec<u8> {
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01"
        .to_vec()
}

pub fn dns_tcp_frame(message: &[u8]) -> Result<Vec<u8>, &'static str> {
    let length = u16::try_from(message.len()).map_err(|_| "DNS fixture is too long")?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    Ok(frame)
}

pub fn append_dns_frame(target: &mut Vec<u8>, message: &[u8]) -> Result<ByteRange, &'static str> {
    let offset = target.len();
    let frame = dns_tcp_frame(message)?;
    let length = frame.len();
    target.extend_from_slice(&frame);
    Ok(ByteRange { offset, length })
}
