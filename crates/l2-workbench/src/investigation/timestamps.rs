use crate::evidence::SourceRange;
use l2_capture::{CaptureLocator, CapturedFrame};
use std::error::Error;

pub(super) fn ranges(
    source: &str,
    number: u32,
    frame: &CapturedFrame,
) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    if frame.metadata().timestamp().is_none() {
        return Ok(Vec::new());
    }
    let offset = match frame.metadata().locator() {
        Some(CaptureLocator::ClassicPcap { record_offset, .. }) => record_offset,
        Some(CaptureLocator::PcapNg {
            block_offset,
            block_type: 2 | 6,
            ..
        }) => block_offset
            .checked_add(12)
            .ok_or("timestamp field offset overflow")?,
        _ => return Ok(Vec::new()),
    };
    // These fields lie in record framing, separately from captured packet bytes
    Ok(vec![SourceRange {
        source: source.to_owned(),
        packet: Some(u64::from(number)),
        offset,
        length: 8,
    }])
}
