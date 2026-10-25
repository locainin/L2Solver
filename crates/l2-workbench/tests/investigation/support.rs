use l2_capture::{CaptureLocator, CaptureMetadata, CapturedFrame};
use l2_workbench::investigation::Record;
use std::error::Error;

pub fn located_records(frames: Vec<CapturedFrame>) -> Result<(Vec<Record>, u64), Box<dyn Error>> {
    let mut offset = 24;
    let mut records = Vec::new();
    for (index, frame) in frames.into_iter().enumerate() {
        let metadata = CaptureMetadata::new(
            frame.metadata().interface(),
            frame.metadata().original_len(),
            Some(CaptureLocator::ClassicPcap {
                record_offset: offset,
                data_offset: offset + 16,
            }),
            frame.metadata().timestamp(),
            frame.metadata().direction(),
            frame.metadata().vlan(),
            frame.metadata().fcs(),
        )
        .with_link_type(frame.metadata().link_type());
        offset += 16 + u64::try_from(frame.bytes().len())?;
        records.push(Record {
            number: u32::try_from(index + 1)?,
            frame: CapturedFrame::new(frame.bytes().to_vec(), metadata)?,
        });
    }
    Ok((records, offset))
}
