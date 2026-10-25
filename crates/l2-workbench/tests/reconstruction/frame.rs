use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

pub fn frame(
    interface: u32,
    input: &CapturedFrame,
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    Ok(CapturedFrame::new(
        input.bytes().to_vec(),
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: interface,
            },
            u32::try_from(input.bytes().len())?,
        ),
    )?)
}
