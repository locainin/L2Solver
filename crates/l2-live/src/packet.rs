//! Validate borrowed libpcap data before allocating retained capture evidence

use l2_capture::{
    CaptureMetadata, CapturedFrame, Direction, InterfaceId, LinkType, LinuxInterfaceIdentity,
    MAX_FRAME_LENGTH,
};
use std::io;

/// Validate borrowed libpcap data with the selected checked data-link identity
pub fn capture_with_link_type<Seconds, Fraction>(
    source: LinuxInterfaceIdentity,
    link_type: LinkType,
    bytes: &[u8],
    captured: u32,
    original: u32,
    seconds: Seconds,
    microseconds: Fraction,
) -> io::Result<CapturedFrame>
where
    Seconds: Into<i64>,
    Fraction: Into<i64>,
{
    // Snaplen normally enforces this bound; the copy boundary checks it independently
    if bytes.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::other("live frame exceeds capture limit"));
    }
    if usize::try_from(captured).map_err(io::Error::other)? != bytes.len() {
        return Err(io::Error::other(
            "libpcap captured length disagrees with data",
        ));
    }
    if captured > original {
        return Err(io::Error::other(
            "libpcap captured length exceeds original length",
        ));
    }
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 0,
        },
        original,
        None,
        Some(
            super::metadata::timestamp(seconds.into(), microseconds.into())
                .map_err(io::Error::other)?,
        ),
        // Direction filtering is not per-packet provenance
        Direction::Unknown,
        None,
        l2_capture::FcsStatus::Unknown,
    )
    .with_link_type(link_type)
    .with_linux_interface(source);
    CapturedFrame::new(bytes.to_vec(), metadata).map_err(io::Error::other)
}
