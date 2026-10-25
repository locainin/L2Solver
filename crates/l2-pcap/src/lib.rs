//! Bounded classic PCAP and PCAPNG capture support

#![forbid(unsafe_code)]

mod collection;
mod error;
mod header;
mod limits;
mod pcapng;
mod pcapng_blocks;
mod pcapng_collection;
mod pcapng_interfaces;
mod pcapng_linux_identity;
mod pcapng_model;
mod pcapng_options;
mod pcapng_packets;
mod pcapng_writer;
mod reader;
mod source;
mod writer_error;

pub use collection::{CollectionGoal, CollectionReport, CollectionStopReason, CollectionSummary};
pub use error::Error;
pub use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsLength,
    FcsStatus, FrameError, InterfaceId, LinkType, MAX_FCS_LENGTH,
    MAX_TIMESTAMP_RESOLUTION_EXPONENT, MetadataError, TimestampResolution, TimestampSource,
    VlanAuxData,
};
pub use limits::CaptureLimits;
pub use pcapng::PcapNgReader;
pub use pcapng_model::{InterfaceDescription, PcapNgOption};
pub use pcapng_writer::{InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgWriter};
pub use reader::CaptureReader;
pub use source::CaptureSource;
pub use writer_error::WriterError;

/// Maximum captured frame length retained by this crate
pub const MAX_FRAME_LENGTH: u32 = 65_535;

/// Default maximum number of packet records accepted from one capture
pub const MAX_RECORD_COUNT: u32 = 1_000_000;

/// Default maximum number of input bytes processed from one capture
pub const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

/// Largest file offset supported by signed file and database offsets
pub const ABSOLUTE_MAX_INPUT_BYTES: u64 = i64::MAX.unsigned_abs();

/// Largest record number representable by the capture reader
pub const ABSOLUTE_MAX_RECORD_COUNT: u32 = u32::MAX;

/// Maximum PCAPNG block bytes read before parsing its body
pub const MAX_BLOCK_LENGTH: usize = 1024 * 1024;

/// Maximum consecutive `Interrupted` results tolerated from an input reader
pub const MAX_CONSECUTIVE_INTERRUPTS: u32 = 32;

/// Canonical frame name retained for source compatibility with the first reader API
pub use l2_capture::CapturedFrame as Packet;
