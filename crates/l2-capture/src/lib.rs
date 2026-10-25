//! Canonical, bounded capture frames and metadata shared by every backend

#![forbid(unsafe_code)]

mod error;
mod evidence_reference;
mod frame;
mod link_type;
mod metadata;
mod source_identity;

pub use error::FrameError;
pub use evidence_reference::{EvidenceReferenceError, EvidenceSourceId, PacketReference};
pub use frame::CapturedFrame;
pub use link_type::LinkType;
pub use metadata::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, Direction, FcsLength, FcsStatus,
    InterfaceId, MAX_FCS_LENGTH, MAX_TIMESTAMP_RESOLUTION_EXPONENT, MetadataError,
    TimestampResolution, TimestampSource, VlanAuxData,
};
pub use source_identity::{
    LinuxInterfaceIdentity, LinuxInterfaceIdentityError, LinuxInterfaceIdentityField,
};

/// Maximum number of captured bytes a frame may retain
pub const MAX_FRAME_LENGTH: usize = 65_535;
