//! Canonical captured frame with private evidence bytes

use crate::{CaptureMetadata, FrameError, MAX_FRAME_LENGTH};

/// One bounded captured frame with private evidence bytes and canonical metadata
///
/// # Invariants
///
/// The byte vector length is at most [`MAX_FRAME_LENGTH`] and at most
/// `metadata.original_len`. Captured length and truncation are always derived
/// from the retained bytes and metadata instead of being stored twice
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapturedFrame {
    // Raw bytes remain authoritative evidence for every decoder
    bytes: Vec<u8>,
    // Metadata is kept beside evidence so backends cannot lose provenance
    metadata: CaptureMetadata,
}

impl CapturedFrame {
    /// Validate and retain one captured frame
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::FrameTooLong`] when the retained bytes exceed the
    /// absolute frame limit or [`FrameError::CapturedLengthExceedsOriginal`]
    /// when the source length is inconsistent. Metadata is already validated
    /// before it can be stored in this frame
    pub fn new(bytes: Vec<u8>, metadata: CaptureMetadata) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_LENGTH {
            return Err(FrameError::FrameTooLong {
                length: bytes.len(),
                max: MAX_FRAME_LENGTH,
            });
        }
        let Ok(captured_len) = u32::try_from(bytes.len()) else {
            return Err(FrameError::FrameTooLong {
                length: bytes.len(),
                max: MAX_FRAME_LENGTH,
            });
        };
        if captured_len > metadata.original_len() {
            return Err(FrameError::CapturedLengthExceedsOriginal {
                captured: bytes.len(),
                original: metadata.original_len(),
            });
        }
        Ok(Self { bytes, metadata })
    }

    /// Borrow the exact bytes retained by the capture backend
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the canonical metadata associated with the retained bytes
    #[must_use]
    pub const fn metadata(&self) -> &CaptureMetadata {
        &self.metadata
    }

    /// Return the number of retained bytes
    #[must_use]
    pub const fn captured_len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the source reported more bytes than were retained
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        u32::try_from(self.bytes.len())
            .is_ok_and(|captured_len| captured_len < self.metadata.original_len())
    }
}

impl AsRef<[u8]> for CapturedFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}
