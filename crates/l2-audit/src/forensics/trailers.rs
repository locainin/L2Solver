use super::{ForensicScope, TrailingData, TrailingProtocol, tracker::ForensicTracker};
use crate::ResourceLimitStatus;
use l2_capture::{CapturedFrame, FcsStatus};

impl ForensicTracker {
    pub(super) fn trailer(
        &mut self,
        scope: &ForensicScope,
        source: &CapturedFrame,
        protocol: TrailingProtocol,
        bytes: &[u8],
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if bytes.is_empty() {
            return false;
        }
        if source.metadata().fcs() != FcsStatus::Absent {
            // Unknown or declared-present FCS prevents attributing the trailing range to data
            self.trailer_frames_unchecked += 1;
            return false;
        }
        self.record_trailer(
            scope,
            protocol,
            (source.captured_len() - bytes.len(), bytes),
            packet,
            status,
        )
    }

    pub(super) fn record_trailer(
        &mut self,
        scope: &ForensicScope,
        protocol: TrailingProtocol,
        (offset, bytes): (usize, &[u8]),
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        let nonzero_bytes = bytes.iter().filter(|byte| **byte != 0).count();
        if nonzero_bytes == 0 || !self.reserve(status) {
            return false;
        }
        self.trailing_data.push(TrailingData {
            scope: scope.clone(),
            protocol,
            packet,
            offset,
            length: bytes.len(),
            nonzero_bytes,
        });
        true
    }
}
