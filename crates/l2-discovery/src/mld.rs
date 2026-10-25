use crate::{
    FingerprintStatus,
    bytes::{read_u8, read_u16},
};

const MLD_V2_HEADER_LEN: usize = 8;
const MLD_V2_RECORD_LEN: usize = 20;
const MAX_MLD_V2_RECORDS: usize = 256;

/// Validate an `MLDv2` membership report without interpreting multicast state
pub fn report_status(payload: &[u8]) -> FingerprintStatus {
    let Some(record_count) = read_u16(payload, 6).map(usize::from) else {
        return FingerprintStatus::Truncated;
    };
    // Bound the record walk independently of the outer frame-size ceiling
    if record_count > MAX_MLD_V2_RECORDS {
        return FingerprintStatus::Unsupported;
    }

    let mut offset = MLD_V2_HEADER_LEN;
    for _ in 0..record_count {
        let Some(record) = payload.get(offset..) else {
            return FingerprintStatus::Truncated;
        };
        let Some(record_type) = read_u8(record, 0) else {
            return FingerprintStatus::Truncated;
        };
        // RFC 3810 defines six multicast-address record types
        if !matches!(record_type, 1..=6) {
            return FingerprintStatus::Malformed;
        }
        let Some(auxiliary_words) = read_u8(record, 1).map(usize::from) else {
            return FingerprintStatus::Truncated;
        };
        let Some(source_count) = read_u16(record, 2).map(usize::from) else {
            return FingerprintStatus::Truncated;
        };
        let Some(record_len) = source_count
            .checked_mul(16)
            .and_then(|sources| MLD_V2_RECORD_LEN.checked_add(sources))
            .and_then(|length| length.checked_add(auxiliary_words.checked_mul(4)?))
        else {
            return FingerprintStatus::Malformed;
        };
        let Some(next_offset) = offset.checked_add(record_len) else {
            return FingerprintStatus::Malformed;
        };
        if next_offset > payload.len() {
            return FingerprintStatus::Truncated;
        }
        offset = next_offset;
    }

    if offset == payload.len() {
        FingerprintStatus::Observed
    } else {
        FingerprintStatus::Malformed
    }
}
