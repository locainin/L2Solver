use crate::{
    Fingerprint, FingerprintStatus, Protocol,
    bytes::{read_u8, read_u16},
};
use core::cmp::Ordering;

const IGMP_HEADER_LEN: usize = 8;
const IGMP_V3_QUERY_LEN: usize = 12;
const IGMP_V3_RECORD_LEN: usize = 8;
const MAX_IGMP_V3_RECORDS: usize = 256;

const MEMBERSHIP_QUERY: u8 = 0x11;
const IGMP_V1_MEMBERSHIP_REPORT: u8 = 0x12;
const IGMP_V2_MEMBERSHIP_REPORT: u8 = 0x16;
const IGMP_V2_LEAVE_GROUP: u8 = 0x17;
const IGMP_V3_MEMBERSHIP_REPORT: u8 = 0x22;

const MODE_IS_INCLUDE: u8 = 1;
const MODE_IS_EXCLUDE: u8 = 2;
const CHANGE_TO_INCLUDE_MODE: u8 = 3;
const CHANGE_TO_EXCLUDE_MODE: u8 = 4;
const ALLOW_NEW_SOURCES: u8 = 5;
const BLOCK_OLD_SOURCES: u8 = 6;

/// Check the bounded IGMP message shape without validating application state
pub fn fingerprint(payload: &[u8], capture_truncated: bool) -> Fingerprint {
    let Some(message_type) = read_u8(payload, 0) else {
        return Fingerprint::truncated(Protocol::Igmp);
    };

    // Only message types defined by IGMPv1 through IGMPv3 receive a positive
    // protocol fingerprint. Unknown values remain visible as unsupported.
    if !matches!(
        message_type,
        MEMBERSHIP_QUERY
            | IGMP_V1_MEMBERSHIP_REPORT
            | IGMP_V2_MEMBERSHIP_REPORT
            | IGMP_V2_LEAVE_GROUP
            | IGMP_V3_MEMBERSHIP_REPORT
    ) {
        return Fingerprint::unsupported(Protocol::Igmp);
    }

    if payload.len() < IGMP_HEADER_LEN {
        return Fingerprint::truncated(Protocol::Igmp);
    }

    let status = match message_type {
        MEMBERSHIP_QUERY => query_status(payload),
        IGMP_V3_MEMBERSHIP_REPORT => report_status(payload),
        IGMP_V1_MEMBERSHIP_REPORT | IGMP_V2_MEMBERSHIP_REPORT | IGMP_V2_LEAVE_GROUP => {
            // The version-one and version-two messages have only the fixed
            // eight-byte header. Extra bytes cannot be assigned a safe meaning.
            if payload.len() == IGMP_HEADER_LEN {
                FingerprintStatus::Observed
            } else {
                FingerprintStatus::Malformed
            }
        }
        _ => FingerprintStatus::Unsupported,
    };

    let status = match status {
        FingerprintStatus::Observed if capture_truncated => FingerprintStatus::Truncated,
        status => status,
    };
    fingerprint_with_status(status)
}

fn query_status(payload: &[u8]) -> FingerprintStatus {
    match payload.len() {
        IGMP_HEADER_LEN => FingerprintStatus::Observed,
        length if length < IGMP_V3_QUERY_LEN => FingerprintStatus::Malformed,
        _ => {
            let Some(source_count) = read_u16(payload, 10).map(usize::from) else {
                return FingerprintStatus::Truncated;
            };
            let Some(required) = source_count
                .checked_mul(4)
                .and_then(|sources| IGMP_V3_QUERY_LEN.checked_add(sources))
            else {
                return FingerprintStatus::Malformed;
            };
            match payload.len().cmp(&required) {
                Ordering::Less => FingerprintStatus::Truncated,
                Ordering::Equal => FingerprintStatus::Observed,
                Ordering::Greater => FingerprintStatus::Malformed,
            }
        }
    }
}

fn report_status(payload: &[u8]) -> FingerprintStatus {
    let Some(record_count) = read_u16(payload, 6).map(usize::from) else {
        return FingerprintStatus::Truncated;
    };
    if record_count > MAX_IGMP_V3_RECORDS {
        return FingerprintStatus::Unsupported;
    }

    let mut offset = IGMP_HEADER_LEN;
    for _ in 0..record_count {
        let Some(record) = payload.get(offset..) else {
            return FingerprintStatus::Truncated;
        };
        let Some(record_type) = read_u8(record, 0) else {
            return FingerprintStatus::Truncated;
        };
        if !matches!(
            record_type,
            MODE_IS_INCLUDE
                | MODE_IS_EXCLUDE
                | CHANGE_TO_INCLUDE_MODE
                | CHANGE_TO_EXCLUDE_MODE
                | ALLOW_NEW_SOURCES
                | BLOCK_OLD_SOURCES
        ) {
            return FingerprintStatus::Malformed;
        }
        let Some(auxiliary_data_len) = read_u8(record, 1).map(usize::from) else {
            return FingerprintStatus::Truncated;
        };
        let Some(source_count) = read_u16(record, 2).map(usize::from) else {
            return FingerprintStatus::Truncated;
        };
        let Some(record_len) = source_count
            .checked_mul(4)
            .and_then(|sources| IGMP_V3_RECORD_LEN.checked_add(sources))
            .and_then(|length| length.checked_add(auxiliary_data_len.checked_mul(4)?))
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

const fn fingerprint_with_status(status: FingerprintStatus) -> Fingerprint {
    match status {
        FingerprintStatus::Observed => Fingerprint::observed(Protocol::Igmp),
        FingerprintStatus::Malformed => Fingerprint::malformed(Protocol::Igmp),
        FingerprintStatus::Truncated => Fingerprint::truncated(Protocol::Igmp),
        FingerprintStatus::Unsupported => Fingerprint::unsupported(Protocol::Igmp),
    }
}
