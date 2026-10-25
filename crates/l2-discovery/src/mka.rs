use crate::{Fingerprint, Protocol, bytes::read_u8};

const PARAMETER_HEADER_LEN: usize = 4;
const BASIC_BODY_MIN_LEN: usize = 28;
const DEFAULT_ICV_LEN: usize = 16;
const MIN_MKPDU_LEN: usize = PARAMETER_HEADER_LEN + BASIC_BODY_MIN_LEN + DEFAULT_ICV_LEN;
const CURRENT_MKA_VERSION: u8 = 3;
const MAX_PARAMETER_SETS: usize = 64;
const ICV_INDICATOR_TYPE: u8 = 255;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParameterStatus {
    Valid,
    Unsupported,
    Malformed,
}

/// Check the MKA Basic Parameter Set and mandatory integrity field bounds
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    if payload.len() < MIN_MKPDU_LEN {
        return Fingerprint::malformed(Protocol::Mka);
    }
    if !payload.len().is_multiple_of(4) {
        return Fingerprint::malformed(Protocol::Mka);
    }

    let Some(version) = read_u8(payload, 0) else {
        return Fingerprint::truncated(Protocol::Mka);
    };
    if version == 0 {
        return Fingerprint::malformed(Protocol::Mka);
    }
    if version > CURRENT_MKA_VERSION {
        return Fingerprint::unsupported(Protocol::Mka);
    }

    let Some(length_high) = read_u8(payload, 2) else {
        return Fingerprint::truncated(Protocol::Mka);
    };
    let Some(length_low) = read_u8(payload, 3) else {
        return Fingerprint::truncated(Protocol::Mka);
    };
    let basic_body_len = usize::from(length_high & 0x0f)
        .checked_mul(256)
        .and_then(|high| high.checked_add(usize::from(length_low)));
    let Some(basic_body_len) = basic_body_len else {
        return Fingerprint::malformed(Protocol::Mka);
    };
    if basic_body_len < BASIC_BODY_MIN_LEN {
        return Fingerprint::malformed(Protocol::Mka);
    }

    let Some(aligned_basic_len) = align_to_word(basic_body_len) else {
        return Fingerprint::malformed(Protocol::Mka);
    };
    let Some(basic_end) = PARAMETER_HEADER_LEN.checked_add(aligned_basic_len) else {
        return Fingerprint::malformed(Protocol::Mka);
    };
    let Some(parameter_end) = payload.len().checked_sub(DEFAULT_ICV_LEN) else {
        return Fingerprint::malformed(Protocol::Mka);
    };
    if basic_end > parameter_end {
        return Fingerprint::malformed(Protocol::Mka);
    }
    match parameter_sets_status(payload, basic_end, parameter_end) {
        ParameterStatus::Valid => Fingerprint::observed(Protocol::Mka),
        ParameterStatus::Unsupported => Fingerprint::unsupported(Protocol::Mka),
        ParameterStatus::Malformed => Fingerprint::malformed(Protocol::Mka),
    }
}

fn parameter_sets_status(payload: &[u8], mut cursor: usize, end: usize) -> ParameterStatus {
    let mut count = 0_usize;
    while cursor < end {
        count += 1;
        if count > MAX_PARAMETER_SETS {
            return ParameterStatus::Unsupported;
        }
        let Some(header_end) = cursor.checked_add(PARAMETER_HEADER_LEN) else {
            return ParameterStatus::Malformed;
        };
        if header_end > end {
            return ParameterStatus::Malformed;
        }
        let Some(parameter_type) = read_u8(payload, cursor) else {
            return ParameterStatus::Malformed;
        };
        let Some(length_high) = read_u8(payload, cursor + 2) else {
            return ParameterStatus::Malformed;
        };
        let Some(length_low) = read_u8(payload, cursor + 3) else {
            return ParameterStatus::Malformed;
        };
        let body_len = usize::from(length_high & 0x0f) * 256 + usize::from(length_low);
        let Some(aligned_body_len) = align_to_word(body_len) else {
            return ParameterStatus::Malformed;
        };
        let Some(parameter_end) = header_end.checked_add(aligned_body_len) else {
            return ParameterStatus::Malformed;
        };
        if parameter_type == ICV_INDICATOR_TYPE {
            // The indicator body is the final ICV rather than another parameter value
            if body_len == 0 || parameter_end != payload.len() {
                return ParameterStatus::Malformed;
            }
            return if body_len == DEFAULT_ICV_LEN {
                ParameterStatus::Valid
            } else {
                ParameterStatus::Unsupported
            };
        }
        if parameter_end > end {
            return ParameterStatus::Malformed;
        }
        cursor = parameter_end;
    }
    if cursor == end {
        ParameterStatus::Valid
    } else {
        ParameterStatus::Malformed
    }
}

const fn align_to_word(length: usize) -> Option<usize> {
    match length.checked_add(3) {
        Some(padded) => Some(padded & !3),
        None => None,
    }
}
