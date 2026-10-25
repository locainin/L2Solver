//! Reusable bounded checks for decoded byte candidates

use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Byte order for the explicit four-byte checksum field
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumByteOrder {
    BigEndian,
    LittleEndian,
}

/// One fully specified structural, checksum, or authenticated-decryption check
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Validator<'a> {
    Utf8,
    Json,
    Crc32 {
        data_offset: usize,
        data_length: usize,
        checksum_offset: usize,
        byte_order: ChecksumByteOrder,
    },
    AesGcm {
        key: &'a [u8],
        nonce: &'a [u8],
        associated_data: &'a [u8],
    },
}

impl fmt::Debug for Validator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 => formatter.write_str("Utf8"),
            Self::Json => formatter.write_str("Json"),
            Self::Crc32 {
                data_offset,
                data_length,
                checksum_offset,
                byte_order,
            } => formatter
                .debug_struct("Crc32")
                .field("data_offset", data_offset)
                .field("data_length", data_length)
                .field("checksum_offset", checksum_offset)
                .field("byte_order", byte_order)
                .finish(),
            Self::AesGcm {
                key,
                nonce,
                associated_data,
            } => formatter
                .debug_struct("AesGcm")
                .field("key_length", &key.len())
                .field("key_sha256", &crate::sha256(key))
                .field("nonce", nonce)
                .field("associated_data", associated_data)
                .finish(),
        }
    }
}

/// A precise validation result that keeps invalid parameters separate from mismatches
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationOutcome {
    Satisfied,
    Violated { reason: ValidationFailure },
    Invalid { reason: ValidationFailure },
}

/// A bounded reason a validator could not pass
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationFailure {
    InvalidUtf8,
    InvalidJson,
    InvalidChecksumParameters,
    ChecksumMismatch { expected: u32, actual: u32 },
    InvalidAesGcmParameters,
    AuthenticatedDecryptionFailed,
}

/// Apply one explicit check without retaining parsed structures or decrypted plaintext
#[must_use]
pub fn validate(bytes: &[u8], validator: &Validator<'_>) -> ValidationOutcome {
    match validator {
        Validator::Utf8 => {
            if std::str::from_utf8(bytes).is_ok() {
                ValidationOutcome::Satisfied
            } else {
                violated(ValidationFailure::InvalidUtf8)
            }
        }
        Validator::Json => {
            if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
                ValidationOutcome::Satisfied
            } else {
                violated(ValidationFailure::InvalidJson)
            }
        }
        Validator::Crc32 {
            data_offset,
            data_length,
            checksum_offset,
            byte_order,
        } => validate_crc32(
            bytes,
            *data_offset,
            *data_length,
            *checksum_offset,
            *byte_order,
        ),
        Validator::AesGcm {
            key,
            nonce,
            associated_data,
        } => validate_aes_gcm(bytes, key, nonce, associated_data),
    }
}

fn validate_crc32(
    bytes: &[u8],
    data_offset: usize,
    data_length: usize,
    checksum_offset: usize,
    byte_order: ChecksumByteOrder,
) -> ValidationOutcome {
    let Some(data_end) = data_offset.checked_add(data_length) else {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    };
    let Some(checksum_end) = checksum_offset.checked_add(4) else {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    };
    if data_end > bytes.len()
        || checksum_end > bytes.len()
        || (data_offset < checksum_end && checksum_offset < data_end)
    {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    }
    let Some(data) = bytes.get(data_offset..data_end) else {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    };
    let Some(checksum_bytes) = bytes.get(checksum_offset..checksum_end) else {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    };
    let Ok(checksum_bytes) = <[u8; 4]>::try_from(checksum_bytes) else {
        return invalid(ValidationFailure::InvalidChecksumParameters);
    };
    let expected = match byte_order {
        ChecksumByteOrder::BigEndian => u32::from_be_bytes(checksum_bytes),
        ChecksumByteOrder::LittleEndian => u32::from_le_bytes(checksum_bytes),
    };
    let actual = crc32fast::hash(data);
    if expected == actual {
        ValidationOutcome::Satisfied
    } else {
        violated(ValidationFailure::ChecksumMismatch { expected, actual })
    }
}

fn validate_aes_gcm(
    bytes: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> ValidationOutcome {
    if nonce.len() != 12 || !matches!(key.len(), 16 | 32) {
        return invalid(ValidationFailure::InvalidAesGcmParameters);
    }
    let Ok(nonce) = aes_gcm::Nonce::<U12>::try_from(nonce) else {
        return invalid(ValidationFailure::InvalidAesGcmParameters);
    };
    let payload = Payload {
        msg: bytes,
        aad: associated_data,
    };
    let authenticated = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .ok()
            .and_then(|cipher| cipher.decrypt(&nonce, payload).ok())
            .is_some(),
        32 => Aes256Gcm::new_from_slice(key)
            .ok()
            .and_then(|cipher| cipher.decrypt(&nonce, payload).ok())
            .is_some(),
        _ => false,
    };
    if authenticated {
        ValidationOutcome::Satisfied
    } else {
        violated(ValidationFailure::AuthenticatedDecryptionFailed)
    }
}

const fn violated(reason: ValidationFailure) -> ValidationOutcome {
    ValidationOutcome::Violated { reason }
}

const fn invalid(reason: ValidationFailure) -> ValidationOutcome {
    ValidationOutcome::Invalid { reason }
}
