//! Bound arbitrary JSON details before allocating their value trees

use super::{
    CaseResourceLimits, EvidenceError, MAX_BLOBS, MAX_NODE_DETAILS_BYTES, MAX_NODES,
    MAX_TOTAL_DETAILS_BYTES, bounded,
};
use crate::serialization::base64::decoded_length;
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize)]
struct RawCase<'a> {
    #[serde(default)]
    resource_limits: CaseResourceLimits,
    #[serde(
        borrow,
        deserialize_with = "bounded::deserialize_vec::<_, _, MAX_BLOBS>"
    )]
    blobs: Vec<RawBlob<'a>>,
    #[serde(
        borrow,
        deserialize_with = "bounded::deserialize_vec::<_, _, MAX_NODES>"
    )]
    nodes: Vec<RawNode<'a>>,
}

#[derive(Deserialize)]
struct RawBlob<'a> {
    #[serde(borrow, rename = "bytes_base64")]
    encoded: &'a str,
}

#[derive(Deserialize)]
struct RawNode<'a> {
    #[serde(borrow)]
    kind: &'a str,
    #[serde(borrow)]
    details: &'a RawValue,
}

pub(super) fn check_details(bytes: &[u8]) -> Result<(), EvidenceError> {
    // Other graph fields are skipped here and validated by the canonical case decoder
    let raw: RawCase<'_> = serde_json::from_slice(bytes).map_err(|_| EvidenceError::InvalidJson)?;
    if raw.resource_limits.blob_bytes == Some(0) {
        return Err(EvidenceError::InvalidResourceLimit {
            field: "blob bytes",
        });
    }
    let mut blob_bytes = 0_usize;
    for blob in raw.blobs {
        let decoded = decoded_length(blob.encoded).ok_or(EvidenceError::InvalidJson)?;
        blob_bytes = blob_bytes
            .checked_add(decoded)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "blob bytes",
            })?;
        if raw
            .resource_limits
            .blob_bytes
            .is_some_and(|maximum| blob_bytes > maximum)
        {
            return Err(EvidenceError::QuotaExceeded {
                field: "blob bytes",
                maximum: raw.resource_limits.blob_bytes.unwrap_or(usize::MAX),
            });
        }
    }
    let mut total = 0;
    for node in raw.nodes {
        let length = node.details.get().len();
        if length > MAX_NODE_DETAILS_BYTES {
            return Err(EvidenceError::NodeDetailsTooLarge {
                length,
                maximum: MAX_NODE_DETAILS_BYTES,
            });
        }
        // Node count and individual lengths already keep this sum below usize limits
        total += length;
        if total > MAX_TOTAL_DETAILS_BYTES {
            return Err(EvidenceError::TotalDetailsTooLarge {
                length: total,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            });
        }
        // Reserved built-in kinds keep their exact raw schema before Value can collapse keys
        if node.kind == super::FLOW_SELECTION_KIND
            && !super::receipt_verification::raw_flow_selection_details_are_valid(node.details)
        {
            return Err(EvidenceError::InvalidJson);
        }
    }
    Ok(())
}
