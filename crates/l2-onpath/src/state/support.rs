//! Shared internal keys and receipt helpers

use std::collections::BTreeMap;

use l2_canary::Canary;
use l2_segmentation::ObservationWindowReceipt;

use crate::{ReceiptError, SessionError};

pub(super) const fn clean_window(window: ObservationWindowReceipt) -> bool {
    window.complete() && window.capture_loss() == 0
}

pub(super) fn receipt_is_new<K: Ord, V: Eq>(
    receipts: &BTreeMap<K, V>,
    key: &K,
    value: &V,
) -> Result<bool, SessionError> {
    match receipts.get(key) {
        Some(existing) if existing == value => Ok(false),
        Some(_) => Err(ReceiptError::ConflictingReceipt.into()),
        None => Ok(true),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct CanaryKey {
    run_id: [u8; 16],
    source: [u8; 16],
    destination: [u8; 16],
    sequence: u64,
    nonce: [u8; 16],
}

impl CanaryKey {
    pub(super) const fn from_canary(canary: &Canary) -> Self {
        Self {
            run_id: canary.run_id().into_bytes(),
            source: canary.source_agent_id().bytes(),
            destination: canary.destination_agent_id().bytes(),
            sequence: canary.sequence(),
            nonce: canary.nonce(),
        }
    }
}
