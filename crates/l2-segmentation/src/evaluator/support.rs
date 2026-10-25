//! Internal receipt and replay bookkeeping for evaluation

use std::collections::BTreeMap;

use l2_canary::Canary;

use crate::{Probe, ReceiptError};

use super::types::{CaptureQuality, EvaluationContext};

pub(super) fn receipt_is_new<T: Eq>(
    receipts: &BTreeMap<ReceiptKey, T>,
    key: ReceiptKey,
    receipt: &T,
) -> Result<bool, ReceiptError> {
    match receipts.get(&key) {
        Some(existing) if existing == receipt => Ok(false),
        Some(_) => Err(ReceiptError::ConflictingReceipt),
        None => Ok(true),
    }
}

pub(super) fn append_context_limitations(
    limitations: &mut Vec<String>,
    context: EvaluationContext,
) {
    if !context.sender_available {
        limitations.push(String::from("sender availability was incomplete"));
    }
    if !context.receiver_available {
        limitations.push(String::from("receiver availability was incomplete"));
    }
    match context.capture_quality {
        CaptureQuality::Complete => {}
        CaptureQuality::Incomplete => {
            limitations.push(String::from("capture quality was incomplete"));
        }
        CaptureQuality::Dropped => {
            limitations.push(String::from("capture reported dropped observations"));
        }
    }
    if context.cancelled {
        limitations.push(String::from("observation was cancelled before completion"));
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ObservationKey {
    run_id: [u8; 16],
    source_agent_id: [u8; 16],
    destination_agent_id: [u8; 16],
    sequence: u64,
    nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ObservationIdentity {
    run: [u8; 16],
    source: [u8; 16],
    destination: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ReceiptKey {
    pub(super) run_id: [u8; 16],
    pub(super) sequence: u64,
}

impl ReceiptKey {
    pub(super) const fn new(run_id: [u8; 16], sequence: u64) -> Self {
        Self { run_id, sequence }
    }

    pub(super) const fn from_probe(probe: &Probe) -> Self {
        Self::new(probe.run_id.into_bytes(), probe.sequence)
    }
}

impl ObservationIdentity {
    pub(super) const fn from_canary(canary: &Canary) -> Self {
        Self {
            run: canary.run_id().into_bytes(),
            source: canary.source_agent_id().bytes(),
            destination: canary.destination_agent_id().bytes(),
        }
    }
}

impl ObservationKey {
    pub(super) const fn from_canary(canary: &Canary) -> Self {
        Self {
            run_id: canary.run_id().into_bytes(),
            source_agent_id: canary.source_agent_id().bytes(),
            destination_agent_id: canary.destination_agent_id().bytes(),
            sequence: canary.sequence(),
            nonce: canary.nonce(),
        }
    }

    pub(super) const fn from_probe(probe: &Probe) -> Self {
        Self {
            run_id: probe.run_id.into_bytes(),
            source_agent_id: probe.source_agent_id().bytes(),
            destination_agent_id: probe.destination_agent_id().bytes(),
            sequence: probe.sequence,
            nonce: probe.nonce,
        }
    }
}
