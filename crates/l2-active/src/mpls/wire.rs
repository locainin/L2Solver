//! Scope a unicast MPLS frame and bound its basic label-stack prefix

use l2_core::FrameField;
use l2_onpath::MacAddress;

use super::{MplsEvidence, MplsLabel, MplsMalformed, MplsUnsupported};

pub(super) const ETHERNET_HEADER: usize = 14;
pub(super) const LABEL_BYTES: usize = 4;
const MAX_STACK_DEPTH: usize = 16;

pub(super) struct Parsed {
    pub evidence: MplsEvidence,
    pub label_count: usize,
}

pub(super) fn classify(bytes: &[u8], destination: MacAddress) -> Option<Parsed> {
    let frame = l2_core::decode(bytes).ok()?;
    // Only the selected unicast endpoint and ordinary MPLS EtherType are in scope
    if frame.field != FrameField::EtherType(0x8847)
        || !frame.vlan_tags.is_empty()
        || frame.destination != destination.bytes()
    {
        return None;
    }
    if MacAddress::new(frame.source).is_err() {
        return Some(parsed(MplsEvidence::Malformed(MplsMalformed::SourceMac), 0));
    }
    Some(stack(frame.payload))
}

fn stack(payload: &[u8]) -> Parsed {
    let (entries, _) = payload.as_chunks::<LABEL_BYTES>();
    for (index, bytes) in entries.iter().take(MAX_STACK_DEPTH).enumerate() {
        let label = MplsLabel::from_bytes(*bytes);
        let count = index + 1;
        // Explicit-null and router-alert placement is defined for basic stacks
        if matches!(label.value(), 0 | 2) && !label.bottom_of_stack()
            || label.value() == 1 && label.bottom_of_stack()
            || label.value() == 3
        {
            return parsed(
                MplsEvidence::Malformed(MplsMalformed::SpecialPurposeLabel),
                count,
            );
        }
        // Later words after these indicators can have non-label encodings
        if (4..=15).contains(&label.value()) {
            return parsed(
                MplsEvidence::Unsupported(MplsUnsupported::SpecialPurposeLabel(label.value())),
                count,
            );
        }
        if label.bottom_of_stack() {
            // No byte after BOS means that even an opaque payload was not captured
            let evidence = if payload.len() == count * LABEL_BYTES {
                MplsEvidence::Malformed(MplsMalformed::MissingPayload)
            } else {
                MplsEvidence::Stack
            };
            return parsed(evidence, count);
        }
    }
    // A complete extra word remains beyond the maximum inspected depth
    if entries.len() > MAX_STACK_DEPTH {
        return parsed(
            MplsEvidence::Unsupported(MplsUnsupported::StackDepthLimit),
            MAX_STACK_DEPTH,
        );
    }
    parsed(
        MplsEvidence::Malformed(MplsMalformed::TruncatedStack),
        entries.len(),
    )
}

const fn parsed(evidence: MplsEvidence, label_count: usize) -> Parsed {
    Parsed {
        evidence,
        label_count,
    }
}
