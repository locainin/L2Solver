//! Bounds and cross-field checks for policy values

use super::{Disposition, SegmentExpectations};
use crate::{AuditError, BridgeIdentity, Protocol};
use std::collections::{BTreeMap, BTreeSet};

const MAX_POLICY_LABEL_BYTES: usize = 64;

pub(super) const fn disposition(value: Option<bool>) -> Disposition {
    match value {
        Some(true) => Disposition::Allowed,
        Some(false) => Disposition::Forbidden,
        None => Disposition::Unspecified,
    }
}

pub(super) fn validate_segment(
    segment: &SegmentExpectations,
    all_segments: &BTreeMap<String, SegmentExpectations>,
) -> Result<(), AuditError> {
    // Local value checks run before cross-segment reference checks
    if let Some(allowed_vlans) = &segment.allowed_vlans {
        validate_vlan_set(allowed_vlans)?;
    }
    validate_vlan_depth(segment.max_vlan_depth)?;
    if let Some(bridge) = &segment.expected_stp_bridge {
        validate_bridge(bridge)?;
    }
    validate_protocols(&segment.protocols)?;
    // Every named path must resolve inside the same policy document
    for isolated in &segment.isolation_from {
        validate_label(isolated)?;
        if !all_segments.contains_key(isolated) {
            return Err(AuditError::Policy(
                "isolation rule references an unknown segment",
            ));
        }
    }
    for allowed in &segment.allow_to {
        validate_label(allowed)?;
        if !all_segments.contains_key(allowed) {
            return Err(AuditError::Policy(
                "allowed path references an unknown segment",
            ));
        }
        if segment.isolation_from.contains(allowed) {
            return Err(AuditError::Policy(
                "one directed path cannot be both allowed and isolated",
            ));
        }
    }
    Ok(())
}

fn validate_protocols(protocols: &BTreeMap<Protocol, Disposition>) -> Result<(), AuditError> {
    // Present entries must make an explicit allow or forbid decision
    if protocols
        .values()
        .any(|disposition| *disposition == Disposition::Unspecified)
    {
        return Err(AuditError::Policy(
            "protocol expectations must be allowed or forbidden",
        ));
    }
    if protocols.contains_key(&Protocol::Lldp) || protocols.contains_key(&Protocol::Stp) {
        return Err(AuditError::Policy(
            "LLDP and STP must use their dedicated policy fields",
        ));
    }
    Ok(())
}

pub(super) fn validate_vlan_list(vlans: Option<&[u16]>) -> Result<(), AuditError> {
    let Some(vlans) = vlans else {
        return Ok(());
    };
    // Priority tag zero and reserved tag 4095 are modeled outside ordinary VLAN IDs
    if vlans.len() > 4_094 || vlans.iter().any(|id| *id == 0 || *id >= 4_095) {
        return Err(AuditError::Policy("VLAN IDs must be in 1..=4094"));
    }
    if vlans.iter().collect::<BTreeSet<_>>().len() != vlans.len() {
        return Err(AuditError::Policy("duplicate VLAN expectation"));
    }
    Ok(())
}

fn validate_vlan_set(vlans: &BTreeSet<u16>) -> Result<(), AuditError> {
    // The valid VID domain has at most 4094 distinct values
    if vlans.iter().any(|id| *id == 0 || *id >= 4_095) {
        return Err(AuditError::Policy("VLAN IDs must be in 1..=4094"));
    }
    Ok(())
}

pub(super) const fn validate_vlan_depth(depth: Option<u8>) -> Result<(), AuditError> {
    match depth {
        Some(value) if value > 4 => {
            return Err(AuditError::Policy("VLAN depth must be in 0..=4"));
        }
        Some(_) | None => {}
    }
    Ok(())
}

pub(super) fn validate_stp_pair(
    bridge: Option<&BridgeIdentity>,
    root: Option<&str>,
) -> Result<(), AuditError> {
    // The structured bridge expectation supersedes the legacy MAC-only field
    if bridge.is_some() && root.is_some() {
        return Err(AuditError::Policy(
            "expected STP bridge and expected STP root cannot both be set",
        ));
    }
    if let Some(bridge) = bridge {
        validate_bridge(bridge)?;
    }
    if root.is_some_and(|value| !is_canonical_mac(value)) {
        return Err(AuditError::Policy(
            "expected STP root must be a six-octet colon-separated MAC",
        ));
    }
    Ok(())
}

fn validate_bridge(bridge: &BridgeIdentity) -> Result<(), AuditError> {
    if bridge.priority > 61_440 || !bridge.priority.is_multiple_of(4_096) {
        return Err(AuditError::Policy(
            "expected STP bridge priority must be a multiple of 4096 in 0..=61440",
        ));
    }
    if bridge.system_id_extension > 4_095 {
        return Err(AuditError::Policy(
            "expected STP bridge system ID extension must be in 0..=4095",
        ));
    }
    if !is_canonical_mac(&bridge.mac) {
        return Err(AuditError::Policy(
            "expected STP bridge MAC must be a six-octet colon-separated MAC",
        ));
    }
    Ok(())
}

pub(super) fn validate_label(value: &str) -> Result<(), AuditError> {
    // Path-neutral ASCII labels are safe in logs, JSON keys, and operator mappings
    if value.is_empty()
        || value.len() > MAX_POLICY_LABEL_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuditError::Policy(
            "policy labels must use 1..=64 safe ASCII bytes",
        ));
    }
    Ok(())
}

fn is_canonical_mac(value: &str) -> bool {
    value.split(':').count() == 6
        && value
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
