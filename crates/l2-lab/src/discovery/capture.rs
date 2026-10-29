//! Stable serialization for exact synthetic packet and transition provenance

use l2_canary::{AgentId, RunId};
use l2_segmentation::EvidenceSourceId;
use sha2::{Digest, Sha256};

use super::{DiscoveryError, Identity, Observation, Observed};

const MARKER: &[u8] = b"l2solver-discovery-capture-v1\0";
const RECORD_OVERHEAD: usize = 8 + 8 + 16 + 1 + 2;

pub(super) fn serialize(
    run_id: RunId,
    receiver: AgentId,
    observations: &[Observation<'_>],
) -> Result<Vec<u8>, DiscoveryError> {
    let size = serialized_size(observations).ok_or(DiscoveryError::Invariant)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| DiscoveryError::Allocation)?;
    bytes.extend_from_slice(MARKER);
    bytes.extend_from_slice(run_id.as_bytes());
    bytes.extend_from_slice(receiver.as_bytes());
    for observation in observations {
        write_observation(&mut bytes, observation)?;
    }
    Ok(bytes)
}

fn serialized_size(observations: &[Observation<'_>]) -> Option<usize> {
    observations
        .iter()
        .try_fold(MARKER.len() + 16 + 16, |size, observation| {
            size.checked_add(record_size(observation)?)
        })
}

fn record_size(observation: &Observation<'_>) -> Option<usize> {
    let decision_size = match observation.observed {
        Observed::Rejected => 1,
        Observed::Accepted(identity) | Observed::Withdrawn(identity) => 1 + identity_size(identity),
    };
    let before_size = 1 + observation.before.map_or(0, identity_size);
    let after_size = 1 + observation.after.map_or(0, identity_size);
    // All identity and frame lengths were bounded before reaching this point
    RECORD_OVERHEAD
        .checked_add(observation.frame.len())?
        .checked_add(decision_size + before_size + after_size)
}

fn write_observation(
    bytes: &mut Vec<u8>,
    observation: &Observation<'_>,
) -> Result<(), DiscoveryError> {
    // Length framing makes each packet and state record unambiguous
    bytes.extend_from_slice(&observation.sequence.to_be_bytes());
    bytes.extend_from_slice(&observation.at_millis.to_be_bytes());
    bytes.extend_from_slice(observation.source.as_bytes());
    bytes.push(observation.protocol.capture_code());
    write_part(bytes, observation.frame)?;
    write_decision(bytes, observation.observed)?;
    write_optional_identity(bytes, observation.before)?;
    write_optional_identity(bytes, observation.after)
}

fn write_decision(bytes: &mut Vec<u8>, observed: Observed<'_>) -> Result<(), DiscoveryError> {
    match observed {
        Observed::Rejected => bytes.push(0),
        Observed::Accepted(identity) => {
            bytes.push(1);
            write_identity(bytes, identity)?;
        }
        Observed::Withdrawn(identity) => {
            bytes.push(2);
            write_identity(bytes, identity)?;
        }
    }
    Ok(())
}

const fn identity_size(identity: Identity<'_>) -> usize {
    4 + identity.device().len() + identity.port().len()
}

fn write_part(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), DiscoveryError> {
    let length = u16::try_from(value.len()).map_err(|_| DiscoveryError::Invariant)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_identity(bytes: &mut Vec<u8>, identity: Identity<'_>) -> Result<(), DiscoveryError> {
    write_part(bytes, identity.device())?;
    write_part(bytes, identity.port())
}

fn write_optional_identity(
    bytes: &mut Vec<u8>,
    identity: Option<Identity<'_>>,
) -> Result<(), DiscoveryError> {
    if let Some(identity) = identity {
        bytes.push(1);
        write_identity(bytes, identity)?;
    } else {
        bytes.push(0);
    }
    Ok(())
}

pub(super) fn source(bytes: &[u8]) -> EvidenceSourceId {
    EvidenceSourceId::from_bytes(Sha256::digest(bytes).into())
}
