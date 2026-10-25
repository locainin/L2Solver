use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    AgentId, Canary, CanaryIdentity, DESTINATION_AGENT_ID_OFFSET, DOMAIN_SEPARATOR, DecodeError,
    ETHER_TYPE, HEADER_LEN, ID_LEN, KeyError, NONCE_LEN, NONCE_OFFSET, RUN_ID_OFFSET, RunId,
    SEQUENCE_OFFSET, SOURCE_AGENT_ID_OFFSET, SessionKey, TAG_LEN, UnverifiedCanary, VERSION,
    VerifiedCanary, WIRE_LEN,
};

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
#[path = "../tests/wire/internal.rs"]
mod internal_tests;

/// Encode one authenticated fixed-size canary payload
///
/// # Errors
///
/// Rejects fields outside the directional session-key scope
pub fn encode(canary: &Canary, key: &SessionKey) -> Result<[u8; WIRE_LEN], KeyError> {
    validate_key_scope(canary.identity(), key.identity())?;
    let mut header = [0; HEADER_LEN];
    write_at(&mut header, 0, &[VERSION])?;
    write_at(&mut header, RUN_ID_OFFSET, canary.run_id().as_bytes())?;
    write_at(
        &mut header,
        SOURCE_AGENT_ID_OFFSET,
        canary.source_agent_id().as_bytes(),
    )?;
    write_at(
        &mut header,
        DESTINATION_AGENT_ID_OFFSET,
        canary.destination_agent_id().as_bytes(),
    )?;
    write_at(
        &mut header,
        SEQUENCE_OFFSET,
        &canary.sequence().to_be_bytes(),
    )?;
    write_at(&mut header, NONCE_OFFSET, &canary.nonce())?;

    let tag = authenticate(key, &header)?;
    let mut wire = [0; WIRE_LEN];
    write_at(&mut wire, 0, &header)?;
    write_at(&mut wire, HEADER_LEN, &tag)?;
    Ok(wire)
}

/// Verify an authenticated fixed-size canary payload and return its fields
///
/// # Errors
///
/// Returns a structural, version, or authentication error when the payload
/// cannot be trusted
pub fn verify(
    packet: UnverifiedCanary<'_>,
    key: &SessionKey,
) -> Result<VerifiedCanary, DecodeError> {
    let input = packet.wire();
    let (header, tag) = checked_wire_parts(input)?;
    verify_tag(key, header, tag)?;

    let Some(run_id) = read_array::<ID_LEN>(input, RUN_ID_OFFSET) else {
        return Err(truncated(input));
    };
    let Some(source_agent_id) = read_array::<ID_LEN>(input, SOURCE_AGENT_ID_OFFSET) else {
        return Err(truncated(input));
    };
    let Some(destination_agent_id) = read_array::<ID_LEN>(input, DESTINATION_AGENT_ID_OFFSET)
    else {
        return Err(truncated(input));
    };
    let Some(sequence_bytes) = read_array::<8>(input, SEQUENCE_OFFSET) else {
        return Err(truncated(input));
    };
    let Some(nonce) = read_array::<NONCE_LEN>(input, NONCE_OFFSET) else {
        return Err(truncated(input));
    };
    let run_id = RunId::from_recorded(run_id).map_err(|_| DecodeError::ZeroRunId)?;
    let source_agent_id = AgentId::new(source_agent_id).map_err(|_| DecodeError::ZeroAgentId)?;
    let destination_agent_id =
        AgentId::new(destination_agent_id).map_err(|_| DecodeError::ZeroAgentId)?;
    let identity = CanaryIdentity::new(run_id, source_agent_id, destination_agent_id)
        .map_err(|_| DecodeError::SameAgent)?;
    let sequence = u64::from_be_bytes(sequence_bytes);
    let canary = Canary::new(identity, sequence, nonce).map_err(|_| DecodeError::ZeroSequence)?;
    validate_decode_scope(canary.identity(), key.identity())?;
    Ok(VerifiedCanary::new(canary, Sha256::digest(input).into()))
}

fn checked_wire_parts(input: &[u8]) -> Result<(&[u8], &[u8]), DecodeError> {
    if input.len() < WIRE_LEN {
        return Err(truncated(input));
    }
    if input.len() > WIRE_LEN {
        return Err(DecodeError::TrailingBytes {
            expected: WIRE_LEN,
            actual: input.len(),
        });
    }
    let Some(&version) = input.first() else {
        return Err(truncated(input));
    };
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { value: version });
    }
    let Some(header) = input.get(..HEADER_LEN) else {
        return Err(truncated(input));
    };
    let Some(tag) = input.get(HEADER_LEN..WIRE_LEN) else {
        return Err(truncated(input));
    };
    Ok((header, tag))
}

fn verify_tag(key: &SessionKey, header: &[u8], tag: &[u8]) -> Result<(), DecodeError> {
    let mut mac = new_mac(key).map_err(|_| DecodeError::InvalidTag)?;
    mac.update(DOMAIN_SEPARATOR);
    mac.update(&ETHER_TYPE.to_be_bytes());
    mac.update(header);
    if mac.verify_slice(tag).is_err() {
        return Err(DecodeError::InvalidTag);
    }
    Ok(())
}

const fn truncated(input: &[u8]) -> DecodeError {
    DecodeError::Truncated {
        needed: WIRE_LEN,
        available: input.len(),
    }
}

/// Verify a payload and require the expected run/source/destination tuple
///
/// # Errors
///
/// Returns any error from [`verify`], or an identity error when the verified
/// payload is addressed to a different run or agent
pub fn verify_for(
    packet: UnverifiedCanary<'_>,
    key: &SessionKey,
    expected: &CanaryIdentity,
) -> Result<VerifiedCanary, DecodeError> {
    let canary = verify(packet, key)?;
    let fields = canary.as_canary();
    if fields.run_id() != expected.run_id() {
        return Err(DecodeError::UnexpectedRun);
    }
    if fields.source_agent_id() != expected.source_agent_id() {
        return Err(DecodeError::UnexpectedSourceAgent);
    }
    if fields.destination_agent_id() != expected.destination_agent_id() {
        return Err(DecodeError::UnexpectedDestinationAgent);
    }
    Ok(canary)
}

fn new_mac(key: &SessionKey) -> Result<HmacSha256, KeyError> {
    HmacSha256::new_from_slice(key.as_bytes()?).map_err(|_| KeyError::InternalInvariant)
}

fn authenticate(key: &SessionKey, header: &[u8]) -> Result<[u8; TAG_LEN], KeyError> {
    let mut mac = new_mac(key)?;
    mac.update(DOMAIN_SEPARATOR);
    mac.update(&ETHER_TYPE.to_be_bytes());
    mac.update(header);
    let mut output = mac.finalize().into_bytes();
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&output);
    output.zeroize();
    Ok(tag)
}

fn validate_key_scope(actual: CanaryIdentity, expected: CanaryIdentity) -> Result<(), KeyError> {
    if actual.run_id() != expected.run_id() {
        return Err(KeyError::RunMismatch);
    }
    if actual.source_agent_id() != expected.source_agent_id() {
        return Err(KeyError::SourceMismatch);
    }
    if actual.destination_agent_id() != expected.destination_agent_id() {
        return Err(KeyError::DestinationMismatch);
    }
    Ok(())
}

fn validate_decode_scope(
    actual: CanaryIdentity,
    expected: CanaryIdentity,
) -> Result<(), DecodeError> {
    if actual.run_id() != expected.run_id() {
        return Err(DecodeError::UnexpectedRun);
    }
    if actual.source_agent_id() != expected.source_agent_id() {
        return Err(DecodeError::UnexpectedSourceAgent);
    }
    if actual.destination_agent_id() != expected.destination_agent_id() {
        return Err(DecodeError::UnexpectedDestinationAgent);
    }
    Ok(())
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let bytes = input.get(offset..end)?;
    bytes.try_into().ok()
}

fn write_at<const W: usize, const N: usize>(
    wire: &mut [u8; W],
    offset: usize,
    value: &[u8; N],
) -> Result<(), KeyError> {
    let end = offset.checked_add(N).ok_or(KeyError::InternalInvariant)?;
    let destination = wire
        .get_mut(offset..end)
        .ok_or(KeyError::InternalInvariant)?;
    destination.copy_from_slice(value);
    Ok(())
}
