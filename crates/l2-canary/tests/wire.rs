use std::error::Error;

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, DecodeError, ETHER_TYPE, KeyError, MAX_KEY_LEN,
    MAX_REPLAY_IDENTITIES, MIN_KEY_LEN, ReplayError, ReplayGuard, RunId, SessionKey, TAG_LEN,
    UnverifiedCanary, VERSION, VerifiedCanary, WIRE_LEN, encode,
};
use sha2::{Digest, Sha256};

const RUN_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SOURCE_ID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const DESTINATION_ID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const NONCE: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

fn key_for(value: &Canary) -> Result<SessionKey, KeyError> {
    // Bind the long-term relationship key to the claimed sender
    let agent_key = AgentKey::new(value.source_agent_id(), &[0x5a; MIN_KEY_LEN])?;
    SessionKey::derive(&agent_key, &value.identity())
}

fn verify(input: &[u8], key: &SessionKey) -> Result<Canary, DecodeError> {
    l2_canary::verify(UnverifiedCanary::new(input), key).map(VerifiedCanary::into_canary)
}

fn verified(value: &Canary) -> Result<VerifiedCanary, Box<dyn Error>> {
    let key = key_for(value)?;
    let wire = encode(value, &key)?;
    Ok(l2_canary::verify(UnverifiedCanary::new(&wire), &key)?)
}

fn verify_for(
    input: &[u8],
    key: &SessionKey,
    expected: &l2_canary::CanaryIdentity,
) -> Result<Canary, DecodeError> {
    l2_canary::verify_for(UnverifiedCanary::new(input), key, expected)
        .map(VerifiedCanary::into_canary)
}

fn canary() -> Result<Canary, Box<dyn Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded(RUN_ID)?,
        AgentId::new(SOURCE_ID)?,
        AgentId::new(DESTINATION_ID)?,
    )?;
    Ok(Canary::new(identity, 0x0102_0304_0506_0708, NONCE)?)
}

fn canary_with_identity(byte: u8, sequence: u64) -> Result<Canary, Box<dyn Error>> {
    let mut run_id = RUN_ID;
    if let Some(first) = run_id.first_mut() {
        *first = byte;
    }
    let identity = CanaryIdentity::new(
        RunId::from_recorded(run_id)?,
        AgentId::new(SOURCE_ID)?,
        AgentId::new(DESTINATION_ID)?,
    )?;
    Ok(Canary::new(identity, sequence, NONCE)?)
}

fn canary_with_index(index: u16, sequence: u64) -> Result<Canary, Box<dyn Error>> {
    let mut run_id = RUN_ID;
    if let Some(bytes) = run_id.get_mut(..2) {
        bytes.copy_from_slice(&index.to_be_bytes());
    }
    let identity = CanaryIdentity::new(
        RunId::from_recorded(run_id)?,
        AgentId::new(SOURCE_ID)?,
        AgentId::new(DESTINATION_ID)?,
    )?;
    Ok(Canary::new(identity, sequence, NONCE)?)
}

#[test]
fn preserves_big_endian_wire_shape() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;

    assert_eq!(wire.len(), WIRE_LEN);
    assert_eq!(wire.first().copied(), Some(VERSION));
    assert_eq!(ETHER_TYPE, 0x88b5);
    assert_eq!(
        wire.get(49..57),
        Some(value.sequence().to_be_bytes().as_slice())
    );
    assert_eq!(TAG_LEN, 32);
    assert_eq!(verify(&wire, &key)?, value);
    Ok(())
}

#[test]
fn verified_canary_authenticated_wire_digest() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;
    let verified = l2_canary::verify(UnverifiedCanary::new(&wire), &key)?;

    assert_eq!(
        verified.wire_sha256(),
        <[u8; 32]>::from(Sha256::digest(wire))
    );
    Ok(())
}

#[test]
fn golden_wire_bytes_remain_stable() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let expected_wire = [
        0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xa0, 0xa1, 0xa2,
        0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xd8, 0x86,
        0x06, 0xcd, 0xba, 0xff, 0x54, 0xf2, 0x7e, 0xcb, 0xc2, 0xf2, 0x7c, 0x26, 0xdd, 0x62, 0x32,
        0x62, 0xcf, 0x8c, 0x79, 0xaf, 0x31, 0x71, 0x7c, 0x85, 0x80, 0xb8, 0x1e, 0x1d, 0xc1, 0x11,
    ];
    let wire = encode(&value, &key)?;
    assert_eq!(wire, expected_wire);
    assert_eq!(wire.len(), WIRE_LEN);
    Ok(())
}

#[test]
fn every_wire_prefix_rejected_truncated() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;
    for length in 0..WIRE_LEN {
        let Some(prefix) = wire.get(..length) else {
            continue;
        };
        assert_eq!(
            verify(prefix, &key),
            Err(DecodeError::Truncated {
                needed: WIRE_LEN,
                available: length,
            })
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_wire_shape() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;

    let mut trailing = wire.to_vec();
    trailing.push(0);
    assert_eq!(
        verify(&trailing, &key),
        Err(DecodeError::TrailingBytes {
            expected: WIRE_LEN,
            actual: WIRE_LEN + 1,
        })
    );

    let mut unknown_version = wire;
    if let Some(version) = unknown_version.first_mut() {
        *version = VERSION.wrapping_add(1);
    }
    assert_eq!(
        verify(&unknown_version, &key),
        Err(DecodeError::UnsupportedVersion {
            value: VERSION.wrapping_add(1),
        })
    );

    let mut invalid_tag = wire;
    if let Some(byte) = invalid_tag.last_mut() {
        *byte ^= 1;
    }
    assert_eq!(verify(&invalid_tag, &key), Err(DecodeError::InvalidTag));
    Ok(())
}

#[test]
fn rejects_tampered_authenticated_fields() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;
    for offset in [1_usize, 17, 33, 49, 57] {
        let mut tampered = wire;
        if let Some(byte) = tampered.get_mut(offset) {
            *byte ^= 0x80;
        }
        assert_eq!(verify(&tampered, &key), Err(DecodeError::InvalidTag));
    }
    for offset in 73..WIRE_LEN {
        let mut tampered = wire;
        if let Some(byte) = tampered.get_mut(offset) {
            *byte ^= 0x01;
        }
        assert_eq!(verify(&tampered, &key), Err(DecodeError::InvalidTag));
    }

    let wrong_agent_key = AgentKey::new(AgentId::new(SOURCE_ID)?, &[0xa5; MIN_KEY_LEN])?;
    let value = canary()?;
    let wrong_key = SessionKey::derive(&wrong_agent_key, &value.identity())?;
    assert_eq!(verify(&wire, &wrong_key), Err(DecodeError::InvalidTag));
    let wrong_run = canary_with_identity(1, value.sequence())?;
    let wrong_run_key = key_for(&wrong_run)?;
    assert_eq!(
        verify(&encode(&wrong_run, &wrong_run_key)?, &key),
        Err(DecodeError::InvalidTag)
    );
    assert_eq!(
        verify(&encode(&value, &wrong_key)?, &key),
        Err(DecodeError::InvalidTag)
    );
    Ok(())
}

#[test]
fn agent_key_lengths_are_checked() -> Result<(), Box<dyn Error>> {
    let source = AgentId::new(SOURCE_ID)?;
    assert!(matches!(
        AgentKey::new(source, &[0; MIN_KEY_LEN - 1]),
        Err(KeyError::TooShort { length, min })
            if length == MIN_KEY_LEN - 1 && min == MIN_KEY_LEN
    ));
    assert!(AgentKey::new(source, &[0; MIN_KEY_LEN]).is_ok());
    assert!(AgentKey::new(source, &[0; MAX_KEY_LEN]).is_ok());
    let too_long = AgentKey::new(source, &[0; MAX_KEY_LEN + 1]);
    assert!(matches!(
        too_long,
        Err(KeyError::TooLong { length, max })
            if length == MAX_KEY_LEN + 1 && max == MAX_KEY_LEN
    ));
    Ok(())
}

#[test]
fn agent_key_bound_source_agent() -> Result<(), Box<dyn Error>> {
    assert!(AgentId::new([0; l2_canary::ID_LEN]).is_err());

    let other = AgentKey::new(
        AgentId::new([0x44; l2_canary::ID_LEN])?,
        &[0x5a; MIN_KEY_LEN],
    )?;
    let value = canary()?;
    assert!(matches!(
        SessionKey::derive(&other, &value.identity()),
        Err(KeyError::AgentKeyMismatch)
    ));
    Ok(())
}

#[test]
fn session_key_same_agent_direction() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let source = value.source_agent_id();

    // A directional identity cannot authorize a loopback canary
    assert!(matches!(
        CanaryIdentity::new(value.run_id(), source, source),
        Err(l2_canary::CanaryIdentityError::SameAgent)
    ));
    Ok(())
}

#[test]
fn session_key_rejects_another_direction() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let mut destination = value.destination_agent_id().bytes();
    if let Some(first) = destination.first_mut() {
        *first ^= 1;
    }
    let identity = CanaryIdentity::new(
        value.run_id(),
        value.source_agent_id(),
        AgentId::new(destination)?,
    )?;
    let other = Canary::new(identity, value.sequence(), value.nonce())?;

    assert!(matches!(
        encode(&other, &key),
        Err(KeyError::DestinationMismatch)
    ));
    Ok(())
}

#[test]
fn rejects_duplicate_sequences() -> Result<(), Box<dyn Error>> {
    let mut guard = ReplayGuard::new();
    let first = canary_with_identity(1, 10)?;
    let verified_first = verified(&first)?;
    assert_eq!(guard.accept(&verified_first), Ok(()));
    assert_eq!(
        guard.accept(&verified_first),
        Err(ReplayError::NonIncreasing {
            previous: 10,
            sequence: 10,
        })
    );
    assert_eq!(
        guard.accept(&verified(&canary_with_identity(1, 9)?)?),
        Err(ReplayError::NonIncreasing {
            previous: 10,
            sequence: 9,
        })
    );
    assert_eq!(
        guard.accept(&verified(&canary_with_identity(1, 11)?)?),
        Ok(())
    );
    assert_eq!(guard.len(), 1);
    assert_eq!(
        guard.accept(&verified(&canary_with_identity(2, 1)?)?),
        Ok(())
    );
    assert_eq!(guard.len(), 2);
    Ok(())
}

#[test]
fn replay_guard_explicit_identity_limit() -> Result<(), Box<dyn Error>> {
    let mut guard = ReplayGuard::new();
    for identity in 0..MAX_REPLAY_IDENTITIES {
        let identity = u16::try_from(identity).map_or(0, |value| value);
        assert_eq!(
            guard.accept(&verified(&canary_with_index(identity, 1)?)?),
            Ok(())
        );
    }
    assert_eq!(guard.len(), MAX_REPLAY_IDENTITIES);
    assert_eq!(
        guard.accept(&verified(&canary_with_index(
            u16::try_from(MAX_REPLAY_IDENTITIES).map_or(0, |value| value),
            1,
        )?)?),
        Err(ReplayError::IdentityLimit {
            max: MAX_REPLAY_IDENTITIES,
        })
    );
    Ok(())
}

#[test]
fn rejects_wrong_identity_context() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;

    let mut wrong_run_bytes = value.run_id().into_bytes();
    if let Some(first) = wrong_run_bytes.first_mut() {
        *first ^= 1;
    }
    let wrong_run = CanaryIdentity::new(
        RunId::from_recorded(wrong_run_bytes)?,
        value.source_agent_id(),
        value.destination_agent_id(),
    )?;
    assert_eq!(
        verify_for(&wire, &key, &wrong_run),
        Err(DecodeError::UnexpectedRun)
    );

    let mut wrong_source_bytes = value.source_agent_id().bytes();
    if let Some(first) = wrong_source_bytes.first_mut() {
        *first ^= 1;
    }
    let wrong_source = CanaryIdentity::new(
        value.run_id(),
        AgentId::new(wrong_source_bytes)?,
        value.destination_agent_id(),
    )?;
    assert_eq!(
        verify_for(&wire, &key, &wrong_source),
        Err(DecodeError::UnexpectedSourceAgent)
    );

    let mut wrong_destination_bytes = value.destination_agent_id().bytes();
    if let Some(first) = wrong_destination_bytes.first_mut() {
        *first ^= 1;
    }
    let wrong_destination = CanaryIdentity::new(
        value.run_id(),
        value.source_agent_id(),
        AgentId::new(wrong_destination_bytes)?,
    )?;
    assert_eq!(
        verify_for(&wire, &key, &wrong_destination),
        Err(DecodeError::UnexpectedDestinationAgent)
    );
    Ok(())
}

#[test]
fn includes_identity_in_replay_key() -> Result<(), Box<dyn Error>> {
    let mut guard = ReplayGuard::new();
    let value = canary_with_identity(7, 5)?;
    assert_eq!(guard.accept(&verified(&value)?), Ok(()));

    let mut different_source_bytes = value.source_agent_id().bytes();
    if let Some(first) = different_source_bytes.first_mut() {
        *first ^= 1;
    }
    let different_source_identity = CanaryIdentity::new(
        value.run_id(),
        AgentId::new(different_source_bytes)?,
        value.destination_agent_id(),
    )?;
    let different_source = Canary::new(different_source_identity, value.sequence(), value.nonce())?;
    assert_eq!(guard.accept(&verified(&different_source)?), Ok(()));

    let mut different_destination_bytes = value.destination_agent_id().bytes();
    if let Some(first) = different_destination_bytes.first_mut() {
        *first ^= 1;
    }
    let different_destination_identity = CanaryIdentity::new(
        value.run_id(),
        value.source_agent_id(),
        AgentId::new(different_destination_bytes)?,
    )?;
    let different_destination = Canary::new(
        different_destination_identity,
        value.sequence(),
        value.nonce(),
    )?;
    assert_eq!(guard.accept(&verified(&different_destination)?), Ok(()));
    Ok(())
}

#[test]
fn decode_errors_are_panic_free() -> Result<(), Box<dyn Error>> {
    let value = canary()?;
    let key = key_for(&value)?;
    let wire = encode(&value, &key)?;
    for length in 0..=WIRE_LEN + 2 {
        let mut input = wire.to_vec();
        input.truncate(length);
        let result = std::panic::catch_unwind(|| verify(&input, &key));
        assert!(result.is_ok(), "verification panicked at {length} bytes");
    }
    Ok(())
}
