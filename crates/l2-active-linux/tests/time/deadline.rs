use super::{decode_deadline, decode_deadline_at, encode_deadline, ensure_before, monotonic_nanos};
use std::{
    io,
    time::{Duration, Instant},
};

#[test]
fn expired_deadlines_cannot_authorize_a_packet_operation() {
    let result = encode_deadline(Instant::now(), Duration::from_secs(1));
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let result = decode_deadline(0);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
}

#[test]
fn process_transport_never_extends_the_original_deadline() -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let encoded = encode_deadline(deadline, Duration::from_secs(1))?;
    let recovered = decode_deadline(encoded)?;
    assert!(
        recovered <= deadline,
        "transport deadline must not exceed caller deadline"
    );
    Ok(())
}

#[test]
fn a_frame_completed_after_the_observation_deadline_is_rejected() {
    let result = ensure_before(Instant::now());
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
}

#[test]
fn encoded_deadline_obeys_the_shorter_transport_ceiling() -> io::Result<()> {
    let ceiling = Duration::from_secs(2);
    let encoded = encode_deadline(Instant::now() + Duration::from_secs(10), ceiling)?;
    let after_encoding = Instant::now();
    let recovered = decode_deadline(encoded)?;
    assert!(recovered <= after_encoding + ceiling);
    Ok(())
}

#[test]
fn zero_ceiling_and_excessive_worker_deadlines_are_rejected() -> io::Result<()> {
    let encoded = encode_deadline(Instant::now() + Duration::from_secs(1), Duration::ZERO);
    assert_eq!(
        encoded.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );

    // Leave a full worker timeout of slack for scheduling between clock samples
    let beyond_ceiling = monotonic_nanos()?
        .checked_add(
            u64::try_from((l2_active::MAX_TIMEOUT * 2).as_nanos()).map_err(io::Error::other)?,
        )
        .ok_or_else(|| io::Error::other("test deadline overflow"))?;
    assert_eq!(
        decode_deadline(beyond_ceiling)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[test]
fn a_live_deadline_allows_the_operation() -> io::Result<()> {
    ensure_before(Instant::now() + Duration::from_secs(30))
}

#[test]
fn decoded_deadline_enforces_exact_expiry_and_worker_ceiling() -> io::Result<()> {
    let sampled = Instant::now();
    let monotonic = 10_000;
    let ceiling = u64::try_from(l2_active::MAX_TIMEOUT.as_nanos()).map_err(io::Error::other)?;

    assert_eq!(
        decode_deadline_at(monotonic, sampled, monotonic)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut),
        "a deadline equal to the sampled clock is already expired"
    );
    assert_eq!(
        decode_deadline_at(monotonic + 1, sampled, monotonic)?,
        sampled + Duration::from_nanos(1),
        "a positive remaining deadline is accepted"
    );
    assert_eq!(
        decode_deadline_at(monotonic + ceiling, sampled, monotonic)?,
        sampled + l2_active::MAX_TIMEOUT,
        "the worker accepts its exact timeout ceiling"
    );
    assert_eq!(
        decode_deadline_at(monotonic + ceiling + 1, sampled, monotonic)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput),
        "a deadline above the worker ceiling is rejected"
    );
    Ok(())
}
