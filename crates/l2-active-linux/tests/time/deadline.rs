use super::{decode_deadline, encode_deadline, ensure_before};
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
