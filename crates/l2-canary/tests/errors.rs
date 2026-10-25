use l2_canary::{
    AgentIdError, CanaryError, CanaryIdentityError, DecodeError, KeyError, ReplayError,
};

#[test]
fn public_error_messages_keep_context() {
    // Each variant carries different details that operators need when a canary is rejected
    let cases = [
        (
            DecodeError::Truncated {
                needed: 96,
                available: 12,
            },
            "canary payload is truncated: need 96 bytes, have 12",
        ),
        (
            DecodeError::TrailingBytes {
                expected: 96,
                actual: 97,
            },
            "canary payload has trailing bytes: expected 96 bytes, received 97",
        ),
        (
            DecodeError::UnsupportedVersion { value: 9 },
            "unsupported canary version 9",
        ),
        (
            DecodeError::InvalidTag,
            "canary authentication tag is invalid",
        ),
        (DecodeError::ZeroSequence, "canary sequence must be nonzero"),
        (
            DecodeError::UnexpectedRun,
            "canary run identity is unexpected",
        ),
        (
            DecodeError::UnexpectedSourceAgent,
            "canary source agent identity is unexpected",
        ),
        (
            DecodeError::UnexpectedDestinationAgent,
            "canary destination agent identity is unexpected",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }

    // Key and replay errors also expose their bounded-policy values
    assert_eq!(
        KeyError::TooShort { length: 4, min: 32 }.to_string(),
        "secret key has 4 bytes; minimum is 32"
    );
    assert_eq!(
        KeyError::TooLong {
            length: 65,
            max: 64
        }
        .to_string(),
        "secret key has 65 bytes; maximum is 64"
    );
    assert_eq!(
        KeyError::AgentKeyMismatch.to_string(),
        "agent relationship key does not belong to the source agent"
    );
    assert_eq!(
        AgentIdError::ReservedZero.to_string(),
        "agent ID must not be all zeroes"
    );
    assert_eq!(
        CanaryIdentityError::SameAgent.to_string(),
        "canary source and destination agents must differ"
    );
    assert_eq!(
        CanaryError::ZeroSequence.to_string(),
        "canary sequence must be nonzero"
    );
    assert_eq!(
        ReplayError::NonIncreasing {
            previous: 10,
            sequence: 9,
        }
        .to_string(),
        "canary sequence 9 is not greater than previously accepted 10"
    );
    assert_eq!(
        ReplayError::IdentityLimit { max: 1024 }.to_string(),
        "replay guard identity limit of 1024 entries reached"
    );
}
