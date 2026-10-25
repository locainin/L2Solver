use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, Protocol, fingerprint};

#[test]
fn recognizes_slow_protocol_subtype_one() {
    observed(&ethernet(0x8809, &[1, 1]), Protocol::Lacp);
    status(
        &ethernet(0x8809, &[1]),
        Protocol::Lacp,
        FingerprintStatus::Truncated,
    );
    status(
        &ethernet(0x8809, &[1, 0]),
        Protocol::Lacp,
        FingerprintStatus::Malformed,
    );
    status(
        &ethernet(0x8809, &[1, 2]),
        Protocol::Lacp,
        FingerprintStatus::Unsupported,
    );
    assert_eq!(fingerprint(&ethernet(0x8809, &[2, 1])), None);
    assert_eq!(fingerprint(&ethernet(0x8809, &[])), None);
}
