use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, Protocol};

#[test]
fn recognizes_complete_headers() {
    observed(&ethernet(0x888e, &[2, 0, 0, 0]), Protocol::Eapol);
    observed(&ethernet(0x888e, &[2, 0, 0, 1, 1]), Protocol::Eapol);
}

#[test]
fn reports_header_and_length_truncation() {
    for length in 0..4 {
        status(
            &ethernet(0x888e, &vec![0; length]),
            Protocol::Eapol,
            FingerprintStatus::Truncated,
        );
    }
    status(
        &ethernet(0x888e, &[2, 0, 0, 4, 1, 2]),
        Protocol::Eapol,
        FingerprintStatus::Truncated,
    );
    status(
        &ethernet(0x888e, &[0, 0, 0, 0]),
        Protocol::Eapol,
        FingerprintStatus::Malformed,
    );
    status(
        &ethernet(0x888e, &[4, 0, 0, 0]),
        Protocol::Eapol,
        FingerprintStatus::Unsupported,
    );
    status(
        &ethernet(0x888e, &[2, 9, 0, 0]),
        Protocol::Eapol,
        FingerprintStatus::Unsupported,
    );
}
