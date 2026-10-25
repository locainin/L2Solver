use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, Protocol};

#[test]
fn recognizes_sectag_and_optional_sci() {
    observed(&ethernet(0x88e5, &[0, 0, 0, 0, 0, 1]), Protocol::Macsec);
    let mut with_sci = vec![0x20, 0, 0, 0, 0, 1];
    with_sci.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    observed(&ethernet(0x88e5, &with_sci), Protocol::Macsec);
    for length in 0..6 {
        status(
            &ethernet(0x88e5, &vec![0; length]),
            Protocol::Macsec,
            FingerprintStatus::Truncated,
        );
    }
    let mut truncated_sci = vec![0x20, 0, 0, 0, 0, 1];
    truncated_sci.extend_from_slice(&[0, 1, 2]);
    status(
        &ethernet(0x88e5, &truncated_sci),
        Protocol::Macsec,
        FingerprintStatus::Truncated,
    );
}
