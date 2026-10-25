use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, Protocol};

#[test]
fn recognizes_declared_address_sizes() {
    let mut arp = vec![0, 1, 0x08, 0, 6, 4, 0, 1];
    arp.extend(std::iter::repeat_n(0, 20));
    observed(&ethernet(0x0806, &arp), Protocol::Arp);
    for length in 0..8 {
        status(
            &ethernet(0x0806, &vec![0; length]),
            Protocol::Arp,
            FingerprintStatus::Truncated,
        );
    }
    status(
        &ethernet(0x0806, &[0, 1, 0x08, 0, 6, 4, 0, 1]),
        Protocol::Arp,
        FingerprintStatus::Truncated,
    );
    status(
        &ethernet(0x0806, &[0, 1, 0x08, 0, 0, 4, 0, 1]),
        Protocol::Arp,
        FingerprintStatus::Malformed,
    );
}
