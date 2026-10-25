use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, MAX_IPV6_EXTENSION_HEADERS, Protocol, fingerprint};

pub fn ipv6_packet(next_header: u8, body: &[u8]) -> Vec<u8> {
    let payload_length = u16::try_from(body.len()).unwrap_or(u16::MAX);
    ipv6_packet_with_declared_length(next_header, body, payload_length)
}

pub fn ipv6_packet_with_declared_length(
    next_header: u8,
    body: &[u8],
    payload_length: u16,
) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0, 0, 0, next_header, 64];
    packet.extend(std::iter::repeat_n(0, 32));
    if let Some(bytes) = packet.get_mut(4..6) {
        bytes.copy_from_slice(&payload_length.to_be_bytes());
    }
    packet.extend_from_slice(body);
    packet
}

#[test]
fn recognizes_ipv6_control_protocols() {
    let mut ra = vec![134, 0, 0, 0];
    ra.extend(std::iter::repeat_n(0, 12));
    observed(&ethernet(0x86dd, &ipv6_packet(58, &ra)), Protocol::Ipv6Ra);

    let mut ns = vec![135, 0, 0, 0];
    ns.extend(std::iter::repeat_n(0, 20));
    observed(&ethernet(0x86dd, &ipv6_packet(58, &ns)), Protocol::Ipv6Nd);

    let mut mld = vec![131, 0, 0, 0];
    mld.extend(std::iter::repeat_n(0, 20));
    observed(&ethernet(0x86dd, &ipv6_packet(58, &mld)), Protocol::Mld);

    let dhcpv6 = {
        let mut udp = Vec::new();
        udp.extend_from_slice(&546_u16.to_be_bytes());
        udp.extend_from_slice(&547_u16.to_be_bytes());
        udp.extend_from_slice(&8_u16.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        ipv6_packet(17, &udp)
    };
    observed(&ethernet(0x86dd, &dhcpv6), Protocol::Dhcpv6);

    let vrrp_v3 = [0x31, 1, 100, 0, 0, 1, 0, 0];
    status(
        &ethernet(0x86dd, &ipv6_packet(112, &vrrp_v3)),
        Protocol::Vrrp,
        FingerprintStatus::Malformed,
    );

    // The minimum eight-byte Neighbor Discovery message is a valid boundary
    let nd_minimum = [133, 0, 0, 0, 0, 0, 0, 0];
    observed(
        &ethernet(0x86dd, &ipv6_packet(58, &nd_minimum)),
        Protocol::Ipv6Nd,
    );
    let mut nd_redirect = vec![137, 0, 0, 0];
    nd_redirect.extend(std::iter::repeat_n(0, 36));
    observed(
        &ethernet(0x86dd, &ipv6_packet(58, &nd_redirect)),
        Protocol::Ipv6Nd,
    );
}

#[test]
fn reports_ipv6_protocol_boundaries() {
    for length in 0..40 {
        assert_eq!(fingerprint(&ethernet(0x86dd, &vec![0; length])), None);
    }
    let ra = vec![134, 0, 0, 0];
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &ra)),
        Protocol::Ipv6Ra,
        FingerprintStatus::Truncated,
    );
    let mut bad_code = vec![134, 1, 0, 0];
    bad_code.extend(std::iter::repeat_n(0, 12));
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &bad_code)),
        Protocol::Ipv6Ra,
        FingerprintStatus::Malformed,
    );
    let mld = vec![131, 0, 0, 0];
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &mld)),
        Protocol::Mld,
        FingerprintStatus::Truncated,
    );
    let udp = [
        546_u16.to_be_bytes(),
        547_u16.to_be_bytes(),
        8_u16.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    status(
        &ethernet(0x86dd, &ipv6_packet(17, &udp)),
        Protocol::Dhcpv6,
        FingerprintStatus::Observed,
    );
    let udp_bad_length = [
        546_u16.to_be_bytes(),
        547_u16.to_be_bytes(),
        20_u16.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    status(
        &ethernet(0x86dd, &ipv6_packet(17, &udp_bad_length)),
        Protocol::Dhcpv6,
        FingerprintStatus::Truncated,
    );
}

#[test]
fn validates_mldv2_sources_and_auxiliary() {
    let mut missing_source = vec![143, 0, 0, 0, 0, 0, 0, 1];
    missing_source.extend_from_slice(&[
        1, 0, 0, 1, // include-mode record with one declared source
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &missing_source)),
        Protocol::Mld,
        FingerprintStatus::Truncated,
    );

    let mut missing_auxiliary_word = vec![143, 0, 0, 0, 0, 0, 0, 1];
    missing_auxiliary_word.extend_from_slice(&[
        2, 1, 0, 0, // exclude-mode record with one declared auxiliary word
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]);
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &missing_auxiliary_word)),
        Protocol::Mld,
        FingerprintStatus::Truncated,
    );

    let mut complete = missing_source;
    complete.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    observed(
        &ethernet(0x86dd, &ipv6_packet(58, &complete)),
        Protocol::Mld,
    );

    let mut trailing = vec![143, 0, 0, 0, 0, 0, 0, 0];
    trailing.push(0xaa);
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &trailing)),
        Protocol::Mld,
        FingerprintStatus::Malformed,
    );
}

#[test]
fn walks_mldv2_records() {
    let mut complete = vec![143, 0, 0, 0, 0, 0, 0, 2];
    complete.extend_from_slice(&[
        1, 0, 0, 1, // include-mode record with one source
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, // exclude-mode record with one auxiliary word
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xde, 0xad, 0xbe, 0xef,
    ]);
    observed(
        &ethernet(0x86dd, &ipv6_packet(58, &complete)),
        Protocol::Mld,
    );

    let mut unknown_type = vec![143, 0, 0, 0, 0, 0, 0, 1];
    unknown_type.extend_from_slice(&[
        7, 0, 0, 0, // record type seven is not defined by RFC 3810
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    ]);
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &unknown_type)),
        Protocol::Mld,
        FingerprintStatus::Malformed,
    );
}

#[test]
fn enforces_mldv2_record_budget() {
    fn report(record_count: u16) -> Vec<u8> {
        let mut payload = vec![143, 0, 0, 0, 0, 0];
        payload.extend_from_slice(&record_count.to_be_bytes());
        for _ in 0..record_count {
            payload.extend_from_slice(&[
                1, 0, 0, 0, // include-mode record without sources or auxiliary data
                0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
        }
        payload
    }

    let maximum = report(256);
    observed(&ethernet(0x86dd, &ipv6_packet(58, &maximum)), Protocol::Mld);

    let over_budget = report(257);
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &over_budget)),
        Protocol::Mld,
        FingerprintStatus::Unsupported,
    );
}

fn ipv6_udp_packet(
    source: u16,
    destination: u16,
    declared_udp_length: u16,
    body: &[u8],
    declared_payload_length: u16,
) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&source.to_be_bytes());
    udp.extend_from_slice(&destination.to_be_bytes());
    udp.extend_from_slice(&declared_udp_length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(body);
    ipv6_packet_with_declared_length(17, &udp, declared_payload_length)
}

#[test]
fn preserves_ipv6_envelope_fragment_state() {
    let mut ra = vec![134, 0, 0, 0];
    ra.extend(std::iter::repeat_n(0, 12));

    // Captured bytes beyond the declared IPv6 payload are padding, not truncation
    let mut extra_capture = ipv6_packet(58, &ra);
    extra_capture.extend_from_slice(&[0xaa, 0xbb]);
    observed(&ethernet(0x86dd, &extra_capture), Protocol::Ipv6Ra);

    // Fragment flags change the result even when the fixed fragment header is complete
    let mut unfragmented = vec![58, 0, 0, 0, 0, 0, 0, 0];
    unfragmented.extend_from_slice(&ra);
    observed(
        &ethernet(0x86dd, &ipv6_packet(44, &unfragmented)),
        Protocol::Ipv6Ra,
    );
    for flags in [1_u16, 0xfff9] {
        let mut fragmented = vec![58, 0, 0, 0, 0, 0, 0, 0];
        if let Some(bytes) = fragmented.get_mut(2..4) {
            bytes.copy_from_slice(&flags.to_be_bytes());
        }
        fragmented.extend_from_slice(&ra);
        status(
            &ethernet(0x86dd, &ipv6_packet(44, &fragmented)),
            Protocol::Ipv6Ra,
            FingerprintStatus::Truncated,
        );
    }

    // Fragment state must not hide a malformed UDP envelope behind truncation
    let mut malformed_fragmented_udp = vec![17, 0, 0, 1, 0, 0, 0, 0];
    malformed_fragmented_udp.extend_from_slice(&546_u16.to_be_bytes());
    malformed_fragmented_udp.extend_from_slice(&547_u16.to_be_bytes());
    malformed_fragmented_udp.extend_from_slice(&4_u16.to_be_bytes());
    malformed_fragmented_udp.extend_from_slice(&[0, 0]);
    status(
        &ethernet(0x86dd, &ipv6_packet(44, &malformed_fragmented_udp)),
        Protocol::Dhcpv6,
        FingerprintStatus::Malformed,
    );
}

#[test]
fn honors_fragment_ah_header_lengths() {
    let mut ra = vec![134, 0, 0, 0];
    ra.extend(std::iter::repeat_n(0, 12));
    // Fragment headers always occupy eight bytes, while AH uses its own length field
    let mut fixed_fragment = vec![58, 1, 0, 0, 0, 0, 0, 0];
    fixed_fragment.extend_from_slice(&ra);
    observed(
        &ethernet(0x86dd, &ipv6_packet(44, &fixed_fragment)),
        Protocol::Ipv6Ra,
    );

    let mut ah_zero = vec![58, 0, 0, 0, 0, 0, 0, 0];
    ah_zero.extend_from_slice(&ra);
    assert_eq!(
        fingerprint(&ethernet(0x86dd, &ipv6_packet(51, &ah_zero))),
        None
    );
    let mut ah = vec![58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    ah.extend_from_slice(&ra);
    observed(&ethernet(0x86dd, &ipv6_packet(51, &ah)), Protocol::Ipv6Ra);
}

#[test]
fn checks_mld_record_boundaries() {
    // MLD records add a second size boundary beyond the fixed ICMPv6 header
    let mld_record_short = [143, 0, 0, 0, 0, 0, 0, 1];
    status(
        &ethernet(0x86dd, &ipv6_packet(58, &mld_record_short)),
        Protocol::Mld,
        FingerprintStatus::Truncated,
    );
    let mut mld_record_exact = mld_record_short.to_vec();
    mld_record_exact.extend(std::iter::repeat_n(0, 20));
    if let Some(record_type) = mld_record_exact.get_mut(8) {
        *record_type = 1;
    }
    observed(
        &ethernet(0x86dd, &ipv6_packet(58, &mld_record_exact)),
        Protocol::Mld,
    );
}

#[test]
fn checks_dhcpv6_port_length_boundaries() {
    // Both directions are valid, but a single matching endpoint is not enough
    assert_eq!(
        fingerprint(&ethernet(0x86dd, &ipv6_udp_packet(546, 600, 8, &[], 8),)),
        None
    );
    assert_eq!(
        fingerprint(&ethernet(0x86dd, &ipv6_udp_packet(600, 547, 8, &[], 8),)),
        None
    );
    assert_eq!(
        fingerprint(&ethernet(0x86dd, &ipv6_udp_packet(547, 600, 8, &[], 8),)),
        None
    );
    observed(
        &ethernet(0x86dd, &ipv6_udp_packet(547, 546, 8, &[], 8)),
        Protocol::Dhcpv6,
    );

    // A declared UDP length shorter than the IPv6 payload is malformed
    status(
        &ethernet(
            0x86dd,
            &ipv6_udp_packet(546, 547, 8, &[0xaa, 0xbb, 0xcc, 0xdd], 12),
        ),
        Protocol::Dhcpv6,
        FingerprintStatus::Malformed,
    );

    // A captured UDP header that falls short of the declared IPv6 payload is truncated
    status(
        &ethernet(0x86dd, &ipv6_udp_packet(546, 547, 8, &[], 12)),
        Protocol::Dhcpv6,
        FingerprintStatus::Truncated,
    );
}

#[test]
fn bounds_ipv6_extensions() {
    let mut body = vec![134, 0, 0, 0];
    body.extend(std::iter::repeat_n(0, 12));
    let mut packet = body;
    let mut following = 58;
    for _ in 0..MAX_IPV6_EXTENSION_HEADERS {
        let mut extension = vec![following, 0];
        extension.extend(std::iter::repeat_n(0, 6));
        extension.extend_from_slice(&packet);
        packet = extension;
        following = 0;
    }
    observed(
        &ethernet(0x86dd, &ipv6_packet(0, &packet)),
        Protocol::Ipv6Ra,
    );

    let mut beyond_cap = vec![134, 0, 0, 0];
    beyond_cap.extend(std::iter::repeat_n(0, 12));
    let mut following = 58;
    for _ in 0..=MAX_IPV6_EXTENSION_HEADERS {
        let mut extension = vec![following, 0];
        extension.extend(std::iter::repeat_n(0, 6));
        extension.extend_from_slice(&beyond_cap);
        beyond_cap = extension;
        following = 0;
    }
    assert_eq!(
        fingerprint(&ethernet(0x86dd, &ipv6_packet(0, &beyond_cap))),
        None
    );

    let mut truncated_extension = vec![58, 1, 0, 0];
    truncated_extension.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        fingerprint(&ethernet(
            0x86dd,
            &ipv6_packet(0, truncated_extension.get(..7).unwrap_or_default())
        )),
        None
    );
    let mut inconsistent_payload = ipv6_packet(58, &[134, 0, 0, 0]);
    if let Some(bytes) = inconsistent_payload.get_mut(4..6) {
        bytes.copy_from_slice(&16_u16.to_be_bytes());
    }
    status(
        &ethernet(0x86dd, &inconsistent_payload),
        Protocol::Ipv6Ra,
        FingerprintStatus::Truncated,
    );
}
