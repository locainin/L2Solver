use super::common::{ethernet, observed, status};
use l2_discovery::{FingerprintStatus, Protocol, fingerprint};

pub fn ipv4_udp(
    source_port: u16,
    destination_port: u16,
    udp_length: u16,
    total_length: u16,
    flags_and_fragment: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
    packet.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    if let Some(bytes) = packet.get_mut(2..4) {
        bytes.copy_from_slice(&total_length.to_be_bytes());
    }
    if let Some(bytes) = packet.get_mut(6..8) {
        bytes.copy_from_slice(&flags_and_fragment.to_be_bytes());
    }
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&udp_length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(body);
    packet
}

pub fn ipv4_protocol(protocol: u8, body: &[u8]) -> Vec<u8> {
    let total_length = u16::try_from(20 + body.len()).unwrap_or(u16::MAX);
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0];
    packet.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    if let Some(bytes) = packet.get_mut(2..4) {
        bytes.copy_from_slice(&total_length.to_be_bytes());
    }
    packet.extend_from_slice(body);
    packet
}

#[test]
fn recognizes_dhcp_and_hsrp_ports() {
    let dhcp_body = dhcp_payload(1);
    let dhcp_length = u16::try_from(8 + dhcp_body.len()).unwrap_or(u16::MAX);
    let dhcp_total = u16::try_from(20 + usize::from(dhcp_length)).unwrap_or(u16::MAX);
    let dhcp = ipv4_udp(68, 67, dhcp_length, dhcp_total, 0, &dhcp_body);
    observed(&ethernet(0x0800, &dhcp), Protocol::Dhcp);
    let hsrp_body = hsrp_payload(0, 0, 16);
    let hsrp = ipv4_udp(1985, 1985, 28, 48, 0, &hsrp_body);
    observed(&ethernet(0x0800, &hsrp), Protocol::Hsrp);
    let hsrp_ipv6_port = ipv4_udp(2029, 1985, 28, 48, 0, &hsrp_body);
    observed(&ethernet(0x0800, &hsrp_ipv6_port), Protocol::Hsrp);
}

fn dhcp_payload(message_type: u8) -> Vec<u8> {
    let mut body = vec![0; 240];
    if let Some(bytes) = body.get_mut(236..240) {
        bytes.copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    }
    body.extend_from_slice(&[53, 1, message_type, 255]);
    body
}

fn hsrp_payload(version: u8, opcode: u8, state: u8) -> Vec<u8> {
    let mut body = vec![version, opcode, state, 3, 10, 100, 0, 0];
    body.extend_from_slice(&[0; 8]);
    body.extend_from_slice(&[192, 0, 2, 1]);
    body
}

fn check_dhcp_body(body: &[u8], expected: FingerprintStatus) {
    let udp_length = u16::try_from(8 + body.len()).unwrap_or(u16::MAX);
    let total_length = u16::try_from(20 + usize::from(udp_length)).unwrap_or(u16::MAX);
    status(
        &ethernet(0x0800, &ipv4_udp(68, 67, udp_length, total_length, 0, body)),
        Protocol::Dhcp,
        expected,
    );
}

#[test]
fn dhcp_requires_header_and_cookie() {
    let short = ipv4_udp(68, 67, 8, 28, 0, &[]);
    status(
        &ethernet(0x0800, &short),
        Protocol::Dhcp,
        FingerprintStatus::Truncated,
    );

    let mut bad_cookie = dhcp_payload(1);
    if let Some(byte) = bad_cookie.get_mut(236) {
        *byte = 0;
    }
    check_dhcp_body(&bad_cookie, FingerprintStatus::Malformed);
}

#[test]
fn dhcp_requires_message_type() {
    let mut no_message_type = vec![0; 240];
    if let Some(bytes) = no_message_type.get_mut(236..240) {
        bytes.copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    }
    no_message_type.extend_from_slice(&[255]);
    check_dhcp_body(&no_message_type, FingerprintStatus::Malformed);
}

#[test]
fn dhcp_reports_cut_options_truncated() {
    let mut cut_option = dhcp_payload(1);
    cut_option.truncate(cut_option.len().saturating_sub(1));
    check_dhcp_body(&cut_option, FingerprintStatus::Truncated);

    let mut cut_option_value = dhcp_payload(1);
    if let Some(bytes) = cut_option_value.get_mut(240..243) {
        bytes.copy_from_slice(&[53, 2, 1]);
    }
    cut_option_value.truncate(243);
    check_dhcp_body(&cut_option_value, FingerprintStatus::Truncated);
}

#[test]
fn dhcp_invalid_message_type_length() {
    let mut bad_option_length = dhcp_payload(1);
    if let Some(bytes) = bad_option_length.get_mut(240..243) {
        bytes.copy_from_slice(&[53, 2, 1]);
    }
    check_dhcp_body(&bad_option_length, FingerprintStatus::Malformed);
}

#[test]
fn distinguishes_dhcp_option_boundaries() {
    // The fixed BOOTP header and cookie without an option is malformed, not truncated
    let mut minimum = vec![0; 240];
    if let Some(cookie) = minimum.get_mut(236..240) {
        cookie.copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    }
    status(
        &ethernet(0x0800, &ipv4_udp(68, 67, 248, 268, 0, &minimum)),
        Protocol::Dhcp,
        FingerprintStatus::Malformed,
    );

    // A complete generic option that ends at EOF leaves the stream malformed without an END
    let mut exact_option = minimum.clone();
    exact_option.extend_from_slice(&[12, 1, 0]);
    status(
        &ethernet(0x0800, &ipv4_udp(68, 67, 251, 271, 0, &exact_option)),
        Protocol::Dhcp,
        FingerprintStatus::Malformed,
    );

    // A generic option whose declared value crosses EOF is truncated
    let mut overrun = minimum;
    overrun.extend_from_slice(&[12, 2, 0]);
    status(
        &ethernet(0x0800, &ipv4_udp(68, 67, 251, 271, 0, &overrun)),
        Protocol::Dhcp,
        FingerprintStatus::Truncated,
    );
}

#[test]
fn stops_dhcp_scan_work_budget() {
    let mut body = vec![0; 240];
    if let Some(cookie) = body.get_mut(236..240) {
        cookie.copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    }
    body.extend(std::iter::repeat_n(0, 129));
    body.extend_from_slice(&[53, 1, 1, 255]);
    let udp_length = u16::try_from(8 + body.len()).unwrap_or(u16::MAX);
    let total_length = u16::try_from(20 + usize::from(udp_length)).unwrap_or(u16::MAX);

    status(
        &ethernet(
            0x0800,
            &ipv4_udp(68, 67, udp_length, total_length, 0, &body),
        ),
        Protocol::Dhcp,
        FingerprintStatus::Unsupported,
    );
}

#[test]
fn requires_valid_hsrp_header() {
    for length in 0..20 {
        let length_field = u16::try_from(length).unwrap_or_default();
        status(
            &ethernet(
                0x0800,
                &ipv4_udp(
                    1985,
                    1985,
                    8 + length_field,
                    28 + length_field,
                    0,
                    &vec![0; length],
                ),
            ),
            Protocol::Hsrp,
            FingerprintStatus::Truncated,
        );
    }
    let bad_version = hsrp_payload(9, 0, 16);
    status(
        &ethernet(0x0800, &ipv4_udp(1985, 1985, 28, 48, 0, &bad_version)),
        Protocol::Hsrp,
        FingerprintStatus::Unsupported,
    );
    let hsrp_v2 = hsrp_payload(2, 0, 16);
    status(
        &ethernet(0x0800, &ipv4_udp(1985, 1985, 28, 48, 0, &hsrp_v2)),
        Protocol::Hsrp,
        FingerprintStatus::Unsupported,
    );
    let bad_opcode = hsrp_payload(0, 9, 16);
    status(
        &ethernet(0x0800, &ipv4_udp(1985, 1985, 28, 48, 0, &bad_opcode)),
        Protocol::Hsrp,
        FingerprintStatus::Malformed,
    );
    let bad_state = hsrp_payload(0, 0, 3);
    status(
        &ethernet(0x0800, &ipv4_udp(1985, 1985, 28, 48, 0, &bad_state)),
        Protocol::Hsrp,
        FingerprintStatus::Malformed,
    );
    let valid_opcode_boundary = hsrp_payload(0, 2, 16);
    observed(
        &ethernet(
            0x0800,
            &ipv4_udp(1985, 1985, 28, 48, 0, &valid_opcode_boundary),
        ),
        Protocol::Hsrp,
    );
}

#[test]
fn rejects_false_ports_and_fragments() {
    let unrelated = ipv4_udp(40000, 67, 8, 20, 0, &[]);
    assert_eq!(fingerprint(&ethernet(0x0800, &unrelated)), None);
    let first_fragment = ipv4_udp(68, 67, 8, 20, 0x2000, &[]);
    assert_eq!(fingerprint(&ethernet(0x0800, &first_fragment)), None);
    let later_fragment = ipv4_udp(68, 67, 8, 20, 0x0001, &[]);
    assert_eq!(fingerprint(&ethernet(0x0800, &later_fragment)), None);
}

#[test]
fn reports_ipv4_udp_boundaries() {
    for length in 0..20 {
        assert_eq!(fingerprint(&ethernet(0x0800, &vec![0; length])), None);
    }
    let mut bad_version = ipv4_udp(68, 67, 8, 20, 0, &[]);
    if let Some(byte) = bad_version.first_mut() {
        *byte = 0x65;
    }
    assert_eq!(fingerprint(&ethernet(0x0800, &bad_version)), None);

    let short_ip_header = ipv4_udp(68, 67, 8, 20, 0, &[]);
    let mut captured_short = short_ip_header;
    captured_short.truncate(19);
    assert_eq!(fingerprint(&ethernet(0x0800, &captured_short)), None);

    let short_total = ipv4_udp(68, 67, 8, 19, 0, &[]);
    assert_eq!(fingerprint(&ethernet(0x0800, &short_total)), None);
    let truncated_ip = ipv4_udp(68, 67, 28, 48, 0, &[]);
    status(
        &ethernet(0x0800, &truncated_ip),
        Protocol::Dhcp,
        FingerprintStatus::Truncated,
    );
    let malformed_udp = ipv4_udp(68, 67, 4, 20, 0, &[]);
    status(
        &ethernet(0x0800, &malformed_udp),
        Protocol::Dhcp,
        FingerprintStatus::Malformed,
    );
    let inconsistent_udp = ipv4_udp(68, 67, 8, 24, 0, &[0xaa, 0xbb, 0xcc, 0xdd]);
    status(
        &ethernet(0x0800, &inconsistent_udp),
        Protocol::Dhcp,
        FingerprintStatus::Malformed,
    );

    // An invalid IHL must not be reinterpreted as a shorter valid header
    let mut short_ihl = vec![0x44, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1];
    short_ihl.extend_from_slice(&68_u16.to_be_bytes());
    short_ihl.extend_from_slice(&67_u16.to_be_bytes());
    short_ihl.extend_from_slice(&8_u16.to_be_bytes());
    short_ihl.extend_from_slice(&[0, 0]);
    assert_eq!(fingerprint(&ethernet(0x0800, &short_ihl)), None);

    // Only one endpoint matching a DHCP or HSRP pair is not enough to classify the packet
    for (source, destination) in [(68, 40_000), (67, 40_000)] {
        assert_eq!(
            fingerprint(&ethernet(
                0x0800,
                &ipv4_udp(source, destination, 8, 28, 0, &[]),
            )),
            None
        );
    }
    assert_eq!(
        fingerprint(&ethernet(0x0800, &ipv4_udp(1985, 40_000, 8, 28, 0, &[]),)),
        None
    );

    // A declared UDP payload beyond the IP boundary cannot be treated as a valid DHCP body
    let dhcp = dhcp_payload(1);
    let oversized_udp_length = u16::try_from(8 + dhcp.len()).unwrap_or(u16::MAX);
    status(
        &ethernet(
            0x0800,
            &ipv4_udp(68, 67, oversized_udp_length, 28, 0, &dhcp),
        ),
        Protocol::Dhcp,
        FingerprintStatus::Truncated,
    );

    // Extra IP payload after a complete DHCP body is an inconsistent UDP length
    let valid_udp_length = u16::try_from(8 + dhcp.len()).unwrap_or(u16::MAX);
    let total_length = valid_udp_length.saturating_add(24);
    let mut short_udp = ipv4_udp(68, 67, valid_udp_length, total_length, 0, &dhcp);
    short_udp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    status(
        &ethernet(0x0800, &short_udp),
        Protocol::Dhcp,
        FingerprintStatus::Malformed,
    );
}

#[test]
fn recognizes_vrrp_rejects_zero_count() {
    let vrrp_v2 = [0x21, 1, 100, 0, 0, 1, 0, 0];
    status(
        &ethernet(0x0800, &ipv4_protocol(112, &vrrp_v2)),
        Protocol::Vrrp,
        FingerprintStatus::Malformed,
    );
    let vrrp_v3 = [
        0x31, 1, 100, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    observed(
        &ethernet(0x0800, &ipv4_protocol(112, &vrrp_v3)),
        Protocol::Vrrp,
    );
    for length in 0..8 {
        status(
            &ethernet(0x0800, &ipv4_protocol(112, &vec![0; length])),
            Protocol::Vrrp,
            FingerprintStatus::Truncated,
        );
    }
    let bad_version = [0x41, 1, 100, 0, 0, 1, 0, 0];
    status(
        &ethernet(0x0800, &ipv4_protocol(112, &bad_version)),
        Protocol::Vrrp,
        FingerprintStatus::Unsupported,
    );
    assert_eq!(
        fingerprint(&ethernet(0x0800, &ipv4_protocol(6, &vrrp_v2))),
        None
    );

    // Version two uses four-byte addresses and accepts the exact one-address boundary
    let vrrp_v2_with_address = [0x21, 1, 100, 1, 192, 0, 2, 1, 0, 0, 0, 0];
    observed(
        &ethernet(0x0800, &ipv4_protocol(112, &vrrp_v2_with_address)),
        Protocol::Vrrp,
    );
    let vrrp_v2_missing_address = [0x21, 1, 100, 1, 0, 0, 0, 0];
    status(
        &ethernet(0x0800, &ipv4_protocol(112, &vrrp_v2_missing_address)),
        Protocol::Vrrp,
        FingerprintStatus::Truncated,
    );

    // Captured Ethernet padding beyond the declared IPv4 length is not capture truncation
    let mut extra_capture = ipv4_protocol(112, &vrrp_v2_with_address);
    extra_capture.extend_from_slice(&[0xaa, 0xbb]);
    observed(&ethernet(0x0800, &extra_capture), Protocol::Vrrp);
}
