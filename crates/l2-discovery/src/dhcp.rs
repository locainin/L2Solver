use crate::{Fingerprint, Protocol, bytes::read_u8};

const BOOTP_FIXED_HEADER_LEN: usize = 236;
const DHCP_MAGIC_COOKIE_LEN: usize = 4;
const DHCP_MIN_HEADER_LEN: usize = BOOTP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE_LEN;
const DHCP_MAGIC_COOKIE: [u8; DHCP_MAGIC_COOKIE_LEN] = [0x63, 0x82, 0x53, 0x63];
const DHCP_MESSAGE_TYPE_OPTION: u8 = 53;
const DHCP_OPTION_END: u8 = 255;
const DHCP_OPTION_PAD: u8 = 0;
const MAX_DHCP_OPTIONS: usize = 128;

/// Check the bounded BOOTP header and the DHCP message-type option
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    if payload.len() < DHCP_MIN_HEADER_LEN {
        return Fingerprint::truncated(Protocol::Dhcp);
    }
    if payload.get(BOOTP_FIXED_HEADER_LEN..DHCP_MIN_HEADER_LEN)
        != Some(DHCP_MAGIC_COOKIE.as_slice())
    {
        return Fingerprint::malformed(Protocol::Dhcp);
    }

    let mut offset = DHCP_MIN_HEADER_LEN;
    let mut message_type_supported = None;
    let mut option_count = 0;
    while let Some(option) = read_u8(payload, offset) {
        if option_count == MAX_DHCP_OPTIONS {
            return Fingerprint::unsupported(Protocol::Dhcp);
        }
        option_count += 1;
        let Some(value_start) = offset.checked_add(1) else {
            return Fingerprint::malformed(Protocol::Dhcp);
        };
        match option {
            DHCP_OPTION_PAD => {
                offset = value_start;
            }
            DHCP_OPTION_END => {
                return match message_type_supported {
                    Some(true) => Fingerprint::observed(Protocol::Dhcp),
                    Some(false) => Fingerprint::unsupported(Protocol::Dhcp),
                    None => Fingerprint::malformed(Protocol::Dhcp),
                };
            }
            DHCP_MESSAGE_TYPE_OPTION => {
                if message_type_supported.is_some() {
                    return Fingerprint::malformed(Protocol::Dhcp);
                }
                let Some(length) = read_u8(payload, value_start).map(usize::from) else {
                    return Fingerprint::truncated(Protocol::Dhcp);
                };
                let Some(value_end) = value_start
                    .checked_add(1)
                    .and_then(|start| start.checked_add(length))
                else {
                    return Fingerprint::malformed(Protocol::Dhcp);
                };
                if value_end > payload.len() {
                    return Fingerprint::truncated(Protocol::Dhcp);
                }
                if length != 1 {
                    return Fingerprint::malformed(Protocol::Dhcp);
                }
                let Some(message_offset) = value_start.checked_add(1) else {
                    return Fingerprint::malformed(Protocol::Dhcp);
                };
                let Some(message_type) = read_u8(payload, message_offset) else {
                    return Fingerprint::truncated(Protocol::Dhcp);
                };
                // Values 1 through 18 are assigned in the IANA DHCP registry
                message_type_supported = Some(matches!(message_type, 1..=18));
                offset = value_end;
            }
            _ => {
                let Some(length) = read_u8(payload, value_start).map(usize::from) else {
                    return Fingerprint::truncated(Protocol::Dhcp);
                };
                let Some(next) = value_start
                    .checked_add(1)
                    .and_then(|start| start.checked_add(length))
                else {
                    return Fingerprint::malformed(Protocol::Dhcp);
                };
                if next > payload.len() {
                    return Fingerprint::truncated(Protocol::Dhcp);
                }
                offset = next;
            }
        }
    }
    // A message type followed by a cut option stream is distinguishable from a packet
    // that never contained a DHCP option at all
    if message_type_supported.is_some() {
        Fingerprint::truncated(Protocol::Dhcp)
    } else {
        Fingerprint::malformed(Protocol::Dhcp)
    }
}
