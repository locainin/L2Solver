//! Check ISL framing without exposing or interpreting encapsulated user traffic

use super::{IslEvidence, IslHeader, IslMalformed};

const HEADER_BYTES: usize = 26;
const OUTER_HEADER_BYTES: usize = 14;
pub(super) const SUFFIX_BYTES: u16 = 12;
pub(super) const LLC: [u8; 3] = [0xaa, 0xaa, 3];
pub(super) const HSA: [u8; 3] = [0, 0, 0x0c];
const INNER_FCS_BYTES: usize = 4;
const ETHERNET_HEADER_BYTES: usize = 14;
// Cisco documents a maximum of 24,575 bytes for the encapsulated frame
const MAX_INNER_BYTES: usize = 24_575;

pub(super) fn classify(frame: &[u8]) -> Option<IslEvidence> {
    // Recognize either 40-bit prefix before interpreting any other field
    let prefix = frame.get(..5)?;
    if prefix != [1, 0, 0x0c, 0, 0] && prefix != [3, 0, 0x0c, 0, 0] {
        return None;
    }
    Some(decode(frame))
}

fn decode(frame: &[u8]) -> IslEvidence {
    let Some(header) = frame.get(..HEADER_BYTES) else {
        return IslEvidence::Malformed(IslMalformed::Header);
    };
    let Some(destination) = field::<6>(header, 0) else {
        return IslEvidence::Malformed(IslMalformed::Header);
    };
    let Some(source) = field::<6>(header, 6) else {
        return IslEvidence::Malformed(IslMalformed::Header);
    };
    // The address is still only an unauthenticated sender claim
    let [first, ..] = source;
    if source == [0; 6] || first & 1 != 0 {
        return IslEvidence::Malformed(IslMalformed::SourceMac);
    }
    if header.get(14..17) != Some(&LLC) || header.get(17..20) != Some(&HSA) {
        return IslEvidence::Malformed(IslMalformed::Header);
    }
    // The final destination byte is shared by the media and USER fields
    let [_, _, _, _, _, media_user] = destination;
    let media = media_user >> 4;
    if media != 0 {
        return IslEvidence::UnsupportedMedia(media);
    }
    let Some(length) = be16(header, 12) else {
        return IslEvidence::Malformed(IslMalformed::Header);
    };
    if length == 0 {
        // Some dissectors accept zero, but it does not establish the inner boundary
        return IslEvidence::UnsupportedLength;
    }
    let length_usize = usize::from(length);
    let Some(inner_len) = length.checked_sub(SUFFIX_BYTES).map(usize::from) else {
        return IslEvidence::Malformed(IslMalformed::Length);
    };
    if inner_len > MAX_INNER_BYTES {
        return IslEvidence::LimitExceeded;
    }
    if inner_len < ETHERNET_HEADER_BYTES + INNER_FCS_BYTES {
        return IslEvidence::Malformed(IslMalformed::Length);
    }
    // The declared boundary excludes any possible outer FCS or padding
    let Some(payload) = frame.get(HEADER_BYTES..OUTER_HEADER_BYTES + length_usize) else {
        return IslEvidence::Malformed(IslMalformed::Length);
    };
    // Remove the protocol-designated inner FCS before validating Ethernet lengths
    let Some(inner) = payload.get(..inner_len - INNER_FCS_BYTES) else {
        return IslEvidence::Malformed(IslMalformed::Length);
    };
    // Validate the inner Ethernet envelope without interpreting user payload
    if l2_core::decode(inner).is_err() {
        return IslEvidence::Malformed(IslMalformed::InnerEthernet);
    }
    let (Some(vlan_bpdu), Some(port_index), Some(reserved)) =
        (be16(header, 20), be16(header, 22), be16(header, 24))
    else {
        return IslEvidence::Malformed(IslMalformed::Header);
    };
    IslEvidence::Frame(IslHeader {
        destination,
        source,
        length,
        vlan_bpdu,
        port_index,
        reserved,
    })
}

fn field<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    input.get(offset..offset + N)?.try_into().ok()
}

fn be16(input: &[u8], offset: usize) -> Option<u16> {
    field::<2>(input, offset).map(u16::from_be_bytes)
}
