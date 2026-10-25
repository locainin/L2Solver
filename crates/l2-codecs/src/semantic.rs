//! Mandatory LLDP semantic checks

use crate::{Tlv, Validity};

/// Validate the mandatory LLDP prefix and its mandatory field shapes
pub fn validate_semantics(tlvs: &[Tlv<'_>]) -> Validity {
    let mut expected = 1u8;
    let mut valid = true;

    // Chassis ID, Port ID and TTL must be the first three non-End TLVs
    for tlv in tlvs {
        match tlv.kind {
            1 => {
                if expected != 1 || !valid_id(tlv.value, 4, 5) {
                    valid = false;
                }
                if expected == 1 {
                    expected = 2;
                }
            }
            2 => {
                if expected != 2 || !valid_id(tlv.value, 3, 4) {
                    valid = false;
                }
                if expected == 2 {
                    expected = 3;
                }
            }
            3 => {
                if expected != 3 || tlv.value.len() != 2 {
                    valid = false;
                }
                if expected == 3 {
                    expected = 4;
                }
            }
            // Optional and unknown TLVs before the mandatory prefix break the sequence
            _ if expected != 4 => valid = false,
            _ => {}
        }
    }

    if expected == 4 && valid {
        return Validity::Valid;
    }
    Validity::Invalid
}

/// Validate an ID's subtype and subtype-specific identifier length
fn valid_id(value: &[u8], mac_subtype: u8, network_subtype: u8) -> bool {
    // 802.1AB limits the ID value to one subtype octet and 255 identifier octets
    if value.len() > 256 {
        return false;
    }

    let Some((&subtype, identifier)) = value.split_first() else {
        return false;
    };

    // Subtype zero and values above seven are reserved in the base LLDP ID TLVs
    if !(1..=7).contains(&subtype) || identifier.is_empty() {
        return false;
    }

    // MAC IDs have one exact six-octet identifier after their subtype
    if subtype == mac_subtype {
        return identifier.len() == 6;
    }

    // Network IDs contain an address-family octet and at least one address octet
    if subtype == network_subtype {
        let Some((&address_family, address)) = identifier.split_first() else {
            return false;
        };
        return match address_family {
            // AFN 1 is IPv4 and AFN 2 is IPv6 in the LLDP network-address field
            1 => address.len() == 4,
            2 => address.len() == 16,
            // Preserve future address families while still requiring an address
            _ => !address.is_empty(),
        };
    }

    true
}
