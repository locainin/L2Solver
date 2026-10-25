#![no_main]

use l2_discovery::{TransportHeader, dns::DnsDecoding};
use libfuzzer_sys::fuzz_target;

// Ethernet validation owns framing bounds before protocol fingerprints inspect payloads
fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = l2_core::decode(data) {
        let _ = l2_discovery::discover(&frame);
        let _ = l2_discovery::arp_packet(&frame);
        if let Some(ip) = l2_discovery::ip_packet(&frame) {
            // An accepted envelope and its trailer partition the captured payload exactly
            assert_eq!(
                ip.declared_len.checked_add(ip.trailing_bytes.len()),
                Some(frame.payload.len())
            );
            if let Some(transport) = ip.transport {
                assert!(!ip.fragmented);
                assert_eq!(
                    transport
                        .payload_offset
                        .checked_add(transport.payload.len())
                        .and_then(|end| end.checked_add(transport.trailing_bytes.len())),
                    Some(ip.declared_len)
                );
                if matches!(transport.header, TransportHeader::Tcp { .. }) {
                    assert!(transport.trailing_bytes.is_empty());
                }
                if let Some(decoding) = l2_discovery::dns::udp_message(ip) {
                    assert_eq!(transport.header, TransportHeader::Udp);
                    assert!(transport.ports.0 == 53 || transport.ports.1 == 53);
                    match decoding {
                        DnsDecoding::Decoded { message } => {
                            assert!(
                                message
                                    .questions
                                    .iter()
                                    .all(|question| { question.name.wire().len() <= 255 })
                            );
                            assert!(message.records.iter().all(|record| {
                                record
                                    .rdata
                                    .offset
                                    .checked_add(record.rdata.length)
                                    .is_some_and(|end| end <= transport.payload.len())
                            }));
                        }
                        DnsDecoding::Unresolved { error } => {
                            assert!(error.offset <= transport.payload.len());
                        }
                    }
                }
            }
        }
    }
});
