use l2_capture::LinkType;
use l2_core::FrameField;
use l2_discovery::{
    IpPacket, fragment_packet_from_payload, ip_header_from_payload, ip_packet_from_payload,
    link::decode_network_frame,
};

pub fn exercise<F>(data: &[u8], mut observe: F)
where
    F: for<'a> FnMut(LinkType, Option<IpPacket<'a>>),
{
    let Ok(mut capture) = l2_pcap::CaptureSource::new(data) else {
        return;
    };
    // Each successful read consumes a record, so finite input bounds this loop
    while let Ok(Some(frame)) = capture.next_packet() {
        let link_type = frame.metadata().link_type();
        let packet = decode_network_frame(link_type, frame.bytes()).and_then(|network| {
            let offset = network.payload_offset();
            let payload = network.payload();
            assert!(
                offset
                    .checked_add(payload.len())
                    .is_some_and(|end| { frame.bytes().get(offset..end) == Some(payload) })
            );

            // Cooked payloads are interpreted as IP only for supported EtherType semantics
            let FrameField::EtherType(protocol) = network.field()? else {
                return None;
            };
            let _ = ip_header_from_payload(protocol, payload);
            if let Some(fragment) = fragment_packet_from_payload(protocol, payload) {
                assert!(fragment.payload.len() <= fragment.declared_payload_length);
                assert!(
                    fragment
                        .payload_offset
                        .checked_add(fragment.payload.len())
                        .is_some_and(|end| end <= payload.len())
                );
                if fragment.captured_complete {
                    assert_eq!(fragment.payload.len(), fragment.declared_payload_length);
                }
            }
            let packet = ip_packet_from_payload(protocol, payload)?;
            assert_eq!(
                packet.declared_len.checked_add(packet.trailing_bytes.len()),
                Some(payload.len())
            );
            if let Some(transport) = packet.transport {
                assert_eq!(
                    transport
                        .payload_offset
                        .checked_add(transport.payload.len())
                        .and_then(|end| end.checked_add(transport.trailing_bytes.len())),
                    Some(packet.declared_len)
                );
            }
            Some(packet)
        });
        observe(link_type, packet);
    }
}
