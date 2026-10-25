#![no_main]

use libfuzzer_sys::fuzz_target;
use wifi_codecs::{ElementKind, InformationElement, ManagementBody};

const MAX_FRAME_BYTES: usize = 4_096;
const MAX_ELEMENT_VALUE_BYTES: usize = u8::MAX as usize;

// Decode the raw frame first so management parsing sees the same borrowed body
fuzz_target!(|data: &[u8]| {
    let length = data.len().min(MAX_FRAME_BYTES);
    let Some(input) = data.get(..length) else {
        return;
    };
    exercise_management(input);

    // A seeded beacon keeps information-element and RSN paths reachable while
    // the raw input still supplies arbitrary element bytes
    let seeded = seeded_beacon(input);
    exercise_management(&seeded);
});

fn exercise_management(input: &[u8]) {
    let Ok(frame) = wifi_core::decode(input) else {
        return;
    };
    let Ok(decoded) = wifi_codecs::parse_management(&frame) else {
        return;
    };
    let _ = decoded.subtype();
    match decoded.body() {
        ManagementBody::AssociationRequest(body) => visit_elements(&body.elements),
        ManagementBody::AssociationResponse(body) | ManagementBody::ReassociationResponse(body) => {
            visit_elements(&body.elements);
        }
        ManagementBody::ReassociationRequest(body) => visit_elements(&body.elements),
        ManagementBody::ProbeRequest(body) => visit_elements(body.elements()),
        ManagementBody::ProbeResponse(body) | ManagementBody::Beacon(body) => {
            visit_elements(body.elements());
        }
        ManagementBody::Authentication(body) => visit_elements(&body.elements),
        ManagementBody::Disassociation(body) | ManagementBody::Deauthentication(body) => {
            let _ = (body.reason, body.trailing);
        }
        ManagementBody::Action(body) => {
            let _ = (body.category, body.action, body.payload);
        }
        ManagementBody::Other(body) => {
            let _ = body;
        }
    }
}

fn visit_elements(elements: &[InformationElement<'_>]) {
    for element in elements.iter().take(wifi_codecs::MAX_INFORMATION_ELEMENTS) {
        let _ = (element.id(), element.bytes(), element.kind());
        if matches!(element.kind(), ElementKind::Rsn | ElementKind::Wpa) {
            let _ = wifi_codecs::parse_security(element);
        }
    }
}

fn seeded_beacon(input: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(320);

    // Build a valid three-address beacon header around fuzzed body material
    frame.extend_from_slice(&(8_u16 << 4).to_le_bytes());
    frame.extend_from_slice(&[0_u8; 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 3]);
    frame.extend_from_slice(&[0_u8; 2]);

    // Beacon fixed fields are timestamp, interval, and capability
    frame.extend_from_slice(&[0_u8; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0010_u16.to_le_bytes());

    // Include representative information-element classes before fuzzed RSN data
    frame.extend_from_slice(&[0, 0, 3, 1, 6, 255, 1, 35]);
    frame.extend_from_slice(&[221, 4, 0x00, 0x50, 0xf2, 1]);

    let value_length = input.len().min(MAX_ELEMENT_VALUE_BYTES);
    let Ok(value_length) = u8::try_from(value_length) else {
        return frame;
    };
    frame.extend_from_slice(&[48, value_length]);
    if let Some(value) = input.get(..usize::from(value_length)) {
        frame.extend_from_slice(value);
    }

    // A valid RSN element exercises the successful suite and PMF path
    frame.extend_from_slice(&[
        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 128, 0,
    ]);
    frame
}
