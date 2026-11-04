#![no_main]

#[path = "pcap/reader.rs"]
mod reader;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    reader::exercise(data, |_, packet| {
        if let Some(packet) = packet {
            assert!(!packet.fragmented || packet.transport.is_none());
        }
    });
});
