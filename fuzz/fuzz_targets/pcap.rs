#![no_main]
use libfuzzer_sys::fuzz_target;

// Each successful read consumes a record, so finite input bounds this loop
fuzz_target!(|data: &[u8]| {
    if let Ok(mut capture) = l2_pcap::CaptureSource::new(data) {
        while let Ok(Some(_)) = capture.next_packet() {}
    }
});
