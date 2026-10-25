#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_FRAME_BYTES: usize = 4_096;

// Keep one raw frame small enough that malformed headers cannot amplify work
fuzz_target!(|data: &[u8]| {
    let length = data.len().min(MAX_FRAME_BYTES);
    let Some(input) = data.get(..length) else {
        return;
    };
    let Ok(frame) = wifi_core::decode(input) else {
        return;
    };

    // Visit every borrowed field after the structural decode succeeds
    let _ = (
        frame.bytes(),
        frame.body(),
        frame.control().raw(),
        frame.control().kind(),
        frame.control().frame_type(),
        frame.control().to_ds(),
        frame.control().from_ds(),
        frame.control().retry(),
        frame.control().protected(),
        frame.control().order(),
        frame.receiver(),
        frame.transmitter(),
        frame.address3(),
        frame.address4(),
        frame.sequence_control(),
        frame.qos_control(),
        frame.ht_control(),
    );
});
