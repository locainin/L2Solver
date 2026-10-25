#![no_main]
use libfuzzer_sys::fuzz_target;

// Both bare BPDUs and LLC framing pass through the same production decoder
fuzz_target!(|data: &[u8]| {
    let _ = l2_codecs::decode_stp(data);
});
