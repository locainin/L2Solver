#![no_main]
use libfuzzer_sys::fuzz_target;

// All length and nesting decisions stay inside the decoder
fuzz_target!(|data: &[u8]| {
    let _ = l2_core::decode(data);
});
