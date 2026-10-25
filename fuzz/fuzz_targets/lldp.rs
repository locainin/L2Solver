#![no_main]
use libfuzzer_sys::fuzz_target;

// Unknown and malformed TLVs share the production parsing path
fuzz_target!(|data: &[u8]| {
    let _ = l2_codecs::decode_lldp(data);
});
