#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "workbench/extensions/native_endpoints.rs"]
mod native_endpoints;

fuzz_target!(|data: &[u8]| {
    // EVTX needs a complete 64 KiB chunk, which exceeds the general workbench harness limit
    let input = data.get(..data.len().min(1024 * 1024)).unwrap_or_default();
    native_endpoints::exercise(input);
});
