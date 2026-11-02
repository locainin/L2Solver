#![no_main]

#[path = "checkpoint_readers/mod.rs"]
mod checkpoint_readers;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| checkpoint_readers::exercise(input));
