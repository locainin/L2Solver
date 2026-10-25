#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;

const MAX_ARGUMENTS: usize = 16;
const MAX_ARGUMENT_BYTES: usize = 128;

fuzz_target!(|data: &[u8]| {
    let Some((&count, mut remaining)) = data.split_first() else {
        return;
    };
    let mut arguments = Vec::with_capacity(usize::from(count) % (MAX_ARGUMENTS + 1));
    for _ in 0..arguments.capacity() {
        let Some((&declared_length, rest)) = remaining.split_first() else {
            break;
        };
        let length = (usize::from(declared_length) % (MAX_ARGUMENT_BYTES + 1)).min(rest.len());
        let Some((argument, rest)) = rest.split_at_checked(length) else {
            break;
        };
        arguments.push(os_string(argument));
        remaining = rest;
    }

    // Parsing must reject hostile argument vectors without panicking
    let _ = l2_cli::arguments::parse(&arguments);
});

#[cfg(unix)]
fn os_string(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;

    OsString::from_vec(bytes.to_vec())
}

#[cfg(not(unix))]
fn os_string(bytes: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(bytes).into_owned())
}
