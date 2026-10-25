#![no_main]

use libfuzzer_sys::fuzz_target;

// Successful decodes must return the exact authenticated control message bytes
fuzz_target!(|data: &[u8]| {
    if let Ok(message) = l2_helper_protocol::decode(data) {
        let mut encoded = [0_u8; l2_helper_protocol::MAX_MESSAGE_LENGTH];
        if let Ok(written) = l2_helper_protocol::encode(&message, &mut encoded) {
            assert_eq!(encoded.get(..written), Some(data));
        }
    }
});
