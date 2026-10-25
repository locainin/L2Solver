#![no_main]
use libfuzzer_sys::fuzz_target;

// Successful encodings must preserve every byte, including unknown fields and padding
fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = l2_core::decode(data)
        && let Ok(length) = l2_core::encoded_len(&frame)
    {
        let mut bytes = vec![0; length];
        let result = l2_core::encode(&frame, &mut bytes);
        assert!(result.is_ok());
        if let Ok(written) = result {
            assert_eq!(written, length);
            assert_eq!(bytes, data);
        }
    }
    if let Ok(frame) = l2_codecs::decode_lldp(data)
        && let Ok(length) = l2_codecs::lldp_encoded_len(&frame)
    {
        let mut bytes = vec![0; length];
        let result = l2_codecs::encode_lldp(&frame, &mut bytes);
        assert!(result.is_ok());
        if let Ok(written) = result {
            assert_eq!(written, length);
            assert_eq!(bytes, data);
        }
    }
});
