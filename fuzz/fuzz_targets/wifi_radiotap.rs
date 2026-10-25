#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_CAPTURE_BYTES: usize = 4_096;

// The declared radiotap length bounds metadata parsing and payload retention
fuzz_target!(|data: &[u8]| {
    let length = data.len().min(MAX_CAPTURE_BYTES);
    let Some(input) = data.get(..length) else {
        return;
    };
    let Ok(frame) = wifi_radiotap::decode(input) else {
        return;
    };

    // Exercise the metadata accessors and the canonical supported-field encoder
    let fields = frame.fields();
    let _ = (
        frame.header_bytes(),
        frame.wifi_bytes(),
        frame.metadata_complete(),
        frame.first_unsupported_field(),
        fields.tsft(),
        fields.flags(),
        fields.rate_500kbps(),
        fields.channel(),
        fields.signal_dbm(),
        fields.noise_dbm(),
        fields.antenna(),
        fields.rx_flags(),
        fields.tx_flags(),
        fields.zero_length_psdu(),
    );
    let Ok(encoded_length) = fields.encoded_len() else {
        return;
    };
    let mut encoded = vec![0_u8; encoded_length];
    let Ok(written) = wifi_radiotap::encode(fields, &mut encoded) else {
        return;
    };
    if let Some(header) = encoded.get(..written) {
        let _ = wifi_radiotap::decode(header);
    }
});
