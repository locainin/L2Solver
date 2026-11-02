use wifi_radiotap::{
    Channel, DecodeError, EncodeError, RadiotapFields, RadiotapFlags, decode, encode,
};

#[test]
fn known_fields_preserve_metadata_payload() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8, 0, 24, 0, 0x2f, 0x08, 0, 0];
    bytes.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    bytes.extend_from_slice(&[0x50, 12]);
    bytes.extend_from_slice(&2_437_u16.to_le_bytes());
    bytes.extend_from_slice(&0x00a0_u16.to_le_bytes());
    bytes.extend_from_slice(&(-42_i8).to_ne_bytes());
    bytes.push(3);
    bytes.extend_from_slice(&[0x80, 0x00]);

    let frame = decode(&bytes)?;

    assert_eq!(frame.fields().tsft(), Some(0x0102_0304_0506_0708));
    assert_eq!(frame.fields().flags(), Some(RadiotapFlags::new(0x50)));
    assert_eq!(frame.fields().rate_500kbps(), Some(12));
    assert_eq!(frame.fields().channel(), Some(Channel::new(2_437, 0x00a0)));
    assert_eq!(frame.fields().signal_dbm(), Some(-42));
    assert_eq!(frame.fields().noise_dbm(), None);
    assert_eq!(frame.fields().antenna(), Some(3));
    assert!(frame.metadata_complete());
    assert_eq!(frame.wifi_bytes(), &[0x80, 0x00]);
    Ok(())
}

#[test]
fn unknown_field_keeps_payload_location() -> Result<(), DecodeError> {
    let bytes = [0, 0, 12, 0, 0, 0, 1, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0x08, 0x00];

    let frame = decode(&bytes)?;

    assert!(!frame.metadata_complete());
    assert_eq!(frame.first_unsupported_field(), Some(16));
    assert_eq!(frame.wifi_bytes(), &[0x08, 0x00]);
    Ok(())
}

#[test]
fn extended_presence_chain_hard_limit() {
    let mut bytes = vec![0_u8, 0, 40, 0];
    for _ in 0..9 {
        bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());
    }

    assert_eq!(
        decode(&bytes),
        Err(DecodeError::PresenceWordLimit { maximum: 8 })
    );
}

#[test]
fn malformed_envelope_lengths_are_distinct() {
    assert_eq!(
        decode(&[0, 0, 8]),
        Err(DecodeError::Truncated {
            context: "header prefix",
            needed: 4,
            available: 3,
        })
    );
    assert!(matches!(
        decode(&[0, 0, 7, 0, 0, 0, 0]),
        Err(DecodeError::InvalidHeaderLength { .. })
    ));
    assert!(matches!(
        decode(&[0, 0, 12, 0, 0, 0, 0, 0]),
        Err(DecodeError::Truncated { .. })
    ));
    assert_eq!(
        decode(&[1, 0, 8, 0, 0, 0, 0, 0]),
        Err(DecodeError::UnsupportedVersion(1))
    );
}

#[test]
fn known_field_encoder_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let fields = RadiotapFields::new()
        .with_tsft(0x0102_0304_0506_0708)
        .with_flags(RadiotapFlags::new(0x10))
        .with_rate_500kbps(108)
        .with_channel(Channel::new(5_180, 0x0140))
        .with_signal_dbm(-51)
        .with_noise_dbm(-83)
        .with_antenna(1);
    let mut bytes = vec![0_u8; fields.encoded_len()? + 2];
    let header_length = encode(&fields, &mut bytes)?;
    bytes
        .get_mut(header_length..)
        .ok_or(EncodeError::OutputTooSmall {
            needed: header_length + 2,
            available: header_length,
        })?
        .copy_from_slice(&[0x80, 0x00]);

    let decoded = decode(&bytes)?;

    assert_eq!(decoded.fields(), &fields);
    assert_eq!(decoded.fields().tsft(), Some(0x0102_0304_0506_0708));
    assert_eq!(decoded.fields().noise_dbm(), Some(-83));
    assert_eq!(decoded.wifi_bytes(), &[0x80, 0x00]);
    assert!(decoded.fields().flags().is_some_and(RadiotapFlags::has_fcs));
    Ok(())
}

#[test]
fn extra_fields() -> Result<(), Box<dyn std::error::Error>> {
    let fields = RadiotapFields::new()
        .with_flags(RadiotapFlags::new(0))
        .with_channel(Channel::new(2_412, 0x00a0))
        .with_rx_flags(0x1234)
        .with_tx_flags(0x5678);
    let mut bytes = vec![0; fields.encoded_len()?];
    assert_eq!(encode(&fields, &mut bytes)?, bytes.len());

    let frame = decode(&bytes)?;
    assert_eq!(frame.fields(), &fields);
    assert_eq!(frame.fields().rx_flags(), Some(0x1234));
    assert_eq!(frame.fields().tx_flags(), Some(0x5678));
    Ok(())
}

#[test]
fn empty_radiotap_fields() -> Result<(), Box<dyn std::error::Error>> {
    let fields = RadiotapFields::new();
    assert_eq!(fields.encoded_len()?, 8);
    let mut bytes = vec![0; 8];
    assert_eq!(encode(&fields, &mut bytes)?, 8);
    assert_eq!(decode(&bytes)?.fields(), &fields);
    Ok(())
}

#[test]
fn radiotap_alignment() -> Result<(), Box<dyn std::error::Error>> {
    let fields = RadiotapFields::new()
        .with_flags(RadiotapFlags::new(0x10))
        .with_channel(Channel::new(2_437, 0x0140));
    let mut bytes = vec![0; fields.encoded_len()?];
    assert_eq!(encode(&fields, &mut bytes)?, bytes.len());
    assert_eq!(decode(&bytes)?.fields(), &fields);
    Ok(())
}

#[test]
fn radiotap_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let exact = [0, 0, 9, 0, 0x02, 0, 0, 0, 0x55];
    let frame = decode(&exact)?;
    assert_eq!(frame.fields().flags(), Some(RadiotapFlags::new(0x55)));

    let short = [0, 0, 8, 0, 0x02, 0, 0, 0, 0x55];
    assert_eq!(
        decode(&short),
        Err(DecodeError::Truncated {
            context: "field",
            needed: 9,
            available: 8,
        })
    );
    Ok(())
}

#[test]
fn radiotap_layouts() -> Result<(), Box<dyn std::error::Error>> {
    let presence = (1_u32 << 19)
        | (1_u32 << 20)
        | (1_u32 << 21)
        | (1_u32 << 22)
        | (1_u32 << 23)
        | (1_u32 << 24)
        | (1_u32 << 26)
        | (1_u32 << 27);
    let declared = 74_u16;
    let mut bytes = vec![0, 0];
    bytes.extend_from_slice(&declared.to_le_bytes());
    bytes.extend_from_slice(&presence.to_le_bytes());
    bytes.resize(usize::from(declared), 0);
    bytes.extend_from_slice(&[0x08, 0x00]);

    let frame = decode(&bytes)?;
    assert!(frame.metadata_complete());
    assert_eq!(frame.first_unsupported_field(), None);
    assert_eq!(frame.wifi_bytes(), &[0x08, 0x00]);
    Ok(())
}

#[test]
fn radiotap_flags() {
    for (raw, has_fcs, bad_fcs) in [(0, false, false), (0x10, true, false), (0x40, false, true)] {
        let flags = RadiotapFlags::new(raw);
        assert_eq!(flags.raw(), raw);
        assert_eq!(flags.has_fcs(), has_fcs);
        assert_eq!(flags.bad_fcs(), bad_fcs);
    }
}

#[test]
fn radiotap_errors() {
    assert_eq!(
        DecodeError::UnsupportedVersion(1).to_string(),
        "unsupported radiotap version 1"
    );
    assert_eq!(
        EncodeError::OutputTooSmall {
            needed: 12,
            available: 8,
        }
        .to_string(),
        "radiotap output needs 12 bytes, only 8 available"
    );
}

#[test]
fn encoder_short_output_without_writing() {
    let fields = RadiotapFields::new().with_channel(Channel::new(2_412, 0x00a0));
    let mut output = [0xa5; 8];
    let before = output;

    assert!(matches!(
        encode(&fields, &mut output),
        Err(EncodeError::OutputTooSmall { .. })
    ));
    assert_eq!(output, before);
}

#[test]
fn zero_length_retained_radio_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let fields = RadiotapFields::new().with_zero_length_psdu(1);
    let mut bytes = vec![0; fields.encoded_len()?];

    assert_eq!(encode(&fields, &mut bytes)?, bytes.len());
    let decoded = decode(&bytes)?;
    assert_eq!(decoded.fields().zero_length_psdu(), Some(1));
    assert_eq!(decoded.wifi_bytes(), []);
    Ok(())
}
