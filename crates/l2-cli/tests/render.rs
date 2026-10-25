#[path = "../src/render.rs"]
mod render;

#[test]
fn renders_bytes_as_bounded_ascii() -> Result<(), std::io::Error> {
    let input: Vec<u8> = (0..=255).collect();
    let mut output = Vec::new();
    render::bytes(&mut output, &input)?;
    assert!(output.iter().all(|byte| (32..=126).contains(byte)));
    assert!(output.len() <= input.len() * 4);
    Ok(())
}

#[test]
fn mac_zero_padded_lowercase_octets() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    render::mac(&mut output, [0, 1, 2, 128, 254, 255])?;
    assert_eq!(String::from_utf8(output)?, "00:01:02:80:fe:ff");
    Ok(())
}

#[test]
fn rendering_propagates_output_capacity_errors() {
    let mut empty = [].as_mut_slice();
    assert!(render::bytes(&mut empty, b"x").is_err());
    assert!(render::mac(&mut empty, [0; 6]).is_err());
}

#[path = "../src/stp_render.rs"]
mod stp_render;
use l2_codecs::BridgeId;
use l2_engine::StpUpdate;

#[test]
fn root_changes_readable_mac_addresses() -> std::io::Result<()> {
    let mut output = Vec::new();
    stp_render::update(
        &mut output,
        StpUpdate::RootChanged {
            previous: None,
            current: Some(BridgeId::from_wire(0x8001, [0, 1, 2, 3, 4, 5])),
        },
    )?;
    assert_eq!(
        output,
        b"root none -> 00:01:02:03:04:05 (priority=32768 extension=1)"
    );
    Ok(())
}
