use std::error::Error;

use l2_lab::RunOptions;
use l2_lab::discovery::{Expectation, Identity, Protocol};
use l2_segmentation::EvaluationStatus;

use super::support::{CDP_GOLDEN, budget, lab, lldp, probe};

fn decode_hex(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[test]
fn every_truncated_lldp_and_cdp_frame_is_rejected() -> Result<(), Box<dyn Error>> {
    let lldp_bytes = lldp(120)?;
    for (protocol, wire) in [
        (Protocol::Lldp, lldp_bytes.as_slice()),
        (Protocol::Cdp, CDP_GOLDEN),
    ] {
        for length in 1..wire.len() {
            let truncated = wire.get(..length).ok_or("missing prefix")?;
            let probes = [probe(1, 1, protocol, truncated, Expectation::Rejected)?];
            let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
            assert_eq!(
                run.status(),
                EvaluationStatus::Pass,
                "protocol {protocol:?}, length {length}"
            );
        }
    }
    Ok(())
}

#[test]
fn cdp_rejects_checksum_valid_malformed_duplicate_missing_and_empty_tlvs()
-> Result<(), Box<dyn Error>> {
    // These intentionally malformed fixtures still carry Scapy-calculated checksums
    let fixtures = [
        "01000ccccccc0200000000010023aaaa0300000c20000278e6c7000100037377697463682d610003000b4769312f302f31",
        "01000ccccccc020000000001002faaaa0300000c2000027878fc0001000c7377697463682d610001000c7377697463682d610003000b4769312f302f31",
        "01000ccccccc0200000000010018aaaa0300000c200002788fc50001000c7377697463682d61",
        "01000ccccccc020000000001001baaaa0300000c20000278547c000100040003000b4769312f302f31",
    ];
    for fixture in fixtures {
        let bytes = decode_hex(fixture)?;
        let probes = [probe(1, 1, Protocol::Cdp, &bytes, Expectation::Rejected)?];
        let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
        assert_eq!(run.status(), EvaluationStatus::Pass, "fixture {fixture}");
    }
    Ok(())
}

#[test]
fn cdp_checksum_corruption_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut bytes = CDP_GOLDEN.to_vec();
    *bytes.last_mut().ok_or("missing final byte")? ^= 1;
    let probes = [probe(1, 1, Protocol::Cdp, &bytes, Expectation::Rejected)?];
    assert_eq!(
        lab(&probes)?
            .run(budget()?, RunOptions::default())?
            .status(),
        EvaluationStatus::Pass
    );
    Ok(())
}

#[test]
fn cdp_v1_expiry_and_zero_hold_shutdown_use_the_recorded_virtual_clock()
-> Result<(), Box<dyn Error>> {
    let ttl_one = decode_hex(
        "01000ccccccc0200000000010023aaaa0300000c20000101e8350001000c7377697463682d610003000b4769312f302f31",
    )?;
    let zero = decode_hex(
        "01000ccccccc0200000000010023aaaa0300000c20000200e7360001000c7377697463682d610003000b4769312f302f31",
    )?;
    let identity = super::support::cdp_identity();
    let probes = [
        probe(
            1,
            1,
            Protocol::Cdp,
            &ttl_one,
            Expectation::Accepted(identity),
        )?,
        probe(
            2,
            1001,
            Protocol::Cdp,
            CDP_GOLDEN,
            Expectation::Accepted(identity),
        )?,
        probe(
            3,
            1002,
            Protocol::Cdp,
            &zero,
            Expectation::Withdrawn(identity),
        )?,
    ];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    assert_eq!(run.status(), EvaluationStatus::Pass);
    assert_eq!(
        run.observations().get(1).and_then(|item| item.before()),
        None
    );
    assert_eq!(
        run.observations().get(2).and_then(|item| item.after()),
        None
    );
    Ok(())
}

#[test]
fn cdp_shutdown_for_another_identity_preserves_the_existing_neighbor() -> Result<(), Box<dyn Error>>
{
    let zero = decode_hex(
        "01000ccccccc0200000000010023aaaa0300000c20000200e7350001000c7377697463682d620003000b4769312f302f31",
    )?;
    let identity = super::support::cdp_identity();
    let other = Identity::new(b"switch-b", super::support::CDP_PORT);
    let probes = [
        probe(
            1,
            1,
            Protocol::Cdp,
            CDP_GOLDEN,
            Expectation::Accepted(identity),
        )?,
        probe(2, 2, Protocol::Cdp, &zero, Expectation::Withdrawn(other))?,
    ];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    assert_eq!(
        run.status(),
        EvaluationStatus::Fail,
        "an unrelated shutdown did not withdraw its target"
    );
    let observation = run.observations().get(1).ok_or("missing shutdown")?;
    assert_eq!(observation.before(), Some(identity));
    assert_eq!(observation.after(), Some(identity));
    Ok(())
}

#[test]
fn lldp_rejects_structurally_decodable_invalid_identity_subtype() -> Result<(), Box<dyn Error>> {
    let mut wire = lldp(120)?;
    let subtype = wire.get_mut(16).ok_or("missing subtype")?;
    *subtype = 0;
    let payload = wire.get(14..).ok_or("missing payload")?;
    assert_eq!(
        l2_codecs::decode_lldp(payload)?.validity,
        l2_codecs::Validity::Invalid
    );
    let probes = [probe(1, 1, Protocol::Lldp, &wire, Expectation::Rejected)?];
    assert_eq!(
        lab(&probes)?
            .run(budget()?, RunOptions::default())?
            .status(),
        EvaluationStatus::Pass
    );
    Ok(())
}

#[test]
fn cdp_rejects_bad_link_framing_and_unsupported_version() -> Result<(), Box<dyn Error>> {
    let mut destination = CDP_GOLDEN.to_vec();
    *destination.first_mut().ok_or("missing destination")? = 2;
    let unknown_version =
        decode_hex("01000ccccccc0200000000010017aaaa0300000c2000037898920001000664650003000581")?;
    for wire in [&destination, &unknown_version] {
        let probes = [probe(1, 1, Protocol::Cdp, wire, Expectation::Rejected)?];
        assert_eq!(
            lab(&probes)?
                .run(budget()?, RunOptions::default())?
                .status(),
            EvaluationStatus::Pass
        );
    }
    Ok(())
}

// Build optional empty TLVs and recompute the CDP checksum for a boundary fixture
fn cdp_with_extra_tlvs(count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = CDP_GOLDEN.to_vec();
    for _ in 0..count {
        frame.extend_from_slice(&[0x01, 0x00, 0, 4]);
    }
    let length = u16::try_from(frame.len() - 14)?;
    frame
        .get_mut(12..14)
        .ok_or("missing length")?
        .copy_from_slice(&length.to_be_bytes());
    frame
        .get_mut(24..26)
        .ok_or("missing checksum")?
        .copy_from_slice(&[0, 0]);
    let packet = frame.get(22..).ok_or("missing CDP packet")?;
    let mut sum = 0_u32;
    for chunk in packet.chunks(2) {
        match chunk {
            [high, low] => sum += u32::from(u16::from_be_bytes([*high, *low])),
            [last] if *last >= 0x80 => sum += 0xff00 + u32::from(*last - 1),
            [last] => sum += u32::from(*last),
            _ => return Err("invalid chunk".into()),
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = u16::try_from(sum)? ^ 0xffff;
    frame
        .get_mut(24..26)
        .ok_or("missing checksum")?
        .copy_from_slice(&checksum.to_be_bytes());
    Ok(frame)
}

#[test]
fn cdp_accepts_128_tlvs_and_rejects_129_with_valid_checksum() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        cdp_with_extra_tlvs(0)?,
        CDP_GOLDEN,
        "the fixture checksum agrees with Scapy"
    );
    let exact = cdp_with_extra_tlvs(126)?;
    let excessive = cdp_with_extra_tlvs(127)?;
    for (wire, expectation) in [
        (
            exact.as_slice(),
            Expectation::Accepted(super::support::cdp_identity()),
        ),
        (excessive.as_slice(), Expectation::Rejected),
    ] {
        let probes = [probe(1, 1, Protocol::Cdp, wire, expectation)?];
        assert_eq!(
            lab(&probes)?
                .run(budget()?, RunOptions::default())?
                .status(),
            EvaluationStatus::Pass
        );
    }
    Ok(())
}

#[test]
fn cdp_checksum_signed_octet_boundary_matches_wireshark() -> Result<(), Box<dyn Error>> {
    // Wireshark accepts 0x9993 for final octet 0x80 and flags Scapy's 0x9893
    let fixtures = [
        (
            "01000ccccccc0200000000010017aaaa0300000c200002789894000100066465000300057f",
            true,
            0x7f,
        ),
        (
            "01000ccccccc0200000000010017aaaa0300000c2000027899930001000664650003000580",
            true,
            0x80,
        ),
        (
            "01000ccccccc0200000000010017aaaa0300000c2000027898930001000664650003000580",
            false,
            0x80,
        ),
        (
            "01000ccccccc0200000000010017aaaa0300000c2000027899920001000664650003000581",
            true,
            0x81,
        ),
        (
            "01000ccccccc0200000000010017aaaa0300000c20000278991400010006646500030005ff",
            true,
            0xff,
        ),
    ];
    for (hex, valid, last) in fixtures {
        let wire = decode_hex(hex)?;
        let port = [last];
        let expectation = if valid {
            Expectation::Accepted(Identity::new(b"de", &port))
        } else {
            Expectation::Rejected
        };
        let probes = [probe(1, 1, Protocol::Cdp, &wire, expectation)?];
        assert_eq!(
            lab(&probes)?
                .run(budget()?, RunOptions::default())?
                .status(),
            EvaluationStatus::Pass,
            "last octet {last:#x} valid {valid}"
        );
    }
    Ok(())
}

#[test]
fn receiver_rejects_tagged_frames_and_non_unicast_sources() -> Result<(), Box<dyn Error>> {
    let lldp_bytes = lldp(120)?;
    for (protocol, wire, identity) in [
        (
            Protocol::Lldp,
            lldp_bytes.as_slice(),
            super::support::lldp_identity(),
        ),
        (Protocol::Cdp, CDP_GOLDEN, super::support::cdp_identity()),
    ] {
        let mut tagged = wire.get(..12).ok_or("missing Ethernet addresses")?.to_vec();
        tagged.extend_from_slice(&[0x81, 0, 0, 1]);
        tagged.extend_from_slice(wire.get(12..).ok_or("missing Ethernet payload")?);

        let mut zero_source = wire.to_vec();
        zero_source
            .get_mut(6..12)
            .ok_or("missing source address")?
            .fill(0);
        let mut multicast_source = wire.to_vec();
        *multicast_source
            .get_mut(6)
            .ok_or("missing source address")? |= 1;

        for invalid in [&tagged, &zero_source, &multicast_source] {
            let probes = [
                probe(1, 1, protocol, wire, Expectation::Accepted(identity))?,
                probe(2, 2, protocol, invalid, Expectation::Rejected)?,
            ];
            let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
            assert_eq!(
                run.status(),
                EvaluationStatus::Pass,
                "invalid {protocol:?} framing"
            );
            let observed = run
                .observations()
                .get(1)
                .ok_or("missing rejection evidence")?;
            assert_eq!(observed.observed(), l2_lab::discovery::Observed::Rejected);
            assert_eq!(observed.before(), Some(identity));
            assert_eq!(observed.after(), Some(identity));
        }
    }
    Ok(())
}
