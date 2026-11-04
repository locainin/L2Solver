use std::{error::Error, net::Ipv4Addr, sync::atomic::AtomicBool};

use l2_active::switching::vtp::{VtpEvidence, VtpMessageKind, VtpMonitor, VtpObservation};

use crate::{fixture, support::Link};

#[test]
fn scapy_vtp_summary_subset_and_request_are_structured_claims() -> Result<(), Box<dyn Error>> {
    let frames = [fixture::SUMMARY, fixture::SUBSET, fixture::REQUEST];
    let events = frames
        .into_iter()
        .map(fixture::event)
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 3);
    let get_message = |index: usize| -> Result<_, Box<dyn Error>> {
        let observation = report
            .observations()
            .get(index)
            .ok_or("missing VTP frame")?;
        let VtpEvidence::Message(message) = observation.evidence() else {
            return Err("VTP message not decoded".into());
        };
        assert_eq!(message.source_mac(), [2, 0, 0, 0, 0, 2]);
        assert_eq!(message.domain(), b"PRIVATE-DOMAIN");
        Ok(message)
    };
    let summary = get_message(0)?;
    assert_eq!(summary.version(), 2);
    assert!(
        matches!(summary.kind(), VtpMessageKind::Summary {revision: 0x0102_0304, followers: 1, updater} if *updater == Ipv4Addr::new(192, 0, 2, 7))
    );
    let subset = get_message(1)?;
    let VtpMessageKind::Subset {
        revision,
        sequence,
        vlans,
    } = subset.kind()
    else {
        return Err("missing VLAN claims".into());
    };
    assert_eq!((*revision, *sequence), (0x0102_0304, 1));
    let vlan = vlans.first().ok_or("missing VLAN")?;
    assert_eq!(
        (
            vlan.id(),
            vlan.status(),
            vlan.vlan_type(),
            vlan.mtu(),
            vlan.said()
        ),
        (37, 1, 1, 1500, 0x0001_86c5)
    );
    assert_eq!(vlan.name(), b"SECRET-VLAN");
    let second_vlan = vlans.get(1).ok_or("missing second VLAN")?;
    assert_eq!(
        (second_vlan.id(), second_vlan.status(), second_vlan.mtu()),
        (84, 0, 1400)
    );
    assert_eq!(second_vlan.name(), b"VOICE");
    assert!(matches!(
        get_message(2)?.kind(),
        VtpMessageKind::Request { start_value: 37 }
    ));
    assert!(!report.summary().send_attempted());
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing raw summary")?
            .frame()
            .bytes(),
        fixture::SUMMARY
    );
    Ok(())
}

#[test]
fn vtp_default_debug_redacts_domain_names_digest_and_padding() -> Result<(), Box<dyn Error>> {
    let events = [fixture::SUMMARY, fixture::SUBSET]
        .into_iter()
        .map(fixture::event)
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let debug = format!("{report:?}");
    for sensitive in [
        "PRIVATE-DOMAIN",
        "SECRET-VLAN",
        "DIGEST-SECRET",
        "PADDING-SECRET",
        "80, 82, 73, 86, 65, 84, 69",
    ] {
        assert!(
            !debug.contains(sensitive),
            "debug output disclosed {sensitive}"
        );
    }
    Ok(())
}

#[test]
fn vtp_invalid_lengths_and_unsupported_formats_are_distinguished() -> Result<(), Box<dyn Error>> {
    let events = vec![
        // Domain length exceeds the fixed 32-byte field
        fixture::event(&fixture::change(fixture::SUMMARY, 25, 33)?)?,
        // VLAN record length is shorter than its fixed fields
        fixture::event(&fixture::change(fixture::SUBSET, 62, 11)?)?,
        // VTP 3 has a different layout from version 2
        fixture::event(&fixture::change(fixture::SUMMARY, 22, 3)?)?,
        // Unknown message code is explicitly unsupported
        fixture::event(&fixture::change(fixture::SUMMARY, 23, 0x7f)?)?,
    ];
    let mut link = Link::new(events, Some(0))?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    for index in [0, 1] {
        assert!(matches!(
            report
                .observations()
                .get(index)
                .map(VtpObservation::evidence),
            Some(VtpEvidence::Malformed(_))
        ));
    }
    assert!(matches!(
        report.observations().get(2).map(VtpObservation::evidence),
        Some(VtpEvidence::UnsupportedVersion(3))
    ));
    assert!(matches!(
        report.observations().get(3).map(VtpObservation::evidence),
        Some(VtpEvidence::UnsupportedMessage(0x7f))
    ));
    Ok(())
}

#[test]
fn vtp_limits_vlan_records_and_checks_nested_lengths() -> Result<(), Box<dyn Error>> {
    let mut excessive = vec![2, 2, 1, 0];
    excessive.extend_from_slice(&[0; 32]);
    excessive.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..65 {
        excessive.extend_from_slice(&[12, 0, 1, 0, 0, 37, 5, 220, 0, 0, 0, 1]);
    }
    let mut invalid_tlv = vec![2, 2, 1, 0];
    invalid_tlv.extend_from_slice(&[0; 32]);
    invalid_tlv.extend_from_slice(&1_u32.to_be_bytes());
    invalid_tlv.extend_from_slice(&[14, 0, 1, 0, 0, 37, 5, 220, 0, 0, 0, 1, 6, 1]);
    let mut link = Link::new(
        vec![
            fixture::event(&fixture::frame(0x2003, &excessive)?)?,
            fixture::event(&fixture::frame(0x2003, &invalid_tlv)?)?,
        ],
        Some(0),
    )?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(VtpObservation::evidence),
        Some(VtpEvidence::LimitExceeded)
    ));
    assert!(matches!(
        report.observations().get(1).map(VtpObservation::evidence),
        Some(VtpEvidence::Malformed(_))
    ));
    Ok(())
}

#[test]
fn vtp_summary_extensions_are_not_misrepresented_as_authenticated() -> Result<(), Box<dyn Error>> {
    // Cisco devices may append summary extensions after the 72-byte fixed fields
    let mut payload = fixture::SUMMARY
        .get(22..94)
        .ok_or("missing summary payload")?
        .to_vec();
    payload.extend_from_slice(&[0, 0, 0, 1, 6, 1, 0, 2]);
    let wire = fixture::frame(0x2003, &payload)?;
    let mut link = Link::new(vec![fixture::event(&wire)?], Some(0))?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(VtpObservation::evidence),
        Some(VtpEvidence::Message(_))
    ));
    Ok(())
}

#[test]
fn vtp_nested_tlv_budget_accepts_the_boundary_and_rejects_the_next_record()
-> Result<(), Box<dyn Error>> {
    fn subset(second_count: u8) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut payload = vec![2, 2, 1, 0];
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&1_u32.to_be_bytes());
        for count in [64_u8, second_count] {
            payload.extend_from_slice(&[12 + count * 2, 0, 1, 0, 0, 37, 5, 220, 0, 0, 0, 1]);
            for _ in 0..count {
                payload.extend_from_slice(&[0xee, 0]);
            }
        }
        fixture::frame(0x2003, &payload)
    }
    let mut link = Link::new(
        vec![fixture::event(&subset(64)?)?, fixture::event(&subset(65)?)?],
        Some(0),
    )?;
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(VtpObservation::evidence),
        Some(VtpEvidence::Message(_))
    ));
    assert!(matches!(
        report.observations().get(1).map(VtpObservation::evidence),
        Some(VtpEvidence::LimitExceeded)
    ));
    Ok(())
}
