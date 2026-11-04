use super::support::*;
use l2_capture::{CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, VlanAuxData};

#[test]
fn claim_change_traffic_references() -> TestResult {
    let report = assess([
        captured(arp(FIRST_MAC, FIRST_MAC, ADDRESS), 0)?,
        captured(arp(SECOND_MAC, SECOND_MAC, ADDRESS), 0)?,
        captured(traffic(SECOND_MAC, ADDRESS), 0)?,
    ])?;
    let change = report
        .forensics
        .arp_changes
        .first()
        .ok_or("missing ARP change")?;
    assert_eq!(change.previous_mac, "02:00:00:00:00:01");
    assert_eq!(change.claimed_mac, "02:00:00:00:00:02");
    assert_eq!(
        (
            change.previous_packet,
            change.packet,
            change.followup_packet
        ),
        (1, 2, Some(3))
    );
    assert_evidence(&report, &[1, 2, 3]);
    assert!(report.findings.is_empty());
    Ok(())
}

#[test]
fn repetitions_reversions_keep_capture_order() -> TestResult {
    let mut packets = Vec::new();
    for mac in [FIRST_MAC, FIRST_MAC, SECOND_MAC, FIRST_MAC] {
        packets.push(captured(arp(mac, mac, ADDRESS), 0)?);
    }
    packets.push(captured(traffic(SECOND_MAC, ADDRESS), 0)?);
    packets.push(captured(traffic(FIRST_MAC, ADDRESS), 0)?);
    let report = assess(packets)?;
    assert_eq!(report.forensics.arp_changes.len(), 2);
    let first = report.forensics.arp_changes.first().ok_or("first change")?;
    let second = report.forensics.arp_changes.get(1).ok_or("second change")?;
    assert_eq!(
        (first.previous_packet, first.packet, first.followup_packet),
        (1, 3, None)
    );
    assert_eq!(
        (
            second.previous_packet,
            second.packet,
            second.followup_packet
        ),
        (3, 4, Some(6))
    );
    assert_evidence(&report, &[1, 3, 4, 6]);
    Ok(())
}

#[test]
fn probes_invalid_never_changes() -> TestResult {
    let report = assess([
        captured(arp(FIRST_MAC, FIRST_MAC, [0; 4]), 0)?,
        captured(arp(SECOND_MAC, SECOND_MAC, [0; 4]), 0)?,
        captured(arp(FIRST_MAC, [0xff; 6], ADDRESS), 0)?,
        captured(arp(SECOND_MAC, SECOND_MAC, ADDRESS), 0)?,
    ])?;
    assert_eq!(report.forensics.arp_observations.len(), 4);
    assert_eq!(
        report.forensics.arp_changes,
        [] as [l2_audit::ArpBindingChange; 0]
    );
    assert_eq!(
        report.network_model.address_conflicts,
        [] as [l2_audit::AddressConflict; 0]
    );
    Ok(())
}

#[test]
fn scope_both_destination_fields_match() -> TestResult {
    let report = assess([
        captured(arp(FIRST_MAC, FIRST_MAC, ADDRESS), 0)?,
        captured(arp(SECOND_MAC, SECOND_MAC, ADDRESS), 0)?,
        captured(traffic(SECOND_MAC, ADDRESS), 1)?,
        captured(tagged(&traffic(SECOND_MAC, ADDRESS), 20)?, 0)?,
        captured(traffic(FIRST_MAC, ADDRESS), 0)?,
        captured(traffic(SECOND_MAC, [192, 0, 2, 99]), 0)?,
    ])?;
    assert_eq!(report.forensics.arp_changes.len(), 1);
    assert_eq!(
        report
            .forensics
            .arp_changes
            .first()
            .ok_or("change")?
            .followup_packet,
        None
    );
    Ok(())
}

#[test]
fn reserved_vlan_not_binding_comparisons() -> TestResult {
    let report = assess([
        captured(tagged(&arp(FIRST_MAC, FIRST_MAC, ADDRESS), 0x0fff)?, 0)?,
        captured(tagged(&arp(SECOND_MAC, SECOND_MAC, ADDRESS), 0xafff)?, 0)?,
        captured(tagged(&traffic(SECOND_MAC, ADDRESS), 0x0fff)?, 0)?,
    ])?;
    // Raw claims remain available even when a VLAN identifier cannot name valid membership
    assert_eq!(report.forensics.arp_observations.len(), 2);
    assert_eq!(
        report.forensics.arp_changes,
        [] as [l2_audit::ArpBindingChange; 0]
    );
    assert_eq!(
        report.network_model.address_conflicts,
        [] as [l2_audit::AddressConflict; 0]
    );
    Ok(())
}

#[test]
fn auxiliary_vlan_claims_kept_separate() -> TestResult {
    let first = captured(arp(FIRST_MAC, FIRST_MAC, ADDRESS), 0)?;
    let bytes = arp(SECOND_MAC, SECOND_MAC, ADDRESS);
    let second = CapturedFrame::new(
        bytes.clone(),
        CaptureMetadata::new(
            InterfaceId {
                section: 0,
                index: 0,
            },
            u32::try_from(bytes.len())?,
            None,
            None,
            Direction::Unknown,
            Some(VlanAuxData {
                tpid: 0x8100,
                tci: 20,
            }),
            FcsStatus::Unknown,
        ),
    )?;
    let report = assess([first, second])?;
    assert_eq!(
        report.forensics.arp_changes,
        [] as [l2_audit::ArpBindingChange; 0]
    );
    assert_eq!(
        report.network_model.address_conflicts,
        [] as [l2_audit::AddressConflict; 0]
    );
    assert!(
        report
            .forensics
            .arp_observations
            .iter()
            .any(|observation| observation.scope.vlan_aux == Some((0x8100, 20)))
    );
    Ok(())
}

#[test]
fn outer_source_arp_sender_distinct() -> TestResult {
    let report = assess([captured(arp(FIRST_MAC, SECOND_MAC, ADDRESS), 0)?])?;
    let observation = report
        .forensics
        .arp_observations
        .first()
        .ok_or("ARP observation")?;
    assert_eq!(observation.source_mac, "02:00:00:00:00:01");
    assert_eq!(observation.sender_mac, "02:00:00:00:00:02");
    Ok(())
}
