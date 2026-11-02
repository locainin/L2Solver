use super::support::*;
use l2_audit::{ForensicScope, ForensicTracker, ResourceLimitStatus};
use l2_capture::InterfaceId;
use l2_discovery::link::decode_network_frame;

#[path = "../../../../../tests/fixtures/cooked.rs"]
mod fixture;
use fixture::cooked;

#[test]
fn cooked_dns_keeps_network_facts_and_scopes_without_ethernet_claims() -> TestResult {
    let question = standard_question()?;
    let query = query(73, std::slice::from_ref(&question))?;
    let response = response(73, &[question], &[], 0x8180, &[], &[])?;
    for (version, header) in [(113, 16), (276, 20)] {
        let interface = InterfaceId {
            section: 4,
            index: 9,
        };
        let frames = [
            cooked(&query, version, interface, 67)?,
            cooked(&response, version, interface, 67)?,
        ];
        let mut tracker = ForensicTracker::new(128, 128);
        let mut status = ResourceLimitStatus::default();
        for (index, frame) in frames.iter().enumerate() {
            let envelope = decode_network_frame(frame.metadata().link_type(), frame.bytes())
                .ok_or("missing cooked envelope")?;
            tracker.observe_network(
                frame,
                &envelope,
                u64::try_from(index + 1)?,
                true,
                &mut status,
            );
        }
        let report = tracker.finish();
        assert!(report.communications.is_empty());
        assert!(report.arp_observations.is_empty());
        assert_eq!(report.ip_frames_seen, 2);
        assert_eq!(report.ip_frames_parsed, 2);
        assert_eq!(report.dns_messages_parsed, 2);
        assert_eq!(report.dns_observations.len(), 2);
        let observation = report.dns_observations.first().ok_or("missing DNS query")?;
        let scope = &observation.scope;
        assert_eq!((scope.section, scope.interface), (4, 9));
        assert_eq!(scope.cooked_ifindex, (version == 276).then_some(67));
        assert!(scope.vlan_ids.is_empty());
        assert_eq!(observation.payload_offset, header + 28);
        assert_eq!(
            report
                .dns_matches
                .first()
                .ok_or("missing DNS match")?
                .query_packet,
            Some(1)
        );
    }
    Ok(())
}

#[test]
fn ethernet_scope_serialization_keeps_existing_shape() -> TestResult {
    let frame = captured(query(74, &[standard_question()?])?, 2)?;
    let decoded = l2_core::decode(frame.bytes())?;
    let scope = ForensicScope::new(frame.metadata(), &decoded);
    assert_eq!(
        serde_json::to_value(scope)?,
        serde_json::json!({
            "section": 0, "interface": 2, "vlan_ids": [], "vlan_aux": null
        })
    );
    Ok(())
}

#[test]
fn cooked_dns_does_not_correlate_distinct_capture_or_os_interfaces() -> TestResult {
    let question = standard_question()?;
    let query = query(75, std::slice::from_ref(&question))?;
    let response = response(75, &[question], &[], 0x8180, &[], &[])?;
    let frames = [
        cooked(
            &query,
            276,
            InterfaceId {
                section: 1,
                index: 2,
            },
            7,
        )?,
        cooked(
            &response,
            276,
            InterfaceId {
                section: 1,
                index: 2,
            },
            8,
        )?,
        cooked(
            &response,
            276,
            InterfaceId {
                section: 1,
                index: 3,
            },
            7,
        )?,
        cooked(
            &response,
            276,
            InterfaceId {
                section: 2,
                index: 2,
            },
            7,
        )?,
    ];
    let mut tracker = ForensicTracker::new(128, 128);
    let mut status = ResourceLimitStatus::default();
    for (index, frame) in frames.iter().enumerate() {
        let envelope = decode_network_frame(frame.metadata().link_type(), frame.bytes())
            .ok_or("missing cooked envelope")?;
        tracker.observe_network(
            frame,
            &envelope,
            u64::try_from(index + 1)?,
            true,
            &mut status,
        );
    }
    let report = tracker.finish();
    assert_eq!(report.dns_matches.len(), 3);
    assert!(
        report
            .dns_matches
            .iter()
            .all(|item| item.query_packet.is_none())
    );
    Ok(())
}
