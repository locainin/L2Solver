use super::common::{captured, ethernet_frame, frame, source_with_suffix};
use l2_audit::{Policy, Survey, Verdict};

#[test]
fn disallowed_vlan_keeps_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&[0x81, 0, 0, 20, 0x08, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(bytes.clone(), 18)?)?;
    let report = survey.finish(&Policy {
        allowed_vlans: Some(vec![10]),
        ..Policy::default()
    })?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.check_id == "VLAN-001")
        .ok_or("missing VLAN finding")?;
    assert_eq!(finding.verdict, Verdict::Fail);
    assert_eq!(finding.evidence_packets, [1]);
    assert_eq!(
        report.evidence.first().ok_or("missing evidence")?.raw_bytes,
        bytes
    );
    let mut survey = Survey::new();
    survey.observe(&frame(bytes, 18)?)?;
    let report = survey.finish(&Policy::default())?;
    assert!(report.findings.iter().all(|f| f.verdict != Verdict::Fail));
    Ok(())
}

#[test]
fn preserves_tag_stack_context() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&[0x88, 0xa8, 0, 100, 0x81, 0, 0, 100, 8, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(bytes, 22)?)?;
    let report = survey.finish(&Policy::default())?;
    assert_eq!(
        report
            .interfaces
            .first()
            .ok_or("interface")?
            .vlans
            .first()
            .ok_or("tag stack")?
            .tags,
        [(0x88a8, 100), (0x8100, 100)]
    );
    Ok(())
}

#[test]
fn qinq_when_single_tag_required() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&[0x88, 0xa8, 0, 100, 0x81, 0, 0, 100, 8, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(bytes, 22)?)?;
    let report = survey.finish(&Policy {
        allowed_vlans: Some(vec![100]),
        max_vlan_depth: Some(1),
        ..Policy::default()
    })?;
    assert!(report.findings.iter().any(|f| f.check_id == "VLAN-003"
        && f.verdict == Verdict::Fail
        && f.evidence_packets == [1]));
    Ok(())
}

#[test]
fn priority_tag_requires_explicit_prohibition() -> Result<(), Box<dyn std::error::Error>> {
    let mut priority = vec![0; 12];
    priority.extend_from_slice(&[0x81, 0, 0, 0, 0x08, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(priority.clone(), 18)?)?;
    let report = survey.finish(&Policy {
        allow_priority_tagged: Some(false),
        ..Policy::default()
    })?;
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.check_id == "VLAN-004")
    );

    let mut survey = Survey::new();
    survey.observe(&frame(priority, 18)?)?;
    let report = survey.finish(&Policy::default())?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.check_id != "VLAN-004")
    );
    Ok(())
}

#[test]
fn allowed_vlan_not_create_finding() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    let mut ordinary = vec![0; 12];
    ordinary.extend_from_slice(&[0x81, 0, 0, 20, 0x08, 0]);
    survey.observe(&frame(ordinary, 18)?)?;
    let report = survey.finish(&Policy {
        allow_untagged: Some(true),
        ..Policy::default()
    })?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.check_id != "VLAN-001")
    );
    Ok(())
}

#[test]
fn vlan_allowlist_not_priority_tags() -> Result<(), Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    let mut unspecified_priority = vec![0; 12];
    unspecified_priority.extend_from_slice(&[0x81, 0, 0, 0, 0x08, 0]);
    survey.observe(&frame(unspecified_priority, 18)?)?;
    let report = survey.finish(&Policy {
        allowed_vlans: Some(vec![10]),
        ..Policy::default()
    })?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.check_id != "VLAN-004")
    );
    Ok(())
}

#[test]
fn forbidden_untagged_frame_creates_finding() -> Result<(), Box<dyn std::error::Error>> {
    let untagged = vec![0; 12]
        .into_iter()
        .chain([0x08, 0x00])
        .collect::<Vec<_>>();
    let mut survey = Survey::new();
    survey.observe(&frame(untagged, 14)?)?;
    let report = survey.finish(&Policy {
        allow_untagged: Some(false),
        ..Policy::default()
    })?;
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.check_id == "VLAN-002")
    );
    Ok(())
}

#[test]
fn single_tag_depth_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut one_tag = vec![0; 12];
    one_tag.extend_from_slice(&[0x81, 0, 0, 10, 0x08, 0]);
    let mut survey = Survey::new();
    survey.observe(&frame(one_tag, 18)?)?;
    let report = survey.finish(&Policy {
        allowed_vlans: Some(vec![10]),
        max_vlan_depth: Some(1),
        ..Policy::default()
    })?;
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.check_id != "VLAN-003")
    );
    Ok(())
}

#[test]
fn vlan_stack_representatives() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0; 12];
    first.extend_from_slice(&[0x81, 0, 0, 10, 0x08, 0]);
    let mut second = first.clone();
    let second_field = second.get_mut(14..18).ok_or("second VLAN tag")?;
    second_field.copy_from_slice(&[0, 10, 0x08, 0]);
    let mut distinct = first.clone();
    let distinct_field = distinct.get_mut(14..18).ok_or("distinct VLAN tag")?;
    distinct_field.copy_from_slice(&[0, 20, 0x08, 0]);

    let mut survey = Survey::new();
    survey.observe(&captured(first)?)?;
    survey.observe(&captured(second)?)?;
    survey.observe(&captured(distinct)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.vlans.len(), 2);
    assert_eq!(interface.vlans.first().ok_or("first VLAN")?.packet, 1);
    assert_eq!(interface.vlans.get(1).ok_or("second VLAN")?.packet, 3);
    assert_eq!(
        report
            .evidence
            .iter()
            .map(|evidence| evidence.sequence)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    Ok(())
}

#[test]
fn keeps_first_untagged_representative() -> Result<(), Box<dyn std::error::Error>> {
    let source = source_with_suffix(7);
    let bytes = ethernet_frame([0; 6], source, 0x0800, &[]);
    let mut survey = Survey::new();
    survey.observe(&captured(bytes.clone())?)?;
    survey.observe(&captured(bytes)?)?;
    let report = survey.finish(&Policy::default())?;
    let interface = report.interfaces.first().ok_or("interface")?;
    assert_eq!(interface.untagged_packet, Some(1));
    assert_eq!(interface.macs, ["00:00:00:00:00:07"]);
    assert_eq!(report.evidence.len(), 1);
    Ok(())
}
