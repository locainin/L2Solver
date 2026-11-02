use crate::behavior_support::{PacketSpec, case_with_packets, tcp_frame};
use l2_workbench::{
    evidence::{Edge, EvidenceStatus, SourceRange},
    query::{Selector, select},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn source_ranges_composed_network_filters() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 1],
            [198, 51, 100, 1],
            40000,
            80,
            0x18,
        ))
        .with_scope(2, vec![37]),
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            40001,
            443,
            0x18,
        ))
        .with_scope(3, vec![38]),
    ])?;
    let ranges = case.nodes().first().ok_or("missing packet")?.ranges.clone();
    let operation = case.add_node("operation", None, Vec::new(), json!({}))?;
    let derived = case.add_node("derived_bytes", None, ranges, json!({}))?;
    case.add_edge(Edge {
        from: operation,
        to: derived,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::ConstraintSatisfied,
        reason: "The stated operation passed its supplied constraints".to_owned(),
    })?;
    let selector = Selector::parse(&[
        "kind=derived_bytes",
        "dst=198.51.100.1/32",
        "port=80",
        "proto=tcp",
        "packet=1..1",
        "interface=0:2",
        "vlan=37",
        "status=constraint_satisfied",
    ])?;
    let selected = select(&case, &selector);
    let result = selected
        .first()
        .ok_or("derived byte evidence was hidden by network filters")?;
    assert_eq!(selected.len(), 1);
    assert_eq!(result.node_id, derived);
    assert_eq!(result.packet_numbers, [1]);
    assert_eq!(result.statuses, [EvidenceStatus::ConstraintSatisfied]);
    assert_eq!(
        select(
            &case,
            &Selector::parse(&["kind=derived_bytes", "port=443"])?
        )
        .len(),
        0
    );
    Ok(())
}

#[test]
fn equal_packet_sources_never_cross() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(vec![PacketSpec::new(tcp_frame(
        [192, 0, 2, 1],
        [198, 51, 100, 1],
        40000,
        443,
        0x18,
    ))])?;
    let ranges = case.nodes().first().ok_or("missing packet")?.ranges.clone();
    let bytes = tcp_frame([192, 0, 2, 2], [198, 51, 100, 2], 40001, 80, 0x18);
    let source = case.add_source(
        "second.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &sha256(&bytes),
        None,
    )?;
    let blob = case.add_blob(&bytes)?;
    case.add_node(
        "packet",
        Some(&blob),
        vec![SourceRange {
            source,
            packet: Some(1),
            offset: 0,
            length: u64::try_from(bytes.len())?,
        }],
        json!({"record":1,"link_type":1}),
    )?;
    let derived = case.add_node("derived_bytes", None, ranges, json!({}))?;
    assert_eq!(
        select(&case, &Selector::parse(&["kind=derived_bytes", "port=80"])?).len(),
        0
    );
    let selected = select(
        &case,
        &Selector::parse(&["kind=derived_bytes", "port=443"])?,
    );
    assert_eq!(selected.len(), 1);
    assert_eq!(selected.first().map(|item| item.node_id), Some(derived));
    assert_eq!(
        selected.first().map(|item| item.packet_numbers.as_slice()),
        Some([1].as_slice())
    );
    Ok(())
}

#[test]
fn range_filter_single_match() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 1],
            [198, 51, 100, 1],
            40000,
            80,
            0x18,
        ))
        .with_scope(2, vec![37]),
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            40001,
            443,
            0x18,
        ))
        .with_scope(3, vec![38]),
    ])?;
    let ranges = case
        .nodes()
        .iter()
        .flat_map(|node| node.ranges.clone())
        .collect();
    case.add_node("derived_bytes", None, ranges, json!({}))?;
    assert_eq!(
        select(
            &case,
            &Selector::parse(&["kind=derived_bytes", "port=80", "vlan=38"])?
        )
        .len(),
        0
    );
    let intermediate = case.add_node("operation", None, Vec::new(), json!({}))?;
    let unlocated = case.add_node("unlocated_output", None, Vec::new(), json!({}))?;
    for (from, to) in [(1, intermediate), (intermediate, unlocated)] {
        case.add_edge(Edge {
            from,
            to,
            relation: "related".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Only a graph relationship is present".to_owned(),
        })?;
    }
    assert_eq!(
        select(
            &case,
            &Selector::parse(&["kind=unlocated_output", "port=80"])?
        )
        .len(),
        0
    );
    Ok(())
}
