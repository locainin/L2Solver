use super::{frames, support::capture, vlan};
use l2_workbench::{
    evidence::{Case, ReceiptVerificationLimits, verify_index_flow_selection},
    reconstruction::Limits,
    store::{Options, Store},
};
use serde_json::json;
use std::{error::Error, io::Cursor};

fn three_flow_records() -> Result<Vec<u8>, Box<dyn Error>> {
    let records = [
        frames::tcp(false, 100, 2, b"first")?,
        frames::tcp_ports(false, (41_000, 8_000), 700, 2, b"middle")?,
        frames::tcp(false, 105, 0x10, b"last")?,
    ];
    capture(&records)
}

fn flow_id(store: &Store, source: &str, packet: u32) -> Result<i64, Box<dyn Error>> {
    store
        .packet(source, packet)?
        .flow
        .ok_or_else(|| "packet has no indexed flow".into())
}

#[test]
fn large_flow_bounded_node_details() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let packets = (0..128_u16)
        .map(|index| frames::tcp_ports(false, (40_000 + index, 8_000), u32::from(index), 2, b"x"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("large-cohort.pcap", Cursor::new(capture(&packets)?))?;
    let flow_ids = (1..=128_u32)
        .map(|packet| flow_id(&store, &source.source_id, packet))
        .collect::<Result<Vec<_>, _>>()?;

    let result = store.investigate_flows(&flow_ids, Limits::default())?;

    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("flow selection evidence is missing")?;
    assert_eq!(selection.details.get("flow_count"), Some(&json!(128)));
    assert_eq!(
        selection.details.get("requested_flow_count"),
        Some(&json!(128))
    );
    assert_eq!(
        selection.details.get("representation"),
        Some(&json!("json_blob"))
    );
    let receipt_id = selection
        .blob
        .as_deref()
        .ok_or("flow selection receipt is missing")?;
    let receipt_blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_id)
        .ok_or("flow selection receipt blob is missing")?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(
        receipt
            .get("requested_flow_ids")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(128)
    );
    assert_eq!(
        receipt
            .get("flow_contributions")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(128)
    );
    assert_eq!(
        result
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "index_flow_cohort")
            .count(),
        0
    );
    Ok(())
}

#[test]
fn selected_flow_capture_provenance() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let first_capture = three_flow_records()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("cohort.pcap", Cursor::new(first_capture))?;
    let first_flow = flow_id(&store, &source.source_id, 1)?;
    let second_flow = flow_id(&store, &source.source_id, 2)?;

    let result = store.investigate_flows(&[second_flow, first_flow], Limits::default())?;
    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("flow selection evidence node is missing")?;
    assert_eq!(selection.details.get("selected_records"), Some(&json!(3)));
    assert_eq!(
        selection.details.get("retained_input_records"),
        Some(&json!(3))
    );
    let receipt_id = selection
        .blob
        .as_deref()
        .ok_or("selection receipt is missing")?;
    let receipt: serde_json::Value = serde_json::from_slice(
        &result
            .case
            .blobs()
            .iter()
            .find(|blob| blob.id == receipt_id)
            .ok_or("selection receipt blob is missing")?
            .bytes,
    )?;
    assert_eq!(
        receipt.get("requested_flow_ids"),
        Some(&json!([second_flow, first_flow]))
    );
    assert_eq!(
        receipt.get("flow_contributions"),
        Some(&json!([
            {"flow_id": second_flow, "packet_records": 1},
            {"flow_id": first_flow, "packet_records": 2}
        ]))
    );

    let packets: Vec<_> = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .filter_map(|node| {
            node.details
                .get("record")
                .and_then(serde_json::Value::as_u64)
        })
        .collect();
    assert_eq!(packets, [1, 2, 3]);
    assert!(result.complete);
    assert_eq!(result.case.sources().len(), 1);
    Ok(())
}

#[test]
fn repeated_flow_not_duplicate_packet() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let first_capture = three_flow_records()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("duplicate-selection.pcap", Cursor::new(first_capture))?;
    let flow = flow_id(&store, &source.source_id, 1)?;

    let result = store.investigate_flows(&[flow, flow], Limits::default())?;
    let packet_record_count = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .count();
    assert_eq!(packet_record_count, 2);
    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("flow selection evidence node is missing")?;
    assert_eq!(selection.details.get("selected_records"), Some(&json!(2)));
    assert_eq!(
        selection.details.get("duplicate_flow_selections_removed"),
        Some(&json!(1))
    );
    Ok(())
}

#[test]
fn pair_cohort_groups_cross_protocol_flows() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let first = frames::tcp_ports(false, (40_000, 80), 100, 2, b"")?;
    let second = frames::tcp_ports(true, (41_000, 21), 100, 2, b"")?;
    let third = frames::tcp_ports(false, (42_000, 22), 100, 2, b"")?;
    let udp = super::udp(false, b"")?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "pair-scopes.pcap",
        Cursor::new(capture(&[first, second, udp, vlan(&third, 7)?])?),
    )?;

    let mut cohorts = Vec::new();
    let mut packet_maps = Vec::new();
    let coverage = store.visit_ip_pair_cohort_analyses(Limits::default(), |analysis| {
        cohorts.push(
            analysis
                .member_flows
                .iter()
                .map(|flow| (flow.id, flow.protocol, flow.port_a))
                .collect::<Vec<_>>(),
        );
        packet_maps.push(analysis.packet_flow_ids);
        Ok(())
    })?;

    assert_eq!(cohorts.len(), 1);
    let cohort = cohorts.first().ok_or("IP-pair cohort is missing")?;
    assert_eq!(cohort.len(), 3);
    let first = cohort.first().ok_or("first cohort flow is missing")?;
    let second = cohort.get(1).ok_or("second cohort flow is missing")?;
    let third = cohort.get(2).ok_or("third cohort flow is missing")?;
    assert_ne!(first.2, second.2);
    let protocols = cohort
        .iter()
        .map(|(_, protocol, _)| *protocol)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(protocols, [6, 17].into_iter().collect());
    assert_eq!(
        packet_maps,
        [vec![(1, first.0), (2, second.0), (3, third.0)]]
    );
    assert_eq!(coverage.multi_flow_groups, 1);
    assert_eq!(coverage.complete_groups, 1);
    assert_eq!(coverage.analysis_chunks, 1);
    assert_eq!(coverage.reanalyzed_flows, 3);
    Ok(())
}

#[test]
fn pair_chunks_follow_capture_order() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let packets = [
        frames::tcp_ports(false, (40_000, 80), 100, 2, b"")?,
        frames::tcp_ports(false, (41_000, 80), 100, 2, b"")?,
        frames::tcp_ports(false, (42_000, 80), 100, 2, b"")?,
    ];
    store.ingest("split-pair.pcap", Cursor::new(capture(&packets)?))?;

    let limits = Limits {
        frames: 2,
        units: 2,
        ..Limits::default()
    };
    let mut chunks = Vec::new();
    let coverage = store.visit_ip_pair_cohort_analyses(limits, |analysis| {
        chunks.push((
            analysis.split,
            analysis
                .member_flows
                .iter()
                .map(|flow| flow.id)
                .collect::<Vec<_>>(),
        ));
        Ok(())
    })?;

    assert_eq!(chunks.len(), 1);
    let first_chunk = chunks.first().ok_or("cohort chunk is missing")?;
    assert!(first_chunk.0);
    assert_eq!(first_chunk.1.len(), 2);
    assert_eq!(coverage.split_groups, 1);
    assert_eq!(coverage.incomplete_groups, 1);
    assert_eq!(coverage.singleton_chunks_skipped, 1);
    let mut repeated = Vec::new();
    store.visit_ip_pair_cohort_analyses(limits, |analysis| {
        repeated.push((
            analysis.split,
            analysis
                .member_flows
                .iter()
                .map(|flow| flow.id)
                .collect::<Vec<_>>(),
        ));
        Ok(())
    })?;
    assert_eq!(repeated, chunks);
    Ok(())
}

#[test]
fn visitor_error_cleans_spools() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let packets = [
        frames::tcp_ports(false, (40_000, 80), 100, 2, b"")?,
        frames::tcp_ports(false, (41_000, 80), 100, 2, b"")?,
    ];
    store.ingest("cohort-cleanup.pcap", Cursor::new(capture(&packets)?))?;

    let failed = store.visit_ip_pair_cohort_analyses(Limits::default(), |_| {
        Err("stop after first cohort".into())
    });
    assert!(failed.is_err());

    let mut visited = 0;
    let coverage = store.visit_ip_pair_cohort_analyses(Limits::default(), |_| {
        visited += 1;
        Ok(())
    })?;
    assert_eq!(visited, 1);
    assert_eq!(coverage.multi_flow_groups, 1);
    Ok(())
}

#[test]
fn generated_receipts_verify_after_persistence() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("receipt.pcap", Cursor::new(three_flow_records()?))?;
    let first_flow = flow_id(&store, &source.source_id, 1)?;
    let second_flow = flow_id(&store, &source.source_id, 2)?;

    for (requested, limits, flow_count, selected, retained) in [
        (vec![first_flow], Limits::default(), 1, 2, 2),
        (vec![first_flow, first_flow], Limits::default(), 1, 2, 2),
        (
            vec![second_flow, first_flow, second_flow],
            Limits {
                frames: 1,
                ..Limits::default()
            },
            2,
            3,
            1,
        ),
    ] {
        let result = store.investigate_flows(&requested, limits)?;
        // Reload the generated case so raw detail validation is part of the production path
        let case = Case::from_json(&result.case.to_json()?)?;
        let selection = case
            .nodes()
            .iter()
            .find(|node| node.kind == "index_flow_selection")
            .ok_or("flow selection receipt is missing")?;
        let report =
            verify_index_flow_selection(&case, selection.id, ReceiptVerificationLimits::default())?;

        assert!(report.verified);
        assert_eq!(report.source_id, source.source_id);
        assert_eq!(report.requested_flow_count, u64::try_from(requested.len())?);
        assert_eq!(report.flow_count, flow_count);
        assert_eq!(report.selected_records, selected);
        assert_eq!(report.retained_input_records, retained);
        assert_eq!(report.omitted_records, selected - retained);
    }
    Ok(())
}

#[test]
fn missing_flow_is_reported_explicitly() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let store = Store::create(temporary.path(), Options::default())?;
    let error = store
        .investigate_flows(&[99_999], Limits::default())
        .err()
        .ok_or("missing flow must fail")?;
    assert!(error.to_string().contains("flow 99999 was not found"));
    Ok(())
}

#[test]
fn cross_source_flow_rejection() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let first_capture = three_flow_records()?;
    let other_capture = capture(&[frames::tcp_ports(
        false,
        (42_000, 8_001),
        900,
        2,
        b"other source",
    )?])?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let first = store.ingest("first.pcap", Cursor::new(first_capture))?;
    let second = store.ingest("second.pcap", Cursor::new(other_capture))?;
    let first_flow = flow_id(&store, &first.source_id, 1)?;
    let second_flow = flow_id(&store, &second.source_id, 1)?;

    let error = store
        .investigate_flows(&[first_flow, second_flow], Limits::default())
        .err()
        .ok_or("cross-source cohort must fail")?;
    assert!(error.to_string().contains("different retained sources"));
    Ok(())
}

#[test]
fn retention_limits_union_omissions_prefix() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = three_flow_records()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("limited.pcap", Cursor::new(capture))?;
    let first_flow = flow_id(&store, &source.source_id, 1)?;
    let second_flow = flow_id(&store, &source.source_id, 2)?;
    let limits = Limits {
        frames: 1,
        units: 1,
        ..Limits::default()
    };

    let result = store.investigate_flows(&[second_flow, first_flow], limits)?;
    assert!(!result.complete);
    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("flow selection evidence node is missing")?;
    assert_eq!(selection.details.get("selected_records"), Some(&json!(3)));
    assert_eq!(
        selection.details.get("retained_input_records"),
        Some(&json!(1))
    );
    assert_eq!(selection.details.get("omitted_records"), Some(&json!(2)));
    assert!(
        result
            .case
            .limitations()
            .iter()
            .any(|limitation| { limitation.contains('2') && limitation.contains("omitted") })
    );
    let packet = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "packet")
        .ok_or("first capture-order packet is missing")?;
    assert_eq!(packet.details.get("record"), Some(&json!(1)));
    Ok(())
}

#[test]
fn reconstruction_session_reported_packet_retention() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = three_flow_records()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("session-limited.pcap", Cursor::new(capture))?;
    let first_flow = flow_id(&store, &source.source_id, 1)?;
    let second_flow = flow_id(&store, &source.source_id, 2)?;
    let limits = Limits {
        sessions: 1,
        ..Limits::default()
    };

    let result = store.investigate_flows(&[first_flow, second_flow], limits)?;
    assert!(!result.complete);
    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("flow selection evidence node is missing")?;
    assert_eq!(
        selection.details.get("retained_input_records"),
        Some(&json!(3))
    );
    assert_eq!(selection.details.get("omitted_records"), Some(&json!(0)));
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("capture summary evidence is missing")?;
    assert!(
        summary
            .details
            .get("omitted_tcp_records")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|omitted| omitted > 0)
    );
    Ok(())
}
