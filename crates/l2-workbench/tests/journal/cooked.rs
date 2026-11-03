use crate::{captures, cooked_analysis};
use l2_workbench::{
    evidence::{Case, SourceRange},
    journal::{ChainDeadline, ChainPlan, EventSelector, Journal, JournalOptions},
    store::{Options, Store},
};
use std::{error::Error, io::Cursor};

fn index(version: u16, interfaces: &[u32]) -> Result<(tempfile::TempDir, Store), Box<dyn Error>> {
    let frames = interfaces
        .iter()
        .map(|ifindex| cooked_analysis::frame(version, *ifindex, 9000, 0x18))
        .collect::<Result<Vec<_>, _>>()?;
    let mut capture = captures::capture(&frames)?;
    // The shared capture fixture writes Ethernet by default
    capture
        .get_mut(20..24)
        .ok_or("capture link type missing")?
        .copy_from_slice(&u32::from(version).to_le_bytes());
    let directory = tempfile::tempdir()?;
    let mut store = Store::create(directory.path(), Options::default())?;
    store.ingest("cooked", Cursor::new(capture))?;
    Ok((directory, store))
}

#[test]
fn cooked_case_events_keep_tcp_addresses_and_ports() -> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let result = cooked_analysis::case(vec![cooked_analysis::frame(version, 37, 9000, 0x02)?])?;
        let directory = tempfile::tempdir()?;
        let mut journal =
            Journal::create(directory.path(), &result.case, JournalOptions::default())?;
        journal.import_base_events()?;
        let mut packets = Vec::new();
        journal.visit_events(0, None, |event| {
            if event.kind.starts_with("packet_") {
                packets.push(event);
            }
            Ok(())
        })?;
        let packet = packets.first().ok_or("packet event missing")?;
        assert_eq!(packet.kind, "packet_tcp", "link type {version}");
        assert_eq!(packet.actor.as_deref(), Some("192.0.2.1"));
        assert_eq!(packet.peer.as_deref(), Some("192.0.2.2"));
        assert_eq!(
            packet.fields.get("source_port"),
            Some(&serde_json::json!(40000))
        );
        assert_eq!(
            packet.fields.get("destination_port"),
            Some(&serde_json::json!(9000))
        );
        assert_eq!(
            packet.fields.get("source_mac"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            packet.fields.get("destination_mac"),
            Some(&serde_json::Value::Null)
        );
    }
    Ok(())
}

#[test]
fn indexed_sll2_event_chains_do_not_join_different_interface_indices() -> Result<(), Box<dyn Error>>
{
    let (_index_directory, store) = index(276, &[37, 38, 37])?;
    let journal_directory = tempfile::tempdir()?;
    let mut journal = Journal::create(
        journal_directory.path(),
        &Case::new(),
        JournalOptions::default(),
    )?;
    assert_eq!(journal.import_index_events(&store)?, 3);
    let plan = ChainPlan {
        steps: vec![EventSelector::default(), EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut chains = Vec::new();
    journal.visit_chains(&plan, |chain| {
        chains.push(chain);
        Ok(())
    })?;
    assert_eq!(
        chains.len(),
        1,
        "different cooked interfaces must stay separate"
    );
    let chain = chains.first().ok_or("same-interface chain missing")?;
    assert_eq!(
        chain
            .events
            .iter()
            .map(|event| event.packet)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert!(chain.events.iter().all(|event| event.kind == "packet_tcp"));
    assert!(
        chain
            .events
            .iter()
            .all(|event| event.scope.contains("cooked_ifindex"))
    );
    Ok(())
}

#[test]
fn overlapping_case_and_index_import_do_not_duplicate_cooked_events() -> Result<(), Box<dyn Error>>
{
    for version in [113, 276] {
        let (_index_directory, store) = index(version, &[37])?;
        let mut flow_id = None;
        store.visit_flows(0, None, |flow| {
            flow_id = Some(flow.id);
            Ok(())
        })?;
        let case = store.investigate_flow(flow_id.ok_or("flow missing")?)?.case;
        let directory = tempfile::tempdir()?;
        let mut journal = Journal::create(directory.path(), &case, JournalOptions::default())?;
        journal.import_base_events()?;
        assert_eq!(
            journal.import_index_events(&store)?,
            0,
            "link type {version}"
        );
    }
    Ok(())
}

#[test]
fn case_event_scope_uses_the_sll2_header_when_saved_scope_is_wrong_or_missing()
-> Result<(), Box<dyn Error>> {
    let frames = [37, 38, 39]
        .into_iter()
        .map(|ifindex| cooked_analysis::frame(276, ifindex, 9000, 0x18))
        .collect::<Result<Vec<_>, _>>()?;
    let mut case = Case::new();
    let length = frames.iter().try_fold(0_u64, |sum, frame| {
        Ok::<_, std::num::TryFromIntError>(sum + u64::try_from(frame.bytes().len())?)
    })?;
    let source = case.add_source(
        "cooked",
        "capture",
        length,
        &l2_workbench::sha256(b"source"),
        None,
    )?;
    let mut offset = 0_u64;
    for (index, frame) in frames.iter().enumerate() {
        let packet = u64::try_from(index + 1)?;
        let length = u64::try_from(frame.bytes().len())?;
        let blob = case.add_blob(frame.bytes())?;
        case.add_node("packet", Some(&blob), vec![SourceRange {
            source: source.clone(), packet: Some(packet), offset, length,
        }], serde_json::json!({
            "record": packet,
            "link_type": 276,
            "scope": if packet == 3 { serde_json::Value::Null } else {
                serde_json::json!({"section": 0, "interface": 0, "vlan_ids": [], "vlan_aux": null, "cooked_ifindex": 37})
            },
        }))?;
        offset += length;
    }
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &case, JournalOptions::default())?;
    journal.import_base_events()?;
    let mut scopes = Vec::new();
    journal.visit_events(0, None, |event| {
        scopes.push(serde_json::from_str::<serde_json::Value>(&event.scope)?);
        Ok(())
    })?;
    assert_eq!(scopes.len(), 3);
    assert_eq!(
        scopes.first().and_then(|scope| scope.get("cooked_ifindex")),
        Some(&serde_json::json!(37))
    );
    assert_eq!(
        scopes.get(1).and_then(|scope| scope.get("cooked_ifindex")),
        Some(&serde_json::json!(38))
    );
    assert_eq!(
        scopes.get(2).and_then(|scope| scope.get("cooked_ifindex")),
        Some(&serde_json::json!(39))
    );
    Ok(())
}
