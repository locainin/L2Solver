#[path = "../../../../tests/fixtures/truncated_tcp.rs"]
mod fixture;

use super::support::capture;
use l2_workbench::store::{Options, Store};
use std::{error::Error, io::Cursor};

#[test]
fn truncated_tcp_keeps_flow() -> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let mut conflict = payload.to_vec();
    let body = conflict.len() - 3;
    *conflict.get_mut(body).ok_or("missing body")? = b'x';
    let frames = [
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(101, 0x18, payload, 0)?,
        fixture::tcp(101, 0x18, &conflict, 8)?,
        fixture::tcp(101 + u32::try_from(payload.len())?, 0x11, b"", 0)?,
    ];
    let bytes = capture(&frames)?;
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let receipt = store.ingest("truncated.pcap", Cursor::new(bytes))?;
    assert_eq!(receipt.transport_packets, 4);
    let mut flows = Vec::new();
    store.visit_flows(0, None, |flow| {
        flows.push(flow);
        Ok(())
    })?;
    let flow = flows.first().ok_or("missing flow")?;
    assert_eq!(flow.packets, 4);
    let result = store.investigate_flow(flow.id)?;
    assert!(!result.complete);
    assert!(!result.case.nodes().iter().any(|node| {
        node.kind == "http_body"
            && node.details.get("status").and_then(|value| value.as_str()) == Some("complete")
    }));
    store.verify_sources()?;
    Ok(())
}

#[test]
fn old_index_requires_rebuild() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let store = Store::create(temp.path(), Options::default())?;
    drop(store);
    let path = temp.path().join("index.sqlite");
    let connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "user_version", 6)?;
    drop(connection);
    let before = std::fs::read(&path)?;
    let Err(error) = Store::open(temp.path(), Options::default()) else {
        return Err("old index was accepted".into());
    };
    assert!(error.to_string().contains("rebuild"));
    assert_eq!(std::fs::read(path)?, before);
    Ok(())
}

#[test]
fn truncated_header_keeps_tuple() -> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let partial = fixture::tcp(101, 0x18, payload, 0)?;
    let partial = l2_capture::CapturedFrame::new(
        partial
            .bytes()
            .get(..38)
            .ok_or("missing TCP ports")?
            .to_vec(),
        partial.metadata().clone(),
    )?;
    let frames = [
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(101, 0x18, payload, 0)?,
        partial,
        fixture::tcp(101 + u32::try_from(payload.len())?, 0x11, b"", 0)?,
    ];
    let temp = tempfile::tempdir()?;
    let mut store = Store::create(temp.path(), Options::default())?;
    let receipt = store.ingest("truncated.pcap", Cursor::new(capture(&frames)?))?;
    assert_eq!(receipt.transport_packets, 4);
    let mut flows = Vec::new();
    store.visit_flows(0, None, |flow| {
        flows.push(flow);
        Ok(())
    })?;
    let result = store.investigate_flow(flows.first().ok_or("missing flow")?.id)?;
    assert!(!result.complete);
    let packet = result
        .case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "packet"
                && node
                    .details
                    .get("record")
                    .and_then(serde_json::Value::as_u64)
                    == Some(3)
        })
        .ok_or("missing truncated packet")?;
    assert_eq!(
        packet
            .details
            .pointer("/truncated_tcp_header/captured_transport_bytes")
            .and_then(serde_json::Value::as_u64),
        Some(4)
    );
    let episode = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "tcp_episode")
        .ok_or("missing episode")?;
    assert!(result.case.edges().iter().any(|edge| edge.from == packet.id
        && edge.to == episode.id
        && edge.status == l2_workbench::evidence::EvidenceStatus::Unresolved));
    assert!(!result.case.nodes().iter().any(|node| {
        node.kind == "http_body"
            && node.details.get("status").and_then(|value| value.as_str()) == Some("complete")
    }));
    Ok(())
}
