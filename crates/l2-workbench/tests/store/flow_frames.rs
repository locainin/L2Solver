use super::{capture, frames};
use l2_workbench::{
    reconstruction::Limits,
    sha256,
    store::{FlowPageError, Options, Store},
};
use std::{error::Error, fs, io::Cursor};

#[test]
fn flow_frame_packet_exact_bytes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let frames = [
        frames::tcp(false, 100, 2, b"")?,
        frames::tcp(false, 101, 0x10, b"first")?,
        frames::tcp_ports(false, (41_000, 8_000), 700, 0x10, b"other flow")?,
        frames::tcp(false, 106, 0x10, b"second")?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("capture.pcap", Cursor::new(capture(&frames)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing TCP flow")?;
    let mut observed = Vec::new();

    store.visit_flow_frames(flow, |packet, frame| {
        observed.push((packet.number, frame.bytes().to_vec()));
        Ok(())
    })?;

    assert_eq!(observed.len(), 3);
    for (index, expected_packet) in [1_u32, 2, 4].into_iter().enumerate() {
        let (packet_number, bytes) = observed.get(index).ok_or("flow packet is missing")?;
        assert_eq!(*packet_number, expected_packet);
        assert_eq!(
            bytes,
            frames
                .get(usize::try_from(expected_packet - 1)?)
                .ok_or("fixture packet is missing")?
                .bytes()
        );
    }
    Ok(())
}

#[test]
fn flow_frame_retained_source_bytes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_bytes = capture(&[frames::tcp(false, 100, 2, b"hello")?])?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("capture.pcap", Cursor::new(&capture_bytes))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing TCP flow")?;
    let digest = sha256(&capture_bytes);
    fs::write(
        temporary
            .path()
            .join("sources")
            .join(format!("{digest}.pcap")),
        vec![0; capture_bytes.len()],
    )?;

    let error = store
        .visit_flow_frames(flow, |_, _| Ok(()))
        .err()
        .ok_or_else(|| std::io::Error::other("changed packet data must not reach the visitor"))?;

    assert!(error.to_string().contains("retained packet bytes changed"));
    Ok(())
}

#[test]
fn flow_pages_preserve_order_ranges_and_exact_counts() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let frames = [
        frames::tcp(false, 100, 0x18, b"same")?,
        frames::tcp_ports(false, (41_000, 8_000), 700, 0x18, b"peer")?,
        frames::tcp(false, 104, 0x18, b"same")?,
        frames::tcp(false, 108, 0x18, b"same")?,
        frames::tcp_ports(false, (41_000, 8_000), 704, 0x18, b"peer")?,
        frames::tcp(false, 112, 0x18, b"same")?,
        frames::tcp(false, 116, 0x18, b"same")?,
    ];
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("paged-flow.pcap", Cursor::new(capture(&frames)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing TCP flow")?;
    let page_bytes = frames
        .first()
        .ok_or("first fixture frame is missing")?
        .bytes()
        .len()
        .checked_mul(2)
        .ok_or("page byte limit overflow")?;
    let limits = Limits {
        frames: 2,
        bytes: page_bytes,
        units: 2,
        ..Limits::default()
    };
    let mut observed_pages = Vec::new();

    let coverage = store.visit_flow_pages_after_prefix(flow, 1, limits, |page| {
        assert_flow_page(&store, &source.source_id, &page)?;
        observed_pages.push(page.page_index);
        Ok(())
    })?;

    assert_eq!(observed_pages, [1, 2]);
    assert_eq!(coverage.pages, 2);
    assert_eq!(coverage.selected_records, 4);
    assert_eq!(coverage.retained_records, 4);
    assert_eq!(coverage.omitted_records, 0);
    Ok(())
}

fn assert_flow_page(
    store: &Store,
    source_id: &str,
    page: &l2_workbench::store::FlowPageAnalysis,
) -> Result<(), Box<dyn Error>> {
    let packet_records = page
        .result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .collect::<Vec<_>>();
    let packet_numbers = packet_records
        .iter()
        .map(|node| {
            node.details
                .get("record")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "packet record number is missing".into())
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let expected_numbers = match page.page_index {
        1 => [3_u64, 4],
        2 => [6_u64, 7],
        _ => return Err("unexpected supplementary page index".into()),
    };
    assert_eq!(packet_numbers, expected_numbers);
    assert_eq!(page.first_packet, u32::try_from(expected_numbers[0])?);
    assert_eq!(page.last_packet, u32::try_from(expected_numbers[1])?);
    assert_eq!(page.selected_records, 2);
    assert_eq!(page.retained_records, 2);
    assert_eq!(page.omitted_records, 0);
    assert!(!page.result.complete);
    assert!(!page.result.case.collection_complete());
    assert!(page.result.case.limitations().iter().any(|message| {
        message.contains("TCP/session/application state was not joined across page boundaries")
    }));
    assert_page_packet_ranges(store, source_id, &packet_records)?;
    Ok(())
}

fn assert_page_packet_ranges(
    store: &Store,
    source_id: &str,
    packet_records: &[&l2_workbench::evidence::Node],
) -> Result<(), Box<dyn Error>> {
    for node in packet_records {
        let number = node
            .details
            .get("record")
            .and_then(serde_json::Value::as_u64)
            .ok_or("packet record number is missing")?;
        let expected_range = store.packet(source_id, u32::try_from(number)?)?;
        assert_eq!(node.ranges, [expected_range.range]);
    }
    Ok(())
}

#[test]
fn flow_page_rejects_a_record_that_cannot_fit_by_itself() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let frames = [frames::tcp(false, 100, 0x18, b"too large")?];
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest("oversized-flow-page.pcap", Cursor::new(capture(&frames)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing TCP flow")?;
    let limits = Limits {
        bytes: frames
            .first()
            .ok_or("fixture frame is missing")?
            .bytes()
            .len()
            .checked_sub(1)
            .ok_or("fixture frame is empty")?,
        ..Limits::default()
    };

    let error = store
        .visit_flow_pages_after_prefix(flow, 0, limits, |_| Ok(()))
        .err()
        .ok_or("an oversized page record must return a typed error")?;

    assert!(error.downcast_ref::<FlowPageError>().is_some());
    assert!(error.to_string().contains("cannot fit one flow page"));
    Ok(())
}
