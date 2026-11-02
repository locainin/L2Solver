use super::{cooked_fixture, dns, support::capture, udp};
use l2_capture::{CapturedFrame, InterfaceId};
use l2_workbench::{
    evidence::{
        Case, MAX_NODES, MAX_TOTAL_DETAILS_BYTES, ReceiptVerificationLimits,
        verify_index_flow_selection,
    },
    reconstruction::Limits,
    store::{Options, Store},
};
use std::{error::Error, io::Cursor};

fn cooked_capture(frame: &CapturedFrame, count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let frames = vec![frame.clone(); count];
    let mut bytes = capture(&frames)?;
    // The shared classic fixture supplies the records; the global header identifies SLL1
    bytes
        .get_mut(20..24)
        .ok_or("short capture header")?
        .copy_from_slice(&113_u32.to_le_bytes());
    Ok(bytes)
}

fn assert_partial_scope(case: &Case, count: usize) -> Result<(), Box<dyn Error>> {
    assert!(!case.collection_complete());
    assert!(
        case.nodes()
            .iter()
            .any(|node| node.kind == "capture_collection_summary")
    );
    let selection = case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or("missing flow selection receipt")?;
    let verified =
        verify_index_flow_selection(case, selection.id, ReceiptVerificationLimits::default())?;
    assert!(verified.verified);
    assert_eq!(verified.retained_input_records, u64::try_from(count)?);
    case.validate()?;
    Ok(())
}

#[test]
fn saturated_selected_flow_keeps_scope_and_collection_receipts() -> Result<(), Box<dyn Error>> {
    let frame = cooked_fixture::cooked(
        udp(false, &dns(false))?.bytes(),
        113,
        InterfaceId {
            section: 0,
            index: 0,
        },
        0,
    )?;
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let baseline = store.ingest("baseline.pcap", Cursor::new(cooked_capture(&frame, 1)?))?;
    let baseline_flow = store
        .packet(&baseline.source_id, 1)?
        .flow
        .ok_or("missing baseline flow")?;
    let baseline_case = store.investigate_flow(baseline_flow)?;
    let packet = baseline_case
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "packet")
        .ok_or("missing baseline packet")?;
    let detail_bytes = serde_json::to_vec(&packet.details)?.len();
    // Later record numbers and offsets only increase the packet details length
    let count = MAX_TOTAL_DETAILS_BYTES
        .checked_div(detail_bytes)
        .ok_or("empty packet details")?
        + 1;
    assert!(
        count + 16 < MAX_NODES,
        "fixture must reach the details limit before the node limit"
    );
    let source = store.ingest("bulk.pcap", Cursor::new(cooked_capture(&frame, count)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("missing bulk flow")?;
    let limits = Limits {
        frames: u64::try_from(count)?,
        units: count,
        bytes: frame
            .captured_len()
            .checked_mul(count)
            .ok_or("capture size overflow")?,
        ..Limits::default()
    };
    let result = store.investigate_flows(&[flow], limits)?;
    assert!(!result.complete);
    assert_partial_scope(&result.case, count)?;
    assert!(
        result
            .case
            .limitations()
            .iter()
            .any(|text| text.contains("evidence resource budget"))
    );
    drop(result);

    // Page scope metadata must survive the same saturated analysis budget
    let mut pages = 0;
    let coverage = store.visit_flow_pages_after_prefix(flow, 0, limits, |page| {
        pages += 1;
        assert!(!page.result.complete);
        assert_partial_scope(&page.result.case, count)?;
        assert!(
            page.result
                .case
                .nodes()
                .iter()
                .any(|node| node.kind == "index_flow_page")
        );
        Ok(())
    })?;
    assert_eq!(pages, 1);
    assert_eq!(coverage.retained_records, u64::try_from(count)?);
    Ok(())
}
