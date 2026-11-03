use super::{case_support::located_records, support::tcp};
use l2_capture::CaptureLocator;
use l2_workbench::{
    carrier::discovery::mapped_node,
    investigation::{BuildInput, build},
    sha256,
};
use std::error::Error;

#[test]
fn chunk_extensions_preserve_native_extraction_and_exact_source_ranges()
-> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2 ;a=\"b\\\"c\"\r\nDA\r\n2\t; b = value\r\nTA\r\n0 ;end\r\n\r\n";
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, payload)?,
    ])?;
    let result = build(BuildInput {
        label: "chunked.pcap",
        length,
        sha256_hex: &sha256(b"chunked source"),
        records: &records,
        frames_seen: 2,
    })?;
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing HTTP body")?;
    let mapped = mapped_node(&result.case, body.id)?;
    assert_eq!(mapped.bytes, b"DATA");
    assert_eq!(
        body.details.get("status"),
        Some(&serde_json::json!("complete"))
    );
    assert_eq!(
        body.details.get("framing_complete"),
        Some(&serde_json::json!(true))
    );

    let record = records.get(1).ok_or("missing data packet")?;
    let frame = record.frame.bytes();
    let frame_start = frame
        .windows(payload.len())
        .position(|window| window == payload)
        .ok_or("missing payload in packet")?;
    let Some(CaptureLocator::ClassicPcap { data_offset, .. }) = record.frame.metadata().locator()
    else {
        return Err("missing capture locator".into());
    };
    assert_eq!(mapped.mappings.len(), 2);
    for (mapping, (output_offset, piece)) in mapped
        .mappings
        .iter()
        .zip([(0, b"DA".as_slice()), (2, b"TA".as_slice())])
    {
        let payload_offset = payload
            .windows(piece.len())
            .position(|window| window == piece)
            .ok_or("missing data chunk")?;
        assert_eq!(mapping.offset, output_offset);
        assert_eq!(mapping.range.packet, Some(2));
        assert_eq!(mapping.range.length, u64::try_from(piece.len())?);
        assert_eq!(
            mapping.range.offset,
            data_offset + u64::try_from(frame_start + payload_offset)?
        );
    }
    result.case.validate()?;
    Ok(())
}
