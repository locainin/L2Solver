use super::support::{path_arg, run};
use serde_json::{Value, json};
use std::{error::Error, fs, path::PathBuf};

struct IndexedMessageFixture {
    _temporary: tempfile::TempDir,
    index: PathBuf,
    plan: PathBuf,
    flow_id: String,
    source_id: String,
}

#[test]
fn indexed_messages_segmented_tcp_input() -> Result<(), Box<dyn Error>> {
    let fixture = indexed_messages_fixture()?;
    for (packet, expected_payload) in [(4, b"abc\n".as_slice()), (5, b"def\n".as_slice())] {
        let packet_argument = packet.to_string();
        let indexed_packet = run(
            &[
                "indexed",
                path_arg(&fixture.index)?,
                "packet",
                "--source",
                &fixture.source_id,
                &packet_argument,
            ],
            b"",
        )?;
        assert!(
            indexed_packet.status.success(),
            "{}",
            String::from_utf8_lossy(&indexed_packet.stderr)
        );
        assert_eq!(indexed_packet.stdout.get(54..58), Some(expected_payload));
    }
    let result = run(
        &[
            "indexed",
            path_arg(&fixture.index)?,
            "messages",
            &fixture.flow_id,
            "--plan",
            path_arg(&fixture.plan)?,
        ],
        b"",
    )?;

    assert!(
        result.status.success(),
        "status={} stderr={} stdout={}",
        result.status,
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout),
    );
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(
        report.pointer("/frames/0/bytes"),
        Some(&json!([97, 98, 99, 10]))
    );
    assert_eq!(
        report.pointer("/frames/1/bytes"),
        Some(&json!([100, 101, 102, 10]))
    );
    assert_eq!(
        report.pointer("/frames/0/origins/0/packet"),
        Some(&json!(4))
    );
    assert_eq!(
        report.pointer("/frames/1/origins/0/packet"),
        Some(&json!(5))
    );
    assert_eq!(report.pointer("/frames/0/role"), Some(&Value::Null));
    assert_eq!(report.pointer("/partial"), Some(&json!(false)));
    Ok(())
}

fn indexed_messages_fixture() -> Result<IndexedMessageFixture, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("messages.pcap");
    let index = temporary.path().join("index");
    let plan = temporary.path().join("workflow.json");
    fs::write(&capture, segmented_tcp_capture()?)?;
    fs::write(
        &plan,
        serde_json::to_vec(&json!({
            "framing_candidates": [{"kind": "delimiter", "byte": 10}],
            "search_plan": {
                "families": [{"kind": "reverse"}],
                "constraints": [{"kind": "length", "bytes": 4}],
                "max_depth": 1,
                "max_candidates": 4
            }
        }))?,
    )?;
    let indexed = run(
        &[
            "index",
            path_arg(&capture)?,
            "--directory",
            path_arg(&index)?,
        ],
        b"",
    )?;
    assert!(
        indexed.status.success(),
        "{}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let flow_listing = run(&["indexed", path_arg(&index)?, "flows"], b"")?;
    assert!(flow_listing.status.success());
    let flow: Value = serde_json::from_slice(
        flow_listing
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .ok_or("indexed flow listing is empty")?,
    )?;
    let flow_id = flow
        .get("id")
        .and_then(Value::as_i64)
        .ok_or("indexed flow lacks its stable ID")?;
    let source_id = flow
        .get("source_id")
        .and_then(Value::as_str)
        .ok_or("indexed flow lacks its source identity")?;
    Ok(IndexedMessageFixture {
        _temporary: temporary,
        index,
        plan,
        flow_id: flow_id.to_string(),
        source_id: source_id.to_owned(),
    })
}

fn segmented_tcp_capture() -> Result<Vec<u8>, Box<dyn Error>> {
    classic_pcap(&[
        tcp_frame(false, 1_000, 0, 0x02, b"")?,
        tcp_frame(true, 5_000, 1_001, 0x12, b"")?,
        tcp_frame(false, 1_001, 5_001, 0x10, b"")?,
        tcp_frame(false, 1_001, 5_001, 0x18, b"abc\n")?,
        tcp_frame(false, 1_005, 5_001, 0x18, b"def\n")?,
        tcp_frame(false, 1_009, 5_001, 0x11, b"")?,
        tcp_frame(true, 5_001, 1_010, 0x11, b"")?,
        tcp_frame(false, 1_010, 5_002, 0x10, b"")?,
    ])
}

fn classic_pcap(frames: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(index)?.to_le_bytes());
        let length = u32::try_from(frame.len())?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(frame);
    }
    Ok(bytes)
}

fn tcp_frame(
    reverse: bool,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let tcp_length = 20 + payload.len();
    let ip_length = 20 + tcp_length;
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&u16::try_from(ip_length)?.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 6, 0, 0]);
    let (source, destination, source_port, destination_port) = if reverse {
        ([192, 0, 2, 20], [192, 0, 2, 10], 443_u16, 40_000_u16)
    } else {
        ([192, 0, 2, 10], [192, 0, 2, 20], 40_000_u16, 443_u16)
    };
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&acknowledgement.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags]);
    frame.extend_from_slice(&1024_u16.to_be_bytes());
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(payload);
    Ok(frame)
}
