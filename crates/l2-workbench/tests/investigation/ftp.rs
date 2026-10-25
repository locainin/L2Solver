use super::{
    case_support::located_records,
    support::{tcp, tcp_ports},
};
use l2_workbench::{
    investigation::{BuildInput, build},
    sha256,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn passive_retr_early_exact_argument() -> Result<(), Box<dyn Error>> {
    let command = b"RETR file.bin\r\n";
    let command_start = 107;
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(true, 200, 0x12, b"")?,
        tcp(false, 101, 0x18, b"EPSV\r\n")?,
        tcp(
            true,
            201,
            0x18,
            b"229 Entering Extended Passive Mode (|||10000|)\r\n",
        )?,
        tcp_ports(false, (40_001, 10_000), 500, 2, b"")?,
        tcp(false, command_start, 0x18, b"RETR ")?,
        tcp(false, command_start + 5, 0x18, b"file.bin\r\n")?,
        tcp(false, command_start, 0x18, command)?,
        tcp_ports(true, (40_001, 10_000), 600, 0x12, b"")?,
        tcp_ports(true, (40_001, 10_000), 601, 0x11, b"file contents")?,
    ])?;
    let result = build(BuildInput {
        label: "transfer.pcap",
        length,
        sha256_hex: &sha256(b"FTP source"),
        records: &records,
        frames_seen: 10,
    })?;
    let transfer = node(&result.case, "ftp_transfer_candidate")?;
    let data = node(&result.case, "ftp_data_candidate")?;
    let control = result
        .case
        .nodes()
        .iter()
        .find(|candidate| {
            candidate.kind == "ftp_control_candidate"
                && candidate.details.pointer("/event/kind/kind") == Some(&Value::from("transfer"))
        })
        .ok_or("missing FTP transfer control-line candidate")?;
    let run_id = data
        .details
        .get("tcp_byte_run_node")
        .and_then(Value::as_u64)
        .ok_or("data candidate does not reference its TCP run")?;
    let blob_id = run_blob_id(&result.case, run_id)?;
    let blob = run_blob(&result.case, blob_id)?;
    let filename = filename_argument(&result.case, transfer)?;

    assert_eq!(blob.bytes, b"file contents");
    assert_eq!(data.blob.as_deref(), Some(blob_id));
    assert_eq!(
        transfer.details.get("available_at_record"),
        Some(&Value::from(7))
    );
    assert_eq!(filename, b"file.bin");
    let supporting_packets: Vec<_> = control
        .ranges
        .iter()
        .filter_map(|range| range.packet)
        .collect();
    assert!(supporting_packets.contains(&6));
    assert!(supporting_packets.contains(&7));
    assert!(!supporting_packets.contains(&8));
    assert_eq!(
        transfer.details.get("transfer_accepted"),
        Some(&Value::from("unresolved"))
    );
    assert_eq!(
        data.details.get("transfer_accepted"),
        Some(&Value::from("unresolved"))
    );
    assert_eq!(
        data.details.get("complete_file"),
        Some(&Value::from("unresolved"))
    );
    assert_eq!(
        data.details.get("opened_before_transfer"),
        Some(&Value::from(true))
    );
    assert!(result.case.edges().iter().any(|edge| {
        edge.from == run_id && edge.to == data.id && edge.relation == "derived_from"
    }));
    Ok(())
}

#[test]
fn active_stor_bytes_advertised_endpoint() -> Result<(), Box<dyn Error>> {
    let port_command = b"PORT 192,0,2,1,4,210\r\n";
    let store_command = b"STOR output.bin\r\n";
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(true, 200, 0x12, b"")?,
        tcp(false, 101, 0x18, port_command)?,
        tcp(
            false,
            101 + u32::try_from(port_command.len())?,
            0x18,
            store_command,
        )?,
        tcp_ports(true, (1_234, 50_000), 500, 2, b"")?,
        tcp_ports(false, (50_000, 1_234), 600, 0x12, b"")?,
        tcp_ports(false, (1_234, 50_000), 601, 0x11, b"upload payload")?,
    ])?;
    let result = build(BuildInput {
        label: "active-transfer.pcap",
        length,
        sha256_hex: &sha256(b"active FTP source"),
        records: &records,
        frames_seen: 7,
    })?;
    let data = node(&result.case, "ftp_data_candidate")?;
    let run_id = data
        .details
        .get("tcp_byte_run_node")
        .and_then(Value::as_u64)
        .ok_or("data candidate does not reference its TCP run")?;
    let run = result
        .case
        .nodes()
        .iter()
        .find(|candidate| candidate.id == run_id)
        .ok_or("missing referenced TCP run")?;
    let blob_id = run.blob.as_deref().ok_or("TCP run has no byte blob")?;
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|candidate| candidate.id == blob_id)
        .ok_or("missing TCP run blob")?;

    assert_eq!(blob.bytes, b"upload payload");
    assert_eq!(data.blob.as_deref(), Some(blob_id));
    assert_eq!(data.details.get("mode"), Some(&Value::from("active")));
    assert_eq!(data.details.get("action"), Some(&Value::from("store")));
    Ok(())
}

fn node<'a>(
    case: &'a l2_workbench::evidence::Case,
    kind: &str,
) -> Result<&'a l2_workbench::evidence::Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|candidate| candidate.kind == kind)
        .ok_or_else(|| format!("missing {kind} node").into())
}

fn run_blob_id(case: &l2_workbench::evidence::Case, run_id: u64) -> Result<&str, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|candidate| candidate.id == run_id)
        .and_then(|run| run.blob.as_deref())
        .ok_or_else(|| "missing TCP run blob reference".into())
}

fn run_blob<'a>(
    case: &'a l2_workbench::evidence::Case,
    blob_id: &str,
) -> Result<&'a l2_workbench::evidence::Blob, Box<dyn Error>> {
    case.blobs()
        .iter()
        .find(|candidate| candidate.id == blob_id)
        .ok_or_else(|| "missing TCP run blob".into())
}

fn filename_argument(
    case: &l2_workbench::evidence::Case,
    transfer: &l2_workbench::evidence::Node,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let argument_node_id = transfer
        .details
        .get("filename_argument_node")
        .and_then(Value::as_u64)
        .ok_or("transfer has no filename argument node")?;
    let argument_node = case
        .nodes()
        .iter()
        .find(|candidate| candidate.id == argument_node_id)
        .ok_or("missing filename argument node")?;
    let run_id = argument_node
        .details
        .get("tcp_byte_run_node")
        .and_then(Value::as_u64)
        .ok_or("filename argument does not reference its TCP run")?;
    let blob_id = run_blob_id(case, run_id)?;
    if argument_node.blob.as_deref() != Some(blob_id) {
        return Err("filename argument copied rather than referenced its TCP run".into());
    }
    let blob = run_blob(case, blob_id)?;
    let range = argument_node
        .details
        .get("run_range")
        .ok_or("filename argument has no TCP-run range")?;
    let offset = usize::try_from(
        range
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or("filename argument range has no offset")?,
    )?;
    let length = usize::try_from(
        range
            .get("length")
            .and_then(Value::as_u64)
            .ok_or("filename argument range has no length")?,
    )?;
    let end = offset
        .checked_add(length)
        .ok_or("filename argument range overflow")?;
    Ok(blob
        .bytes
        .get(offset..end)
        .ok_or("filename argument exceeds the TCP run")?
        .to_vec())
}
