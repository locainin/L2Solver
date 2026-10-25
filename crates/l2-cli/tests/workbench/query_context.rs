use super::support::{empty_capture, ipv4_header_frame, path_arg, run};
use l2_workbench::evidence::Case;
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

#[path = "../capture_tcp/frame.rs"]
mod tcp_support;

const MANIFEST_LIMITATION: &str = "Acquisition note retained only in the bundle manifest";

fn capture_with_context_only_tcp_run() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = empty_capture();
    let tcp = tcp_support::frame(100, 0x02, b"abc", Vec::new(), 0)?;
    append_record(&mut bytes, tcp.bytes(), 1)?;
    append_record(
        &mut bytes,
        &ipv4_header_frame([192, 0, 2, 2], [192, 0, 2, 1]),
        2,
    )?;
    Ok(bytes)
}

fn append_record(bytes: &mut Vec<u8>, frame: &[u8], timestamp: u32) -> Result<(), Box<dyn Error>> {
    let length = u32::try_from(frame.len())?;
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(frame);
    Ok(())
}

fn stream_bundle(input: &Path, bundle: &Path, capture: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(input, capture)?;
    let streamed = run(
        &[
            "stream",
            path_arg(input)?,
            "--directory",
            path_arg(bundle)?,
            "--page-records",
            "1",
            "--context-records",
            "1",
        ],
        b"",
    )?;
    if !streamed.status.success() {
        return Err(String::from_utf8_lossy(&streamed.stderr)
            .into_owned()
            .into());
    }
    Ok(())
}

fn first_page_tcp_run_id(bundle: &Path) -> Result<u64, Box<dyn Error>> {
    let first_page = Case::from_json(&fs::read(bundle.join("pages/000001.json"))?)?;
    let second_page = Case::from_json(&fs::read(bundle.join("pages/000002.json"))?)?;
    let first_run = first_page
        .nodes()
        .iter()
        .find(|node| node.kind == "tcp_byte_run")
        .ok_or("first page did not retain the TCP byte run")?;
    assert!(
        second_page
            .nodes()
            .iter()
            .any(|node| node.kind == "tcp_byte_run"),
        "second page should retain the run as context"
    );
    Ok(first_run.id)
}

fn add_manifest_limitation(bundle: &Path) -> Result<(), Box<dyn Error>> {
    let mut manifest: Value = serde_json::from_slice(&fs::read(bundle.join("manifest.json"))?)?;
    manifest
        .get_mut("limitations")
        .and_then(Value::as_array_mut)
        .ok_or("bundle manifest has no limitations array")?
        .push(json!(MANIFEST_LIMITATION));
    fs::write(bundle.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    Ok(())
}

fn assert_query_results(bundle: &Path, first_run_id: u64) -> Result<(), Box<dyn Error>> {
    let json_output = run(
        &[
            "query",
            path_arg(bundle)?,
            "--filter",
            "kind=tcp_byte_run",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(
        json_output.status.success(),
        "{}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let report: Value = serde_json::from_slice(&json_output.stdout)?;
    assert_eq!(report.get("matched_nodes"), Some(&json!(1)));
    assert_eq!(
        report.pointer("/matches/0/page"),
        Some(&json!("pages/000001.json"))
    );
    assert_eq!(
        report.pointer("/matches/0/node_id"),
        Some(&json!(first_run_id))
    );
    assert_eq!(
        report.pointer("/matches/0/packet_numbers"),
        Some(&json!([1]))
    );
    assert!(
        report
            .pointer("/inventory/bundle_limitations")
            .and_then(Value::as_array)
            .is_some_and(|limitations| limitations.contains(&json!(MANIFEST_LIMITATION))),
        "query inventory omitted the manifest-only limitation"
    );

    for format in ["text", "html"] {
        let output = run(&["query", path_arg(bundle)?, "--format", format], b"")?;
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8(output.stdout)?;
        assert!(
            rendered.contains(MANIFEST_LIMITATION),
            "{format} omitted the manifest-only limitation"
        );
    }
    Ok(())
}

#[test]
fn bundle_query_derived_manifest_limitations() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = capture_with_context_only_tcp_run()?;
    let input = directory.path().join("input.pcap");
    let bundle = directory.path().join("bundle");
    stream_bundle(&input, &bundle, &capture)?;
    let first_run_id = first_page_tcp_run_id(&bundle)?;
    add_manifest_limitation(&bundle)?;
    assert_query_results(&bundle, first_run_id)?;
    Ok(())
}
