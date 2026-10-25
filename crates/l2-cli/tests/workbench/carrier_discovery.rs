use super::support::{path_arg, run};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, SourceRange};
use serde_json::{Value, json};
use std::{error::Error, fs, path::PathBuf};

#[path = "../../../../tests/fixtures/carrier_bit_planes.rs"]
mod carrier_bit_planes;

use carrier_bit_planes::printable_bit_planes;

struct PacketCaseFixture {
    case_path: PathBuf,
    source_paths: Vec<PathBuf>,
    node_ids: Vec<u64>,
}

fn tcp_frame(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let tcp_length = 20 + payload.len();
    let ip_length = 20 + tcp_length;
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&u16::try_from(ip_length)?.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 6, 0, 0]);
    frame.extend_from_slice(&[192, 0, 2, 10]);
    frame.extend_from_slice(&[192, 0, 2, 20]);
    frame.extend_from_slice(&40000_u16.to_be_bytes());
    frame.extend_from_slice(&443_u16.to_be_bytes());
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x18]);
    frame.extend_from_slice(&1024_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn save_case_with_packets(
    directory: &std::path::Path,
    payloads: &[&[u8]],
) -> Result<PacketCaseFixture, Box<dyn Error>> {
    let frames = payloads
        .iter()
        .map(|payload| tcp_frame(payload))
        .collect::<Result<Vec<_>, _>>()?;
    let mut capture = Vec::new();
    let mut offsets = Vec::new();
    for frame in &frames {
        offsets.push(capture.len());
        capture.extend_from_slice(frame);
    }
    let capture_path = directory.join("capture.bin");
    fs::write(&capture_path, &capture)?;

    let mut case = Case::new();
    let source_id = case.add_source(
        "capture.bin",
        "capture",
        u64::try_from(capture.len())?,
        &l2_workbench::sha256(&capture),
        None,
    )?;
    let episode_ids = (0..payloads.len())
        .map(|index| {
            case.add_node(
                "tcp_episode",
                None,
                Vec::new(),
                json!({
                    "scope":"capture/interface-0",
                    "generation_ambiguous":false,
                    "episode_index":index
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let node_ids = add_packet_nodes(&mut case, &frames, &offsets, &source_id, &episode_ids)?;
    let case_path = directory.join("case.json");
    fs::write(&case_path, case.to_json()?)?;
    Ok(PacketCaseFixture {
        case_path,
        source_paths: vec![capture_path],
        node_ids,
    })
}

fn add_packet_nodes(
    case: &mut Case,
    frames: &[Vec<u8>],
    offsets: &[usize],
    source_id: &str,
    episode_ids: &[u64],
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut node_ids = Vec::with_capacity(frames.len());
    for (index, frame) in frames.iter().enumerate() {
        let packet_number = u64::try_from(index + 1)?;
        let offset = u64::try_from(
            *offsets
                .get(index)
                .ok_or("packet fixture is missing its source offset")?,
        )?;
        let frame_length = u64::try_from(frame.len())?;
        let node_id = case.add_bytes_node(
            "packet",
            frame,
            vec![SourceRange {
                source: source_id.to_owned(),
                packet: Some(packet_number),
                offset,
                length: frame_length,
            }],
            json!({
                "link_type": 1,
                "record": packet_number,
                "scope": "capture/interface-0/vlan-none",
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "source_port": 40000,
                "destination_port": 443,
                "truncated": false,
                "fragmented": false
            }),
        )?;
        let episode = *episode_ids
            .get(index)
            .ok_or("packet fixture is missing its episode")?;
        case.add_edge(Edge {
            from: node_id,
            to: episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "packet belongs to one fixture session".to_owned(),
        })?;
        node_ids.push(node_id);
    }
    Ok(node_ids)
}

fn write_discovery_plan(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "widths": [7, 8],
            "phases": [0],
            "start_offsets": [0, 1],
            "reset_modes": ["per_sample"],
            "sample_orders": ["input_order"],
            "remainder": "reject",
            "max_input_bytes": 1024,
            "max_work_bytes": 4096,
            "max_candidates": 1,
            "minimum_printable_run_bytes": 4,
            "max_report_bytes": 4096,
            "constraints": [{"kind":"length", "bytes":4}, {"kind":"utf8"}]
        }))?,
    )?;
    Ok(())
}

#[test]
fn carrier_plan_source_mapping_replays() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = save_case_with_packets(directory.path(), &[b"abcd"])?;
    let node_id = *fixture
        .node_ids
        .first()
        .ok_or("packet fixture has no selected node")?;
    let source_path = fixture
        .source_paths
        .first()
        .ok_or("packet fixture has no source file")?;
    let generated = run(
        &[
            "carrier-plan",
            path_arg(&fixture.case_path)?,
            "--node",
            &node_id.to_string(),
            "--view",
            "payload",
            "--source",
            path_arg(source_path)?,
        ],
        b"",
    )?;
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let plan: Value = serde_json::from_slice(&generated.stdout)?;
    let expected_source_path = source_path.canonicalize()?;
    assert_eq!(
        plan.pointer("/sources/0/path"),
        Some(&json!(
            expected_source_path
                .to_str()
                .ok_or("source path is not Unicode")?
        ))
    );
    assert_eq!(plan.pointer("/samples/0/id"), Some(&json!(node_id)));
    assert_eq!(plan.pointer("/samples/0/length"), Some(&json!(4)));
    assert_eq!(
        plan.pointer("/samples/0/mappings/0/range/offset"),
        Some(&json!(54))
    );
    assert_eq!(
        plan.pointer("/samples/0/mappings/0/range/length"),
        Some(&json!(4))
    );
    assert_eq!(plan.pointer("/rules/0/kind"), Some(&json!("bytes")));

    let plan_path = directory.path().join("carrier-plan.json");
    fs::write(&plan_path, generated.stdout)?;
    let replay = run(&["carrier", path_arg(&plan_path)?], b"")?;
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let report: Value = serde_json::from_slice(&replay.stdout)?;
    assert_eq!(
        report.pointer("/extraction/observations/0/value/bytes"),
        Some(&json!([97, 98, 99, 100]))
    );
    assert_eq!(
        report.pointer("/extraction/observations/0/ranges/0/offset"),
        Some(&json!(54))
    );
    Ok(())
}

#[test]
fn carrier_plan_without_publishing() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = save_case_with_packets(directory.path(), &[b"abcd"])?;
    let node_id = *fixture
        .node_ids
        .first()
        .ok_or("packet fixture has no selected node")?;
    let wrong_path = directory.path().join("wrong.bin");
    fs::write(&wrong_path, b"other input")?;

    let generated = run(
        &[
            "carrier-plan",
            path_arg(&fixture.case_path)?,
            "--node",
            &node_id.to_string(),
            "--view",
            "payload",
            "--source",
            path_arg(&wrong_path)?,
        ],
        b"",
    )?;

    assert!(!generated.status.success());
    assert!(generated.stdout.is_empty());
    Ok(())
}

#[test]
fn carrier_plan_disagree_retained_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = save_case_with_packets(directory.path(), &[b"abcd", b"later"])?;
    let node_id = *fixture
        .node_ids
        .first()
        .ok_or("packet fixture has no selected node")?;
    let source_path = fixture
        .source_paths
        .first()
        .ok_or("packet fixture has no source file")?;
    let mut case: Value = serde_json::from_slice(&fs::read(&fixture.case_path)?)?;
    let selected = case
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .find(|node| node.get("id") == Some(&json!(node_id)))
        })
        .ok_or("selected packet node is missing")?;
    let offset = selected
        .get_mut("ranges")
        .and_then(Value::as_array_mut)
        .and_then(|ranges| ranges.first_mut())
        .and_then(|range| range.get_mut("offset"))
        .ok_or("selected packet range offset is missing")?;
    *offset = json!(1);
    let contradictory_case = directory.path().join("contradictory-case.json");
    fs::write(&contradictory_case, serde_json::to_vec(&case)?)?;

    let generated = run(
        &[
            "carrier-plan",
            path_arg(&contradictory_case)?,
            "--node",
            &node_id.to_string(),
            "--view",
            "bytes",
            "--source",
            path_arg(source_path)?,
        ],
        b"",
    )?;

    assert!(!generated.status.success());
    assert!(generated.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&generated.stderr).contains("do not match retained node bytes")
    );
    Ok(())
}

#[test]
fn carrier_discovery_controls_partial_budgets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = save_case_with_packets(directory.path(), &[b"abcd", b"wxyz"])?;
    let plan_path = directory.path().join("discovery-plan.json");
    write_discovery_plan(&plan_path)?;
    let mut args = vec![
        "carrier-discover".to_owned(),
        path_arg(&fixture.case_path)?.to_owned(),
        "--view".to_owned(),
        "payload".to_owned(),
        "--plan".to_owned(),
        path_arg(&plan_path)?.to_owned(),
    ];
    for node_id in &fixture.node_ids {
        args.push("--node".to_owned());
        args.push(node_id.to_string());
    }
    let borrowed: Vec<_> = args.iter().map(String::as_str).collect();

    let output = run(&borrowed, b"")?;

    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/input_bytes"), Some(&json!(8)));
    assert_eq!(report.pointer("/input_budget_bytes"), Some(&json!(1024)));
    assert_eq!(report.pointer("/work_budget_bytes"), Some(&json!(4096)));
    assert_eq!(report.pointer("/candidate_budget"), Some(&json!(1)));
    assert_eq!(report.pointer("/parameter_space_size"), Some(&json!(4)));
    assert_eq!(report.pointer("/attempted_parameters"), Some(&json!(1)));
    assert_eq!(report.pointer("/enumeration_complete"), Some(&json!(false)));
    assert_eq!(report.pointer("/limits/0"), Some(&json!("candidate_count")));
    assert_eq!(report.pointer("/candidates/0/width"), Some(&json!(7)));
    assert_eq!(
        report.pointer("/candidates/0/source_byte_offset"),
        Some(&json!(0))
    );
    assert_eq!(
        report.pointer("/candidates/0/control/unit_count"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/sample_receipts/0/mappings/0/range/offset"),
        Some(&json!(54))
    );
    Ok(())
}

struct CarrierResultsFixture {
    case_path: PathBuf,
    node_id: u64,
    plan_path: PathBuf,
    result_directory: PathBuf,
}

fn write_durable_plan(
    path: &std::path::Path,
    widths: &[u8],
    phases: &[u8],
    max_candidates: usize,
) -> Result<(), Box<dyn Error>> {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "widths": widths,
            "phases": phases,
            "start_offsets": [0],
            "reset_modes": ["per_sample"],
            "sample_orders": ["input_order"],
            "remainder": "reject",
            "max_input_bytes": 1024,
            "max_work_bytes": 4096,
            "max_candidates": max_candidates,
            "minimum_printable_run_bytes": 4,
            "max_report_bytes": 1,
            "constraints": []
        }))?,
    )?;
    Ok(())
}

fn carrier_results_fixture(
    directory: &std::path::Path,
) -> Result<CarrierResultsFixture, Box<dyn Error>> {
    let payload = printable_bit_planes()?;
    let packet_fixture = save_case_with_packets(directory, &[&payload])?;
    let node_id = *packet_fixture
        .node_ids
        .first()
        .ok_or("packet fixture has no selected node")?;
    let plan_path = directory.join("durable-discovery-plan.json");
    write_durable_plan(&plan_path, &[8], &[0, 7], 2)?;
    let result_directory = directory.join("carrier-results");
    let plan_arg = path_arg(&plan_path)?;
    let case_arg = path_arg(&packet_fixture.case_path)?;
    let results_arg = path_arg(&result_directory)?;
    let node_arg = node_id.to_string();
    let discovered = run(
        &[
            "carrier-results",
            "discover",
            case_arg,
            "--node",
            &node_arg,
            "--view",
            "payload",
            "--plan",
            plan_arg,
            "--directory",
            results_arg,
            "--max-output-bytes",
            "1024",
            "--max-disk-bytes",
            "1048576",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(
        discovered.status.success(),
        "{}",
        String::from_utf8_lossy(&discovered.stderr)
    );
    let summary: Value = serde_json::from_slice(&discovered.stdout)?;
    assert_eq!(summary.pointer("/candidate_count"), Some(&json!(2)));
    assert_eq!(summary.pointer("/printable_run_count"), Some(&json!(2)));
    Ok(CarrierResultsFixture {
        case_path: packet_fixture.case_path,
        node_id,
        plan_path,
        result_directory,
    })
}

#[test]
fn carrier_discover_defaults_text() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let payload = printable_bit_planes()?;
    let packet_fixture = save_case_with_packets(directory.path(), &[&payload])?;
    let node_id = *packet_fixture
        .node_ids
        .first()
        .ok_or("packet fixture has no selected node")?;
    let plan_path = directory.path().join("durable-discovery-plan.json");
    write_durable_plan(&plan_path, &[8], &[0, 7], 2)?;
    let result_directory = directory.path().join("carrier-results");

    let output = run(
        &[
            "carrier-results",
            "discover",
            path_arg(&packet_fixture.case_path)?,
            "--node",
            &node_id.to_string(),
            "--view",
            "payload",
            "--plan",
            path_arg(&plan_path)?,
            "--directory",
            path_arg(&result_directory)?,
            "--max-output-bytes",
            "1024",
            "--max-disk-bytes",
            "1048576",
        ],
        b"",
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains(&format!(
        "Created carrier results directory: {}",
        result_directory.display()
    )));
    assert!(text.contains("Candidates: 2; printable runs: 2; enumeration: complete"));
    assert!(result_directory.join("manifest.json").is_file());
    Ok(())
}

#[test]
fn carrier_results_publish_list_candidates() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = carrier_results_fixture(directory.path())?;
    let results_arg = path_arg(&fixture.result_directory)?;
    let listed = run(
        &["carrier-results", "list", results_arg, "--limit", "1"],
        b"",
    )?;
    assert!(listed.status.success());
    let listing_text = String::from_utf8(listed.stdout)?;
    assert!(listing_text.contains("candidate 0"));
    assert!(listing_text.contains("parameter combinations"));
    assert!(!listing_text.contains("SHA-256"));
    assert!(!listing_text.contains("SHA-256="));

    let listed_json = run(
        &[
            "carrier-results",
            "list",
            results_arg,
            "--limit",
            "1",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(listed_json.status.success());
    let listing: Value = serde_json::from_slice(&listed_json.stdout)?;
    assert_eq!(listing.pointer("/page/rows/0/id"), Some(&json!(0)));
    assert_eq!(listing.pointer("/page/next_after"), Some(&json!(0)));
    assert!(listing.pointer("/summary/plan_sha256").is_some());
    assert!(listing.pointer("/summary/result_sha256").is_some());
    assert!(
        listing
            .pointer("/page/rows/0/discovery/output_sha256")
            .is_some()
    );
    Ok(())
}

#[test]
fn carrier_results_sources_exact_mappings() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = carrier_results_fixture(directory.path())?;
    let results_arg = path_arg(&fixture.result_directory)?;
    assert_carrier_result_detail_formats(results_arg)?;
    assert_carrier_result_source_receipt(results_arg)?;
    assert_carrier_result_export(directory.path(), results_arg)?;
    Ok(())
}

fn assert_carrier_result_detail_formats(results_arg: &str) -> Result<(), Box<dyn Error>> {
    let shown = run(
        &[
            "carrier-results",
            "show",
            results_arg,
            "0",
            "--partition",
            "discovery",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(shown.status.success());
    let detail: Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(detail.pointer("/runs/rows/0/text"), Some(&json!("EARLY")));

    let shown_html = run(
        &[
            "carrier-results",
            "show",
            results_arg,
            "0",
            "--partition",
            "discovery",
            "--format",
            "html",
        ],
        b"",
    )?;
    assert!(shown_html.status.success());
    let shown_html = String::from_utf8(shown_html.stdout)?;
    assert!(shown_html.contains("<!doctype html>"));
    assert!(shown_html.contains("candidate 0"));
    assert!(shown_html.contains("source-bit map"));
    assert!(!shown_html.contains("SHA-256"));

    let shown_text = run(
        &[
            "carrier-results",
            "show",
            results_arg,
            "0",
            "--partition",
            "discovery",
        ],
        b"",
    )?;
    assert!(shown_text.status.success());
    let shown_text = String::from_utf8(shown_text.stdout)?;
    assert!(shown_text.contains("candidate 0"));
    assert!(shown_text.contains("printable run"));

    Ok(())
}

fn assert_carrier_result_source_receipt(results_arg: &str) -> Result<(), Box<dyn Error>> {
    let sources = run(
        &[
            "carrier-results",
            "sources",
            results_arg,
            "--after-sample-id",
            "0",
            "--limit",
            "1",
        ],
        b"",
    )?;
    assert!(sources.status.success());
    let sources = String::from_utf8(sources.stdout)?;
    assert!(sources.contains("source receipt"));
    assert!(sources.contains("partition=Discovery"));
    assert!(sources.contains("offset=54"));
    assert!(!sources.contains("SHA-256="));

    let sources_json = run(
        &[
            "carrier-results",
            "sources",
            results_arg,
            "--after-sample-id",
            "0",
            "--limit",
            "1",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(sources_json.status.success());
    let source_report: Value = serde_json::from_slice(&sources_json.stdout)?;
    assert!(source_report.pointer("/page/rows/0/input_sha256").is_some());

    Ok(())
}

fn assert_carrier_result_export(
    directory: &std::path::Path,
    results_arg: &str,
) -> Result<(), Box<dyn Error>> {
    let exported_path = directory.join("candidate.bin");
    let exported = run(
        &[
            "carrier-results",
            "export",
            results_arg,
            "1",
            "--partition",
            "discovery",
            "--output",
            path_arg(&exported_path)?,
        ],
        b"",
    )?;
    assert!(exported.status.success());
    assert_eq!(fs::read(exported_path)?, b"LATER");
    Ok(())
}

#[test]
fn carrier_results_identity_no_overwrite() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = carrier_results_fixture(directory.path())?;
    let case_arg = path_arg(&fixture.case_path)?;
    let results_arg = path_arg(&fixture.result_directory)?;
    let plan_arg = path_arg(&fixture.plan_path)?;
    let node_arg = fixture.node_id.to_string();
    let replayed = run(
        &[
            "carrier-results",
            "replay",
            case_arg,
            "--node",
            &node_arg,
            "--view",
            "payload",
            "--plan",
            plan_arg,
            "--directory",
            results_arg,
            "0",
        ],
        b"",
    )?;
    assert!(replayed.status.success());

    write_durable_plan(&fixture.plan_path, &[7], &[0], 1)?;
    let changed_plan = run(
        &[
            "carrier-results",
            "replay",
            case_arg,
            "--node",
            &node_arg,
            "--view",
            "payload",
            "--plan",
            plan_arg,
            "--directory",
            results_arg,
            "0",
        ],
        b"",
    )?;
    assert!(!changed_plan.status.success());

    let duplicate_destination = run(
        &[
            "carrier-results",
            "discover",
            case_arg,
            "--node",
            &node_arg,
            "--view",
            "payload",
            "--plan",
            plan_arg,
            "--directory",
            results_arg,
        ],
        b"",
    )?;
    assert!(!duplicate_destination.status.success());
    Ok(())
}
