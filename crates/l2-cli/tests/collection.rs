#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use std::{error::Error, process::Command};

#[test]
fn saved_incomplete_basic_replay_command() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("incomplete.pcapng");
    let report = l2_pcap::CollectionReport::new(
        l2_pcap::CollectionStopReason::Deadline,
        l2_pcap::CollectionGoal::Packets,
        10,
        2,
        3,
        false,
    );
    let mut writer =
        l2_pcap::PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, report)?;
    writer.finish()?;
    std::fs::write(&path, writer.into_inner())?;
    for command in ["inspect", "json", "observe"] {
        let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg(command)
            .arg(&path)
            .output()?;
        assert_eq!(
            result.status.code(),
            Some(3),
            "{command}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let rendered = String::from_utf8(result.stdout)?;
        assert!(rendered.contains("source_collection"), "{command}");
        if command == "json" {
            let value: serde_json::Value = serde_json::from_str(&rendered)?;
            assert_eq!(
                value.pointer("/source_collection/incomplete_sections"),
                Some(&serde_json::json!(1))
            );
            assert_eq!(
                value.pointer("/source_collection/capture_dropped"),
                Some(&serde_json::json!(2))
            );
        }
    }
    let built = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "build"])
        .arg(&path)
        .output()?;
    assert_eq!(
        built.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let case = l2_workbench::evidence::Case::from_json(&built.stdout)?;
    assert!(!case.collection_complete());
    assert!(
        case.nodes()
            .iter()
            .any(|node| node.kind == "capture_collection_summary")
    );
    Ok(())
}

#[test]
fn paged_cases_conditions_conflicting_manifest() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.pcapng");
    let report = l2_pcap::CollectionReport::new(
        l2_pcap::CollectionStopReason::Deadline,
        l2_pcap::CollectionGoal::Packets,
        10,
        2,
        3,
        false,
    );
    let packet = l2_pcap::CaptureReader::new(crate::captures::LLDP)?
        .next_packet()?
        .ok_or("missing fixture packet")?;
    let time = packet
        .metadata()
        .timestamp()
        .ok_or("missing packet clock")?;
    let config = l2_pcap::InterfaceConfig::new(
        65_535,
        time.resolution(),
        time.offset_seconds(),
        packet.metadata().fcs(),
    )?;
    let mut writer =
        l2_pcap::PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, report)?;
    writer.add_interface_and_write_frame(packet.metadata().interface(), config, &packet)?;
    writer.finish()?;
    std::fs::write(&path, writer.into_inner())?;
    let bundle = directory.path().join("bundle");
    let created = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "stream"])
        .arg(&path)
        .arg("--directory")
        .arg(&bundle)
        .output()?;
    assert_eq!(
        created.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    assert_eq!(
        manifest.pointer("/source/collection_summary/incomplete_sections"),
        Some(&serde_json::json!(1))
    );
    let page =
        l2_workbench::evidence::Case::from_json(&std::fs::read(bundle.join("pages/000001.json"))?)?;
    assert!(!page.collection_complete());
    let queried = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "query"])
        .arg(&bundle)
        .output()?;
    assert_eq!(
        queried.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&queried.stderr)
    );

    // A valid-shape manifest cannot replace the collection facts retained in its page
    *manifest
        .pointer_mut("/source/collection_summary/capture_dropped")
        .ok_or("missing quality field")? = serde_json::json!(99);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let rejected = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "query"])
        .arg(&bundle)
        .output()?;
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    Ok(())
}
