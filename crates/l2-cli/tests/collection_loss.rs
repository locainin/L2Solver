use serde_json::{Value, json};
use std::{error::Error, path::Path, process::Command};

fn option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&code.to_le_bytes());
    output.extend_from_slice(&u16::try_from(value.len()).unwrap_or_default().to_le_bytes());
    output.extend_from_slice(value);
    output.resize((output.len() + 3) & !3, 0);
    output
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len() + 12).unwrap_or_default();
    let mut output = Vec::new();
    output.extend_from_slice(&kind.to_le_bytes());
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(body);
    output.extend_from_slice(&length.to_le_bytes());
    output
}

fn capture(epb_drops: Option<u64>, if_drops: Option<u64>, os_drops: Option<u64>) -> Vec<u8> {
    let mut section = Vec::new();
    section.extend_from_slice(&0x1a2b_3c4d_u32.to_le_bytes());
    section.extend_from_slice(&1_u16.to_le_bytes());
    section.extend_from_slice(&0_u16.to_le_bytes());
    section.extend_from_slice(&(-1_i64).to_le_bytes());
    let mut result = block(0x0a0d_0d0a, &section);
    let mut interface = Vec::new();
    interface.extend_from_slice(&1_u16.to_le_bytes());
    interface.extend_from_slice(&0_u16.to_le_bytes());
    interface.extend_from_slice(&65_535_u32.to_le_bytes());
    result.extend_from_slice(&block(1, &interface));

    let frame = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x88, 0xb5,
    ];
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&14_u32.to_le_bytes());
    packet.extend_from_slice(&14_u32.to_le_bytes());
    packet.extend_from_slice(&frame);
    packet.resize((packet.len() + 3) & !3, 0);
    if let Some(drops) = epb_drops {
        packet.extend_from_slice(&option(4, &drops.to_le_bytes()));
        packet.extend_from_slice(&option(0, &[]));
    }
    result.extend_from_slice(&block(6, &packet));

    if if_drops.is_some() || os_drops.is_some() {
        let mut statistics = vec![0; 12];
        if let Some(drops) = if_drops {
            statistics.extend_from_slice(&option(5, &drops.to_le_bytes()));
        }
        if let Some(drops) = os_drops {
            statistics.extend_from_slice(&option(7, &drops.to_le_bytes()));
        }
        statistics.extend_from_slice(&option(0, &[]));
        result.extend_from_slice(&block(5, &statistics));
    }
    result
}

fn run(path: &Path, args: &[&str]) -> Result<std::process::Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(args)
        .arg(path)
        .output()?)
}

fn assert_text_drop_counts(text: &str, expected: [&str; 3]) {
    let fields = [
        "enhanced_packet_packets_dropped=",
        "interface_statistics_interface_dropped=",
        "interface_statistics_os_dropped=",
    ];
    for (field, value) in fields.into_iter().zip(expected) {
        let actual = text
            .split_whitespace()
            .find_map(|item| item.strip_prefix(field));
        assert_eq!(actual, Some(value), "unexpected {field} in {text}");
    }
}

#[test]
fn capture_loss_propagation() -> Result<(), Box<dyn Error>> {
    for (epb, interface, operating_system, lower_bound, expected_counts) in [
        (Some(9), None, None, 9, ["9", "unknown", "unknown"]),
        (None, Some(11), Some(4), 15, ["unknown", "11", "4"]),
        (Some(9), Some(11), Some(4), 15, ["9", "11", "4"]),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("loss.pcapng");
        std::fs::write(&path, capture(epb, interface, operating_system))?;
        let output = run(&path, &["inspect"])?;
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("authority=source_declared"));
        assert!(text.contains("Capture inspection: incomplete"));
        assert_text_drop_counts(&text, expected_counts);

        let output = run(&path, &["assess", "--format", "json"])?;
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report.get("dropped_count_semantics"),
            Some(&json!("conservative_lower_bound"))
        );
        assert_eq!(
            report.pointer("/quality/dropped"),
            Some(&json!(lower_bound))
        );
        assert_eq!(report.pointer("/quality/incomplete"), Some(&json!(true)));

        let output = run(&path, &["assess", "-vv"])?;
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("dropped count is a conservative lower bound"));

        let output = run(&path, &["workbench", "build"])?;
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let case = l2_workbench::evidence::Case::from_json(&output.stdout)?;
        assert!(!case.collection_complete());
        let summary = case
            .nodes()
            .iter()
            .find(|node| node.kind == "capture_collection_summary")
            .ok_or("missing collection summary")?;
        assert_eq!(
            summary
                .details
                .pointer("/summary/enhanced_packet_packets_dropped"),
            epb.map(|value| json!(value)).as_ref()
        );
        assert_eq!(
            summary
                .details
                .pointer("/summary/interface_statistics_interface_dropped"),
            interface.map(|value| json!(value)).as_ref()
        );
        assert_eq!(
            summary
                .details
                .pointer("/summary/interface_statistics_os_dropped"),
            operating_system.map(|value| json!(value)).as_ref()
        );
    }
    Ok(())
}

#[test]
fn zero_loss_receipts() -> Result<(), Box<dyn Error>> {
    for (epb, interface, os, expected_counts) in [
        (None, None, None, ["unknown", "unknown", "unknown"]),
        (Some(0), None, None, ["0", "unknown", "unknown"]),
        (None, Some(0), None, ["unknown", "0", "unknown"]),
        (None, None, Some(0), ["unknown", "unknown", "0"]),
        (Some(0), Some(0), Some(0), ["0", "0", "0"]),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("no-loss.pcapng");
        std::fs::write(&path, capture(epb, interface, os))?;
        let output = run(&path, &["inspect"])?;
        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8(output.stdout)?;
        assert_text_drop_counts(&text, expected_counts);
        let output = run(&path, &["assess", "--format", "json"])?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report.pointer("/quality/dropped"), Some(&json!(0)));
        assert_eq!(report.pointer("/quality/incomplete"), Some(&json!(false)));
        let authority = if epb.is_some() || interface.is_some() || os.is_some() {
            "source_declared"
        } else {
            "absent"
        };
        assert_eq!(
            report.pointer("/acquisition_quality/authority"),
            Some(&json!(authority))
        );
        assert_eq!(
            report.pointer("/acquisition_quality/status"),
            Some(&json!("unverified"))
        );

        let output = run(&path, &["workbench", "build"])?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let case = l2_workbench::evidence::Case::from_json(&output.stdout)?;
        let summary = &case
            .nodes()
            .iter()
            .find(|node| node.kind == "capture_collection_summary")
            .ok_or("missing collection summary")?
            .details;
        assert_eq!(
            summary.pointer("/summary/authority"),
            Some(&json!(authority))
        );
        assert_eq!(
            summary.pointer("/summary/acquisition_quality"),
            Some(&json!("unverified"))
        );
        for (field, value) in [
            ("enhanced_packet_packets_dropped", epb),
            ("interface_statistics_interface_dropped", interface),
            ("interface_statistics_os_dropped", os),
        ] {
            assert_eq!(
                summary.pointer(&format!("/summary/{field}")),
                value.map(|count| json!(count)).as_ref(),
                "counter {field}"
            );
        }
    }
    Ok(())
}
