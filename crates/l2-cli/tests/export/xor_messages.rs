use super::*;
use std::io::BufRead;

#[test]
fn extract_recovers_source_linked_xor_packet_observations_in_both_profiles()
-> Result<(), Box<dyn Error>> {
    let messages: &[(&[u8], &[u8])] = &[
        (b"session opened\r\n", b"session opened\n"),
        (
            b"query: list &quot;active&quot; hosts &amp; users\r\n",
            b"query: list \"active\" hosts & users\n",
        ),
        (
            b"result: online, ready; waiting for the next request\r\n",
            b"result: online, ready; waiting for the next request\n",
        ),
        (
            b"query: list &quot;active&quot; hosts &amp; users\r\n",
            b"query: list \"active\" hosts & users\n",
        ),
    ];
    for (profile, key) in [
        ("normal", &[0x37][..]),
        ("deep", &[0xa9][..]),
        ("normal", &[0x35, 0x72, 0xc1][..]),
    ] {
        let temporary = tempfile::tempdir()?;
        let capture = temporary.path().join("messages.pcap");
        let output = temporary.path().join("output");
        fs::write(&capture, packet_capture(messages, key)?)?;
        let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "extract",
                "--no-cache",
                "--jobs",
                "2",
                "--progress",
                "never",
            ])
            .arg("--profile")
            .arg(profile)
            .arg("-o")
            .arg(&output)
            .arg(&capture)
            .env("PATH", temporary.path())
            .output()?;
        assert!(
            matches!(result.status.code(), Some(0 | 3)),
            "{profile} extraction failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let cases = published_cases(&output)?;
        assert_reports_do_not_expose_key_material(&cases)?;
        for (index, (raw, normalized)) in messages.iter().enumerate() {
            let packet = u64::try_from(index)? + 4;
            let found = cases
                .iter()
                .any(|case| has_provisional_message(case, raw, normalized, packet));
            assert!(
                found,
                "{profile} with key length {} omitted source-linked message {index}",
                key.len()
            );
        }
    }
    Ok(())
}

fn has_provisional_message(
    case: &serde_json::Value,
    raw: &[u8],
    normalized: &[u8],
    packet: u64,
) -> bool {
    let Some(nodes) = case.get("nodes").and_then(serde_json::Value::as_array) else {
        return false;
    };
    let raw_hash = format!("sha256:{}", l2_workbench::sha256(raw));
    let normalized_hash = format!("sha256:{}", l2_workbench::sha256(normalized));
    let Some(raw_node) = nodes.iter().find(|node| {
        node["kind"] == "recovered_message"
            && node["blob"] == raw_hash
            && node["ranges"]
                .as_array()
                .is_some_and(|ranges| ranges.iter().any(|range| range["packet"] == packet))
    }) else {
        return false;
    };
    if !message_source_is_linked(case, nodes, raw_node) {
        return false;
    }
    let Some(normalized_node) = nodes.iter().find(|node| {
        node["kind"] == "normalized_message"
            && node["blob"] == normalized_hash
            && node.pointer("/details/raw_node_id") == raw_node.get("id")
    }) else {
        return false;
    };
    nodes.iter().any(|node| {
        if node["kind"] != "recovered_message_bytes"
            || node.pointer("/details/raw_node_id") != raw_node.get("id")
            || node.pointer("/details/normalized_node_id") != normalized_node.get("id")
        {
            return false;
        }
        let Some(payload) = published_payload(case, node) else {
            return false;
        };
        let actual_raw = serde_json::from_value::<Vec<u8>>(payload["raw_bytes"].clone()).ok();
        let actual_normalized =
            serde_json::from_value::<Vec<u8>>(payload["normalized_bytes"].clone()).ok();
        actual_raw.as_deref() == Some(raw) && actual_normalized.as_deref() == Some(normalized)
    })
}

fn message_source_is_linked(
    case: &serde_json::Value,
    nodes: &[serde_json::Value],
    raw: &serde_json::Value,
) -> bool {
    let Some(input) = raw.pointer("/details/source_run_node_id") else {
        return false;
    };
    let Some(report) = raw.pointer("/details/proposal_report_node_id") else {
        return false;
    };
    nodes
        .iter()
        .any(|node| node["id"] == *input && node["kind"] == "tcp_byte_run")
        && nodes
            .iter()
            .any(|node| node["id"] == *report && node["kind"] == "recovery_xor_proposal_report")
        && case["edges"].as_array().is_some_and(|edges| {
            edges.iter().any(|edge| {
                edge["from"] == raw["id"]
                    && edge["to"] == *input
                    && edge["relation"] == "derived_from"
                    && edge["status"] == "hypothesis"
            })
        })
}

#[test]
fn extract_does_not_label_plaintext_or_random_packets_as_xor_messages() -> Result<(), Box<dyn Error>>
{
    let plaintext: &[(&[u8], &[u8])] = &[
        (b"first observation is already plain text\n", b""),
        (b"second observation keeps its own line\n", b""),
        (b"third observation completes the sample\n", b""),
    ];
    let mut state = 0x4a9f_2153_u32;
    let random = (0..192)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state.to_be_bytes().first().copied().unwrap_or_default()
        })
        .collect::<Vec<_>>();
    let random_messages = [
        (
            random.get(..64).ok_or("random fixture too short")?,
            b"".as_slice(),
        ),
        (
            random.get(64..128).ok_or("random fixture too short")?,
            b"".as_slice(),
        ),
        (
            random.get(128..).ok_or("random fixture too short")?,
            b"".as_slice(),
        ),
    ];
    for messages in [plaintext, random_messages.as_slice()] {
        let temporary = tempfile::tempdir()?;
        let capture = temporary.path().join("control.pcap");
        let output = temporary.path().join("output");
        fs::write(&capture, packet_capture(messages, &[0])?)?;
        let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "extract",
                "--no-cache",
                "--jobs",
                "2",
                "--progress",
                "never",
            ])
            .arg("-o")
            .arg(&output)
            .arg(&capture)
            .env("PATH", temporary.path())
            .output()?;
        assert!(
            matches!(result.status.code(), Some(0 | 3)),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let cases = published_cases(&output)?;
        assert!(
            !cases
                .iter()
                .flat_map(|case| case["nodes"].as_array().into_iter().flatten())
                .any(|node| node["kind"] == "recovered_message")
        );
    }
    Ok(())
}

fn assert_reports_do_not_expose_key_material(
    cases: &[serde_json::Value],
) -> Result<(), Box<dyn Error>> {
    let mut report_count = 0;
    for case in cases {
        for node in case["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|node| node["kind"] == "recovery_xor_proposal_report")
        {
            let report = published_payload(case, node).ok_or("proposal report bytes missing")?;
            for proposal in report["proposals"]
                .as_array()
                .ok_or("proposal list missing")?
            {
                assert!(proposal.get("evidence").is_some());
                assert!(proposal.get("key_sha256").is_none());
                assert!(proposal.get("period").is_none());
                assert!(proposal.get("offset").is_none());
                assert!(proposal.get("key").is_none());
                assert!(proposal.get("recipe").is_none());
            }
            report_count += 1;
        }
    }
    assert!(report_count > 0, "the discovery receipt should be retained");
    Ok(())
}

fn published_payload<'a>(
    case: &'a serde_json::Value,
    node: &serde_json::Value,
) -> Option<&'a serde_json::Value> {
    case["blobs"]
        .as_array()?
        .iter()
        .find(|blob| blob["id"] == node["blob"])?
        .get("inline_payload")
}

fn packet_capture(messages: &[(&[u8], &[u8])], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if key.is_empty() {
        return Err("fixture XOR key is empty".into());
    }
    let mut frames = vec![
        tcp_frame_on_connection(31_040, 24_019, false, 100, 0, 0x02, b"")?,
        tcp_frame_on_connection(31_040, 24_019, true, 700, 101, 0x12, b"")?,
        tcp_frame_on_connection(31_040, 24_019, false, 101, 701, 0x10, b"")?,
    ];
    let mut offset = 0_usize;
    for (raw, _) in messages {
        let wire = raw
            .iter()
            .zip(key.iter().cycle().skip(offset % key.len()))
            .map(|(byte, key_byte)| byte ^ key_byte)
            .collect::<Vec<_>>();
        frames.push(tcp_frame_on_connection(
            31_040,
            24_019,
            false,
            101 + u32::try_from(offset)?,
            701,
            0x18,
            &wire,
        )?);
        offset += wire.len();
    }
    frames.push(tcp_frame_on_connection(
        31_040,
        24_019,
        false,
        101 + u32::try_from(offset)?,
        701,
        0x11,
        b"",
    )?);
    capture_from_frames(&frames)
}

fn published_cases(destination: &Path) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let source = fs::File::open(destination.join("evidence.jsonl.gz"))?;
    let input = std::io::BufReader::new(flate2::read::MultiGzDecoder::new(source));
    let mut canonical = Vec::new();
    l2_workbench::evidence::decode_published_evidence(
        l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION,
        input,
        &mut canonical,
        l2_workbench::evidence::PublishedEvidenceLimits::new(u64::MAX, 32 * 1024 * 1024),
    )?;
    std::io::Cursor::new(canonical)
        .lines()
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}
