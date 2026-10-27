use super::*;
use sha2::{Digest, Sha256};

#[path = "relational/anchored.rs"]
mod anchored;

type SessionEncoder = fn(usize, &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;

#[test]
fn extract_recovers_a_novel_transformed_protocol_from_synthetic_capture_packets()
-> Result<(), Box<dyn Error>> {
    assert_synthetic_artifact(true)
}

#[test]
fn extract_recovers_exact_artifact_without_claiming_an_unobserved_transfer_end()
-> Result<(), Box<dyn Error>> {
    assert_synthetic_artifact(false)
}

fn assert_synthetic_artifact(close_sessions: bool) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("independent-protocol.pcap");
    let destination = temporary.path().join("recovered");
    let expected = tiny_png_with_rgb([37, 131, 211])?;
    let captured = synthetic_protocol_capture(&expected, close_sessions)?;
    assert!(
        !captured
            .windows(expected.len())
            .any(|bytes| bytes == expected),
        "the source capture must not contain the clear artifact"
    );
    fs::write(&capture, &captured)?;

    // An empty executable search path makes the native engine the only extractor
    let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("extract")
        .arg(&capture)
        .arg("-o")
        .arg(&destination)
        .args(["--no-cache", "--jobs", "2", "--progress", "json"])
        .env("PATH", temporary.path())
        .output()?;
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "extraction failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let artifacts = artifact_paths(&destination)?
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    if !artifacts.iter().any(|bytes| bytes == &expected) {
        // Keep a private failure fixture so the source and reports can be inspected
        let retained = temporary.keep();
        return Err(format!(
            "the exact independent PNG was not recovered; {} artifacts; fixture retained at {:?}",
            artifacts.len(),
            retained.display(),
        )
        .into());
    }
    assert_eq!(fs::read(&capture)?, captured, "source bytes changed");
    if !close_sessions {
        assert_unknown_transfer_end(&destination, &expected)?;
    }
    Ok(())
}

fn synthetic_protocol_capture(
    artifact: &[u8],
    close_sessions: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let chunks = artifact_chunks(artifact, &[3, 5, 7, 4, 6])?;
    capture_from_protocol_chunks(&chunks, close_sessions, session_wire_bytes)
}

fn capture_from_protocol_chunks(
    chunks: &[&[u8]],
    close_sessions: bool,
    encode_session: SessionEncoder,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frames = Vec::new();
    // Session order differs from artifact order, including reversed records within a session
    for (session, group) in [1_usize, 3, 0, 2].into_iter().enumerate() {
        let mut records = chunks
            .iter()
            .enumerate()
            .filter(|(sequence, _)| sequence % 4 == group)
            .map(|(sequence, payload)| protocol_record(sequence, payload))
            .collect::<Result<Vec<_>, _>>()?;
        if session % 2 == 1 {
            records.reverse();
        }
        let wire = encode_session(session, &records.concat())?;
        let port = 42_400_u16 + u16::try_from(session)?;
        let sequence = 10_000_u32 + 1_000 * u32::try_from(session)?;
        frames.extend(tcp_session_frames(port, sequence, &wire, close_sessions)?);
    }
    capture_from_frames(&frames)
}

fn tcp_session_frames(
    port: u16,
    initial_sequence: u32,
    wire: &[u8],
    close: bool,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let client = initial_sequence + 1;
    let server = initial_sequence + 500_000;
    let after_data = client + u32::try_from(wire.len())?;
    let mut frames = vec![
        tcp_frame_on_connection(port, 23_779, false, initial_sequence, 0, 0x02, b"")?,
        tcp_frame_on_connection(port, 23_779, true, server, client, 0x12, b"")?,
        tcp_frame_on_connection(port, 23_779, false, client, server + 1, 0x10, b"")?,
        tcp_frame_on_connection(port, 23_779, false, client, server + 1, 0x18, wire)?,
        tcp_frame_on_connection(port, 23_779, false, after_data, server + 1, 0x11, b"")?,
        tcp_frame_on_connection(port, 23_779, true, server + 1, after_data + 1, 0x10, b"")?,
        tcp_frame_on_connection(port, 23_779, true, server + 1, after_data + 1, 0x11, b"")?,
        tcp_frame_on_connection(port, 23_779, false, after_data + 1, server + 2, 0x10, b"")?,
    ];
    if !close {
        frames.truncate(4);
    }
    for frame in &mut frames {
        add_packet_checksums(frame)?;
    }
    Ok(frames)
}

fn assert_unknown_transfer_end(destination: &Path, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::io::BufRead;
    let source = fs::File::open(destination.join("evidence.jsonl.gz"))?;
    let normalized = std::io::BufReader::new(flate2::read::MultiGzDecoder::new(source));
    let mut canonical = Vec::new();
    l2_workbench::evidence::decode_published_evidence(
        3,
        normalized,
        &mut canonical,
        l2_workbench::evidence::PublishedEvidenceLimits::new(u64::MAX, 32 * 1024 * 1024),
    )?;
    let evidence = std::io::Cursor::new(canonical);
    let expected_blob = format!("sha256:{}", l2_workbench::sha256(expected));
    let mut found_exact_output = false;
    let mut found_unobserved_end = false;
    for line in evidence.lines() {
        let case: serde_json::Value = serde_json::from_str(&line?)?;
        for node in case
            .get("nodes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if node.get("kind").and_then(serde_json::Value::as_str) == Some("tcp_byte_run") {
                found_unobserved_end |=
                    node.pointer("/details/end_observed") == Some(&serde_json::Value::Bool(false));
            }
            if node.get("kind").and_then(serde_json::Value::as_str)
                == Some("relational_transform_output")
                && node.get("blob").and_then(serde_json::Value::as_str)
                    == Some(expected_blob.as_str())
            {
                assert_eq!(
                    node.pointer("/details/terminal_sequence")
                        .and_then(serde_json::Value::as_str),
                    Some("unknown")
                );
                found_exact_output = true;
            }
        }
    }
    assert!(
        found_unobserved_end,
        "fixture should retain the unobserved TCP end"
    );
    assert!(
        found_exact_output,
        "exact artifact should retain unknown terminal status"
    );
    Ok(())
}

fn add_packet_checksums(frame: &mut [u8]) -> Result<(), Box<dyn Error>> {
    // These fixture packets have a fourteen-byte Ethernet header and a plain IPv4 header
    let ip_checksum = internet_checksum(frame.get(14..34).ok_or("missing fixture IPv4 header")?);
    frame
        .get_mut(24..26)
        .ok_or("missing fixture IPv4 checksum")?
        .copy_from_slice(&ip_checksum.to_be_bytes());
    let tcp = frame.get(34..).ok_or("missing fixture TCP segment")?;
    let mut pseudo = frame
        .get(26..34)
        .ok_or("missing fixture IP addresses")?
        .to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&u16::try_from(tcp.len())?.to_be_bytes());
    pseudo.extend_from_slice(tcp);
    let tcp_checksum = internet_checksum(&pseudo);
    frame
        .get_mut(50..52)
        .ok_or("missing fixture TCP checksum")?
        .copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(())
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.iter().enumerate().fold(0_u16, |sum, (index, byte)| {
        let word = u16::from(*byte) << if index % 2 == 0 { 8 } else { 0 };
        let (sum, carry) = sum.overflowing_add(word);
        sum.wrapping_add(u16::from(carry))
    });
    !sum
}

fn artifact_chunks<'a>(
    artifact: &'a [u8],
    widths: &[usize],
) -> Result<Vec<&'a [u8]>, Box<dyn Error>> {
    if widths.is_empty() || widths.contains(&0) {
        return Err("fixture chunk widths must be positive".into());
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    // Positive widths consume bytes; the take bound also caps the fixture loop
    for width in widths.iter().copied().cycle().take(artifact.len()) {
        if start == artifact.len() {
            break;
        }
        let end = (start + width).min(artifact.len());
        chunks.push(
            artifact
                .get(start..end)
                .ok_or("invalid fixture chunk range")?,
        );
        start = end;
    }
    Ok(chunks)
}

fn protocol_record(sequence: usize, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    // Mixed field byte orders require schema discovery instead of one default layout
    bytes.extend_from_slice(&0x6d21_u16.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(sequence)?.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(payload.len())?.to_le_bytes());
    bytes.push(0x91);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn session_wire_bytes(session: usize, records: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let seed = session_seed(session)?;
    let encoded = reference_counter_stream(records, &seed)?;
    let mut wire = vec![0xa7, 0x51, u8::try_from(seed.len())?];
    wire.extend_from_slice(&seed);
    wire.push(0xc9);
    wire.extend_from_slice(&encoded);
    Ok(wire)
}

fn session_seed(session: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let session = u8::try_from(session)?;
    Ok((0..12_u8)
        .map(|index| {
            0x1d_u8
                .wrapping_add(session.wrapping_mul(17))
                .wrapping_add(index.wrapping_mul(9))
        })
        .collect())
}

#[test]
fn fixture_reference_transform_matches_an_independently_computed_vector()
-> Result<(), Box<dyn Error>> {
    // This vector was calculated with Python hashlib, independently of the recovery engine
    let expected = [
        0xbb, 0x48, 0x73, 0xbf, 0x2e, 0x32, 0x95, 0x60, 0xf3, 0x7c, 0xa3, 0xff, 0x57, 0x6a, 0x01,
        0xbf, 0x87, 0xa3, 0x0c, 0x92, 0x09, 0x4d, 0xc7, 0x2d, 0xa3, 0x68, 0x64, 0x33, 0x4d, 0x0a,
        0xdd, 0x63, 0x42, 0x88, 0xae, 0x12, 0xe0, 0x9c, 0xab, 0x81,
    ];
    let actual = reference_counter_stream(&(0..40).collect::<Vec<u8>>(), &[1, 2, 3, 4, 5])?;
    assert_eq!(actual, expected);
    Ok(())
}

fn reference_counter_stream(plaintext: &[u8], seed: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = Vec::with_capacity(plaintext.len());
    // The fixture writer defines its wire format without calling production transformations
    for (index, chunk) in plaintext.chunks(32).enumerate() {
        let counter = u16::try_from(index)?
            .checked_add(1)
            .ok_or("fixture counter overflow")?;
        let mut hash = Sha256::new();
        hash.update(counter.to_le_bytes());
        hash.update(seed);
        output.extend(
            chunk
                .iter()
                .zip(hash.finalize())
                .map(|(byte, key)| byte ^ key),
        );
    }
    Ok(output)
}
