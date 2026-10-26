use super::*;

#[test]
fn extract_recovers_an_archive_after_session_specific_clear_headers() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("length-anchored-protocol.pcap");
    let destination = temporary.path().join("recovered");
    let first_image = tiny_png_with_rgb([19, 83, 151])?;
    let second_image = tiny_png_with_rgb([227, 47, 109])?;
    let payload = (0_u32..65_536)
        .map(|index| u8::try_from((index.wrapping_mul(173) ^ (index >> 5)) & 0xff))
        .collect::<Result<Vec<_>, _>>()?;
    let archive = stored_archive(&[
        ("images/first.png", first_image.as_slice()),
        ("images/second.png", second_image.as_slice()),
        ("data/sample.bin", payload.as_slice()),
    ])?;
    let chunks = artifact_chunks(&archive, &[403, 277, 601, 173])?;
    let captured = capture_from_protocol_chunks(&chunks, true, anchored_session_wire_bytes)?;
    assert!(
        !captured
            .windows(archive.len())
            .any(|bytes| bytes == archive),
        "the capture must contain the encoded archive rather than its clear bytes"
    );
    fs::write(&capture, &captured)?;

    // Default policy must locate each session's own parameters without a supplied recipe
    let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("extract")
        .arg(&capture)
        .arg("--output")
        .arg(&destination)
        .args(["--no-cache", "--jobs", "1", "--progress", "never"])
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
    if !artifacts.iter().any(|bytes| bytes == &archive) {
        let retained = temporary.keep();
        return Err(format!(
            "the length-anchored archive was not recovered; {} artifacts; fixture retained at {:?}",
            artifacts.len(),
            retained.display()
        )
        .into());
    }
    for expected in [&first_image, &second_image, &payload] {
        assert_eq!(
            artifacts.iter().filter(|bytes| *bytes == expected).count(),
            1,
            "each validated archive member must be retained exactly once"
        );
    }
    assert_member_parent_links(&destination, &archive)?;
    assert_eq!(fs::read(&capture)?, captured, "source bytes changed");
    Ok(())
}

fn assert_member_parent_links(destination: &Path, archive: &[u8]) -> Result<(), Box<dyn Error>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let digest = l2_workbench::sha256(archive);
    let archive_origins = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|artifact| {
            artifact.get("sha256").and_then(serde_json::Value::as_str) == Some(digest.as_str())
        })
        .and_then(|artifact| artifact.get("provenance"))
        .and_then(serde_json::Value::as_array)
        .ok_or("the reconstructed archive has no manifest provenance")?;
    for member in ["images/first.png", "images/second.png", "data/sample.bin"] {
        let origin = archive_member_provenance(&manifest, member)?;
        let case = origin
            .get("case_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("the member's evidence Case was not retained")?;
        let parent = origin
            .pointer("/selection/archive_parent/node_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or("the member has no archive parent reference")?;
        // Case-local node numbers only identify a parent together with the Case identity
        assert!(
            archive_origins.iter().any(|archive_origin| {
                archive_origin
                    .get("case_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(case)
                    && archive_origin
                        .get("selected_node_id")
                        .and_then(serde_json::Value::as_u64)
                        == Some(parent)
            }),
            "member {member} does not refer to an origin of the exact reconstructed archive"
        );
    }
    Ok(())
}

fn anchored_session_wire_bytes(session: usize, records: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let seed = session_seed(session)?;
    let encoded = reference_counter_stream(records, &seed)?;
    let tag = u8::try_from(session)?;
    let mut wire = vec![
        0xa7,
        0x51,
        0x63,
        tag.wrapping_mul(19),
        tag.wrapping_add(31),
        tag.wrapping_mul(29),
        tag.wrapping_add(47),
        tag.wrapping_mul(43),
        u8::try_from(seed.len())?,
    ];
    // The declared seed extent separates two clear regions with different field layouts
    wire.extend_from_slice(&seed);
    wire.extend_from_slice(&[0x75, 0xb4, tag | 0x80]);
    wire.extend_from_slice(&u16::try_from(session)?.to_le_bytes());
    let length = u32::try_from(encoded.len())?.to_be_bytes();
    wire.extend_from_slice(length.get(1..).ok_or("missing fixture length bytes")?);
    wire.extend_from_slice(&[0x57, 0x19, 0xaa]);
    wire.extend_from_slice(&encoded);
    Ok(wire)
}
