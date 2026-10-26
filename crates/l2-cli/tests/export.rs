use l2_workbench::reconstruction::Limits;
use std::{
    error::Error,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const BODY: &[u8] = b"object bytes";
const FTP_BODY: &[u8] = b"example FTP transfer bytes\r\n";

#[path = "export/relational.rs"]
mod relational;
#[path = "export/repeated.rs"]
mod repeated;
#[path = "export/tshark_identity.rs"]
mod tshark_identity;

#[test]
fn exports_named_artifact() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(
        output.status.success(),
        "{}\n{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default(),
        fs::read_to_string(destination.join("limitations.txt")).unwrap_or_default()
    );
    assert!(destination.is_dir());
    let mut objects = fs::read_dir(&destination)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.retain(|path| !is_report(path));
    assert_eq!(objects.len(), 1, "expected one recovered object");

    // A usable name stays a plain filename and the output stays a regular file
    let object = objects.first().ok_or("recovered object is missing")?;
    let name = object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("recovered object name is not readable")?;
    assert!(!name.trim().is_empty());
    assert!(!name.contains(['/', '\\']));
    assert!(!name.chars().any(char::is_control));
    assert!(fs::symlink_metadata(object)?.file_type().is_file());
    assert_eq!(fs::read(object)?, BODY);

    assert_export_reports_complete(&destination)?;
    Ok(())
}

#[test]
fn exports_archive_and_members() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("archive.pcap");
    let destination = temporary.path().join("output");
    let first_image = tiny_png_with_rgb([1, 2, 3])?;
    let second_image = tiny_png_with_rgb([4, 5, 6])?;
    let archive = stored_archive(&[
        ("media/first.png", first_image.as_slice()),
        ("media/second.png", second_image.as_slice()),
        ("notes/readme.txt", b"preserved member"),
    ])?;
    fs::write(&capture, capture_with_http_body(&archive)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    let artifact_paths = artifact_paths(&destination)?;
    let exported = artifact_paths
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    for expected in [
        archive.as_slice(),
        first_image.as_slice(),
        second_image.as_slice(),
        b"preserved member".as_slice(),
    ] {
        assert_eq!(
            exported
                .iter()
                .filter(|bytes| bytes.as_slice() == expected)
                .count(),
            1,
            "each archive object must be preserved exactly once"
        );
    }
    Ok(())
}

#[test]
fn exports_nested_archives_and_shows_member_parent_context() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("nested-archive.pcap");
    let destination = temporary.path().join("output");
    let leaf = tiny_png_with_rgb([7, 8, 9])?;
    let nested_archive = stored_archive(&[("deep/leaf.png", leaf.as_slice())])?;
    let outer_archive = stored_archive(&[("nested/inside.zip", nested_archive.as_slice())])?;
    fs::write(&capture, capture_with_http_body(&outer_archive)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    assert_nested_archive_export(&destination, &outer_archive, &nested_archive, &leaf)
}

fn assert_nested_archive_export(
    destination: &Path,
    outer_archive: &[u8],
    nested_archive: &[u8],
    leaf: &[u8],
) -> Result<(), Box<dyn Error>> {
    let artifact_paths = artifact_paths(destination)?;
    let exported = artifact_paths
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    for expected in [outer_archive, nested_archive, leaf] {
        assert_eq!(
            exported
                .iter()
                .filter(|bytes| bytes.as_slice() == expected)
                .count(),
            1,
            "each nested archive object must be published exactly once"
        );
    }

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let leaf_provenance = archive_member_provenance(&manifest, "deep/leaf.png")?;
    assert_eq!(
        leaf_provenance
            .pointer("/selection/validated_as")
            .and_then(serde_json::Value::as_str),
        Some("zip_member")
    );

    let nested_archive_file = artifact_paths
        .iter()
        .zip(&exported)
        .find(|(_, bytes)| bytes.as_slice() == nested_archive)
        .and_then(|(path, _)| path.file_name())
        .and_then(|name| name.to_str())
        .ok_or("published nested archive filename is missing")?;
    assert_nested_archive_summary(destination, nested_archive_file)
}

fn archive_member_provenance<'a>(
    manifest: &'a serde_json::Value,
    member_path: &str,
) -> Result<&'a serde_json::Value, Box<dyn Error>> {
    manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|artifact| {
            artifact
                .get("provenance")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
        })
        .find(|provenance| {
            provenance
                .pointer("/selection/archive_path")
                .and_then(serde_json::Value::as_str)
                == Some(member_path)
        })
        .ok_or_else(|| format!("archive member {member_path} provenance is missing").into())
}

fn assert_nested_archive_summary(
    destination: &Path,
    nested_archive_file: &str,
) -> Result<(), Box<dyn Error>> {
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    for member_path in ["nested/inside.zip", "deep/leaf.png"] {
        assert!(
            summary.contains(&format!("Archive member path: {member_path}")),
            "archive member path is missing from the text summary: {member_path}\n{summary}"
        );
    }
    let leaf_block = artifact_summary_block(&summary, "deep/leaf.png")?;
    let parent_archive_files = leaf_block
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Parent archive artifact: "))
        .filter_map(|value| value.split_whitespace().next())
        .collect::<Vec<_>>();
    assert!(
        parent_archive_files.contains(&nested_archive_file),
        "leaf must name the exact published nested archive among its independently retained parents:\n{summary}"
    );
    for parent_archive_file in parent_archive_files {
        assert!(destination.join(parent_archive_file).is_file());
    }
    Ok(())
}

fn artifact_summary_block(
    summary: &str,
    archive_member_path: &str,
) -> Result<String, Box<dyn Error>> {
    let lines = summary.lines().collect::<Vec<_>>();
    let marker = format!("Archive member path: {archive_member_path}");
    let member_line = lines
        .iter()
        .position(|line| line.trim() == marker)
        .ok_or_else(|| format!("archive member {archive_member_path} is missing from summary"))?;
    let before_member = lines
        .get(..member_line)
        .ok_or("archive member position exceeds summary lines")?;
    let block_start = before_member
        .iter()
        .rposition(|line| line.starts_with("  ") && !line.starts_with("    "))
        .ok_or("artifact summary block has no file heading")?;
    let after_member = lines
        .get(member_line + 1..)
        .ok_or("archive member position exceeds summary lines")?;
    let block_end = after_member
        .iter()
        .position(|line| line.starts_with("  ") && !line.starts_with("    "))
        .map_or(lines.len(), |offset| member_line + 1 + offset);
    Ok(lines
        .get(block_start..block_end)
        .ok_or("artifact summary block range is invalid")?
        .join("\n"))
}

#[test]
fn published_export_contains_one_evidence_sidecar_without_artifact_payloads()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(matches!(output.status.code(), Some(0 | 3)));
    assert!(destination.is_dir());
    let entries = fs::read_dir(&destination)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.file_name() == "evidence.jsonl.gz")
            .count(),
        1,
        "publication must expose exactly one evidence sidecar"
    );
    assert!(entries.iter().all(|entry| {
        !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".l2solver-evidence-case-")
    }));

    let compressed = fs::read(destination.join("evidence.jsonl.gz"))?;
    let mut evidence = Vec::new();
    flate2::read::MultiGzDecoder::new(compressed.as_slice()).read_to_end(&mut evidence)?;
    assert!(!evidence.is_empty());
    assert!(!evidence.windows(BODY.len()).any(|window| window == BODY));
    let body_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, BODY);
    assert!(!String::from_utf8_lossy(&evidence).contains(&body_base64));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .pointer("/evidence/file")
            .and_then(serde_json::Value::as_str),
        Some("evidence.jsonl.gz")
    );
    let coverage = manifest
        .pointer("/evidence/coverage")
        .ok_or("evidence coverage is missing from the manifest")?;
    assert_eq!(coverage["selected_cases"], coverage["retained_cases"]);
    assert_eq!(coverage["omitted_cases"], 0);
    assert_eq!(coverage["retained_bytes"], u64::try_from(compressed.len())?);
    assert_eq!(
        coverage["raw_retained_bytes"],
        u64::try_from(evidence.len())?
    );
    assert_eq!(coverage["encoding_version"], 2);
    assert_eq!(
        manifest
            .pointer("/evidence/encoding")
            .and_then(serde_json::Value::as_str),
        Some("gzip")
    );
    assert_artifact_case_references(&manifest, &evidence)?;
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Evidence sidecar: evidence.jsonl.gz"));
    assert!(summary.contains("Cases retained ("));
    Ok(())
}

fn assert_artifact_case_references(
    manifest: &serde_json::Value,
    evidence: &[u8],
) -> Result<(), Box<dyn Error>> {
    let evidence_records = std::str::from_utf8(evidence)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let provenance = manifest
        .pointer("/artifacts/0/provenance/0")
        .ok_or("artifact provenance is missing")?;
    let case_id = provenance
        .get("case_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("artifact Case reference is missing")?;
    let case_record = evidence_records
        .iter()
        .find(|record| record.get("case_id").and_then(serde_json::Value::as_str) == Some(case_id))
        .ok_or("artifact Case reference does not resolve in the sidecar")?;
    for field in [
        "selected_node_id",
        "validation_node_id",
        "extension_node_id",
    ] {
        if let Some(node_id) = provenance.get(field).and_then(serde_json::Value::as_u64) {
            assert!(
                case_record
                    .get("nodes")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|nodes| {
                        nodes.iter().any(|node| {
                            node.get("id").and_then(serde_json::Value::as_u64) == Some(node_id)
                        })
                    })
            );
        }
    }
    Ok(())
}

fn assert_export_reports_complete(destination: &Path) -> Result<(), Box<dyn Error>> {
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.to_lowercase().contains("artifact"));
    assert!(
        summary.starts_with("L2Solver capture export\nOverall export: complete (exit status 0)\n")
    );
    assert!(summary.contains('1'));
    assert!(summary.contains("Packets:"));
    assert!(summary.contains("Recovery input-byte ceiling per input item:"));
    assert!(summary.contains("Recovery output-byte ceiling per candidate result:"));
    assert!(summary.contains(
        "Default recovery search exhaustiveness within the declared plan: 1 exhaustive, 0 non-exhaustive flow Cases; not applicable (no cohort Cases)"
    ));
    assert!(summary.contains(
        "Recovery omission entries: 0 (one entry may cover multiple omitted inputs or report details)"
    ));
    assert!(!summary.contains("SHA-256:"));
    assert!(!summary.contains("node "));
    assert!(!summary.trim_start().starts_with('{'));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .get("export_status")
            .and_then(serde_json::Value::as_str),
        Some("complete")
    );
    assert_eq!(
        manifest
            .get("incomplete_components")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let resources = manifest
        .pointer("/discovery_coverage/recovery/resources")
        .and_then(serde_json::Value::as_object)
        .ok_or("recovery resource coverage is missing")?;
    assert!(resources.contains_key("input_bytes_per_item_by_case"));
    assert!(resources.contains_key("output_bytes_per_candidate_by_case"));
    assert!(!resources.contains_key("input_bytes_per_case"));
    assert!(!resources.contains_key("output_bytes_per_case"));
    Ok(())
}

#[test]
fn summary_reports_recovered_artifact_validation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("validated.png.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(&capture, capture_with_http_body(&tiny_png()?)?)?;

    export_with_tshark(&capture, &destination, &executable)?;
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(
        summary.contains("Category: recovered artifact"),
        "{summary}"
    );
    assert!(
        summary.contains("Structural validation: validated as png_structure"),
        "{summary}"
    );
    assert!(
        summary.contains("Signature candidates retained:"),
        "{summary}"
    );
    Ok(())
}

#[test]
fn uses_sibling_directory() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("capture.pcap.export");
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export(&capture, None)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(destination.is_dir());
    assert_eq!(destination.parent(), Some(temporary.path()));
    assert_ne!(destination, capture);
    Ok(())
}

#[test]
fn deduplicates_shared_case_limitations_across_flows_and_cohorts() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("shared-case-limitations.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(
        &capture,
        capture_with_http_flows(&[(40_000, BODY), (40_001, FTP_BODY)])?,
    )?;

    let output = export_with_tshark(&capture, &destination, &executable)?;
    if should_retain_export_fixture(&destination, &output) {
        retain_failed_export_fixture(temporary, &destination, &output);
    }

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    let shared = "Capture order and header addresses do not establish ownership, delivery, causality, or malicious intent";
    assert_eq!(limitations.matches(shared).count(), 1, "{limitations}");
    assert!(
        limitations.contains("Case limitation applies to 2 flow Cases and 1 cohort Cases"),
        "{limitations}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/cohort_reconstruction/cases"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/cohort_reconstruction/cases_with_omissions"
        )?,
        0
    );
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains(
        "Cohort reconstruction omissions: 0 TCP records, 0 fragments, 0 ranges, 0 TCP byte positions affected by omitted observations or rejected ranges, 0 TCP observations, 0 fragment byte positions affected by omitted observations or rejected ranges, 0 fragment observations, 0 state observations, 0 unmeasured ranges (in 0 of 1 Case)"
    ));
    Ok(())
}

#[test]
fn summarizes_empty_capture() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("empty.pcap");
    let destination = temporary.path().join("empty-export");
    fs::write(&capture, empty_capture())?;

    let output = export(&capture, Some(&destination))?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(destination.is_dir());
    assert!(artifact_paths(&destination)?.is_empty());
    assert!(destination.join("limitations.txt").is_file());
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.to_lowercase().contains("artifact"));
    assert!(summary.contains('0'));
    assert!(summary.contains("see limitations.txt"));
    assert!(summary.contains(
        "Default recovery Case evidence collection: not applicable (no flow Cases); not applicable (no cohort Cases)"
    ));
    assert!(summary.contains(
        "Default recovery discovery input coverage: not applicable (no flow Cases); not applicable (no cohort Cases); 0 framing input runs and 0 record input frames omitted"
    ));
    assert!(summary.contains(
        "Default recovery search exhaustiveness within the declared plan: not applicable (no flow Cases); not applicable (no cohort Cases)"
    ));
    assert!(summary.contains(
        "Default recovery report details: not applicable (no flow Cases); not applicable (no cohort Cases)"
    ));
    Ok(())
}

#[test]
fn preserves_existing_output() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    fs::create_dir(&destination)?;
    let sentinel = destination.join("keep.txt");
    fs::write(&sentinel, b"preserve this file")?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(!output.status.success());
    assert_eq!(fs::read(&sentinel)?, b"preserve this file");
    assert_eq!(fs::read_dir(&destination)?.count(), 1);
    let error = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(error.contains("exist") || error.contains("overwrite"));
    Ok(())
}

#[test]
fn reports_invalid_capture() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("invalid.pcap");
    let destination = temporary.path().join("output");
    fs::write(&capture, b"not a capture")?;

    let output = export(&capture, Some(&destination))?;

    assert!(!output.status.success());
    assert!(!destination.exists());
    assert!(!String::from_utf8_lossy(&output.stderr).trim().is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid.pcap"));
    Ok(())
}

#[test]
fn excludes_partial_http_body() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("partial.pcap");
    let destination = temporary.path().join("output");
    fs::write(&capture, capture_with_partial_http_body(BODY)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(artifact_paths(&destination)?.is_empty());
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("No complete HTTP bodies were recovered"));
    Ok(())
}

#[test]
fn unsupported_jpeg_signature_stays_binary() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("image.pcap");
    let destination = temporary.path().join("output");
    let jpeg = b"\xff\xd8\xff\xe0\0\x10JFIF\0sample";
    fs::write(&capture, capture_with_http_body(jpeg)?)?;

    let output = export(&capture, Some(&destination))?;

    assert!(output.status.success());
    let mut matching_artifacts = Vec::new();
    for path in artifact_paths(&destination)? {
        if fs::read(&path)? == jpeg {
            matching_artifacts.push(path);
        }
    }
    assert_eq!(
        matching_artifacts.len(),
        1,
        "JPEG candidate is missing or duplicated"
    );
    let artifact = matching_artifacts
        .first()
        .ok_or("JPEG candidate is missing")?;
    assert_eq!(
        artifact
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("bin")
    );
    assert_eq!(fs::read(artifact)?, jpeg);
    Ok(())
}

#[test]
fn exports_ftp_boundary_candidate() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("ftp.pcap");
    let destination = temporary.path().join("output");
    let empty_path = temporary.path().join("empty-path");
    fs::create_dir(&empty_path)?;
    fs::write(&capture, capture_with_ftp_candidate(FTP_BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &empty_path)?;

    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        fs::read_to_string(destination.join("summary.txt"))?
    );
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(
        artifacts.len(),
        1,
        "expected one native FTP candidate\n{}",
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    let artifact = artifacts.first().ok_or("FTP candidate is missing")?;
    assert_eq!(
        artifact.file_name().and_then(|name| name.to_str()),
        Some("000001-ftp.bin")
    );
    assert_eq!(fs::read(artifact)?, FTP_BODY);

    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Per-flow native analysis: complete"));
    // Native search omissions still require a partial result with optional enrichment
    assert!(summary.contains("- recovery:"));
    assert!(summary.contains("TShark export: partial"));
    assert!(summary.contains("TShark objects exported: 0"));
    assert!(summary.contains("TShark issue: TShark executable not found: tshark"));
    assert!(summary.contains("FTP transfer candidates: 1"));
    assert!(summary.contains("Type: FTP transfer candidate; file boundary unresolved"));
    assert!(summary.contains(
        "FTP candidates are labeled as candidates because TCP connection boundaries do not prove file boundaries"
    ));
    assert!(summary.contains("Packets: 10"));
    assert!(summary.contains("TShark packet provenance is not reported"));
    assert!(summary.contains(
        "Capture-level indexed flow tuples; no MAC/device or application-session attribution:"
    ));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let provenance = manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .ok_or("FTP candidate provenance list is missing")?;
    let supporting_flows = provenance
        .iter()
        .find_map(|origin| {
            origin
                .pointer("/supporting_flows")
                .and_then(serde_json::Value::as_array)
                .filter(|flows| flows.len() == 2)
        })
        .ok_or("FTP candidate should retain control and data flow provenance")?;
    for flow in supporting_flows {
        let protocol = match flow["protocol"].as_u64() {
            Some(6) => "TCP".to_owned(),
            Some(17) => "UDP".to_owned(),
            Some(number) => format!("IP protocol {number}"),
            None => "unknown protocol".to_owned(),
        };
        let expected = format!(
            "Flow {}: {protocol} {}:{} ↔ {}:{}",
            flow["id"].as_i64().ok_or("flow index is missing")?,
            flow["endpoint_a"]
                .as_str()
                .ok_or("flow endpoint is missing")?,
            flow["port_a"].as_u64().ok_or("flow port is missing")?,
            flow["endpoint_b"]
                .as_str()
                .ok_or("flow endpoint is missing")?,
            flow["port_b"].as_u64().ok_or("flow port is missing")?,
        );
        assert!(summary.contains(&expected), "missing {expected}\n{summary}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_objects_use_safe_names() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'tshark bytes' > \"$destination/untrusted-name.exe\"",
    )?;
    fs::write(&capture, empty_capture())?;

    let output =
        export_with_tshark_flags(&capture, &destination, &executable, &["--require-tshark"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        fs::read_to_string(destination.join("summary.txt"))?
    );
    let objects = fs::read_dir(&destination)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    let object = objects
        .iter()
        .find(|path| !is_report(path))
        .ok_or("TShark object is missing")?;
    let name = object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("object name is not readable")?;
    assert!(!name.contains("untrusted"));
    assert!(!name.contains(['/', '\\']));
    assert_eq!(fs::read(object)?, b"tshark bytes");
    assert!(objects.iter().all(|path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    }));
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Native complete HTTP bodies: 0"));
    assert!(summary.contains("FTP transfer candidates: 0"));
    assert!(summary.contains("TShark objects exported: 1"));
    assert!(summary.contains("TShark packet provenance is not reported"));
    assert!(!summary.contains("SHA-256:"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_output_limit_partial() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let truncate = find_program("truncate")?;
    let oversized_bytes = 512_u64 * 1024 * 1024 + 1;
    let command = format!(
        "{} -s {oversized_bytes} \"$destination/oversized-object\"",
        shell_quote(&truncate)
    );
    let executable = install_tshark(temporary.path(), &command)?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        fs::read(artifacts.first().ok_or("native HTTP artifact is missing")?)?,
        BODY
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .pointer("/tshark/status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    let budget = manifest_u64(&manifest, "/tshark/object_export_budget/temporary_bytes")?;
    let observed = manifest_u64(
        &manifest,
        "/tshark/object_export_usage/temporary_bytes_peak",
    )?;
    assert!(observed > budget);
    assert_eq!(
        manifest
            .pointer("/tshark/object_export_usage/temporary_scan_complete")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(artifact_paths(&destination)?.len(), 1);
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    assert!(limitations.contains("may overshoot between scans"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_imf_count() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark_for_protocol(
        temporary.path(),
        &["imf"],
        "imf",
        "for number in 1 2 3 4 5 6 7 8; do printf 'message %s\\n' \"$number\" > \"$destination/message-$number\"; done",
    )?;
    fs::write(&capture, empty_capture())?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        fs::read_to_string(destination.join("summary.txt"))?
    );
    let mut objects = artifact_paths(&destination)?;
    objects.sort();
    assert_eq!(objects.len(), 8);
    for (index, object) in objects.iter().enumerate() {
        let expected_name = format!("{:06}-tshark-imf.eml", index + 1);
        assert_eq!(
            object.file_name().and_then(|name| name.to_str()),
            Some(expected_name.as_str())
        );
        assert!(fs::read(object)?.starts_with(b"message "));
    }
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("TShark email messages (IMF): 8"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_capture_before_running_optional_tshark() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let capture_link = temporary.path().join("capture-link.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'tshark bytes' > \"$destination/object\"",
    )?;
    fs::write(&capture, empty_capture())?;
    symlink(&capture, &capture_link)?;

    let output = export_with_tshark(&capture_link, &destination, &executable)?;

    assert_eq!(output.status.code(), Some(1));
    assert!(!destination.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_object_names_are_deterministic() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'last' > \"$destination/z-last\"\nprintf '%s' 'first' > \"$destination/a-first\"",
    )?;
    fs::write(&capture, empty_capture())?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(destination.join("000001-tshark-http.bin"))?,
        b"first"
    );
    assert_eq!(
        fs::read(destination.join("000002-tshark-http.bin"))?,
        b"last"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_exports_non_utf8_path() -> Result<(), Box<dyn Error>> {
    use std::os::unix::ffi::OsStringExt;

    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary
        .path()
        .join(std::ffi::OsString::from_vec(b"output-\xff".to_vec()));
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'tshark bytes' > \"$destination/object\"",
    )?;
    fs::write(&capture, empty_capture())?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    assert_eq!(
        fs::read(destination.join("000001-tshark-http.bin"))?,
        b"tshark bytes"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn duplicate_tshark_object_is_skipped() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'object bytes' > \"$destination/untrusted-name.exe\"",
    )?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    assert_eq!(artifact_paths(&destination)?.len(), 1);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let origins = manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .ok_or("merged native and TShark provenance is missing")?;
    assert_eq!(origins.len(), 2);
    assert!(origins.iter().any(|origin| {
        origin
            .pointer("/category")
            .and_then(serde_json::Value::as_str)
            == Some("native_http_body")
    }));
    assert!(origins.iter().any(|origin| {
        origin
            .pointer("/category")
            .and_then(serde_json::Value::as_str)
            == Some("tshark_object")
    }));
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Native complete HTTP bodies: 1"));
    assert!(summary.contains("TShark objects exported: 0"));
    assert!(summary.contains("TShark duplicate objects skipped: 1"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unsafe_tshark_files_are_skipped() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'object bytes' > \"$destination/first\"\n/bin/ln \"$destination/first\" \"$destination/hard-link\"\n/bin/ln -s \"$destination/first\" \"$destination/symbolic-link\"",
    )?;
    fs::write(&capture, empty_capture())?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(output.status.code(), Some(0));
    assert!(artifact_paths(&destination)?.is_empty());
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("TShark objects exported: 0"));
    assert!(summary.contains("unsafe object entry"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_stage_escape_aborts_publication() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf '%s' 'unexpected' > \"$destination/../../../escaped\"",
    )?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert!(!output.status.success());
    assert!(!destination.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected entry"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_failure_preserves_native_export() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(
        temporary.path(),
        "printf 'export failed\\nsecond line' >&2\nexit 7",
    )?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(output.status.code(), Some(0));
    let exported = fs::read_dir(&destination)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| !is_report(path))
        .ok_or("native object was lost")?;
    assert_eq!(fs::read(exported)?, BODY);
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Native complete HTTP bodies: 1"));
    assert!(summary.contains("TShark export: partial"));
    assert!(summary.contains("exit status"));
    assert!(summary.contains("export failed\\nsecond line"));
    assert_eq!(summary.matches("TShark issue:").count(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_tshark_preserves_native_export() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let empty_path = temporary.path().join("empty-path");
    fs::create_dir(&empty_path)?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &empty_path)?;

    assert_eq!(output.status.code(), Some(0));
    assert!(destination.join("summary.txt").is_file());
    assert!(fs::read_to_string(destination.join("summary.txt"))?.contains("not found"));
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        fs::read(artifacts.first().ok_or("native artifact is missing")?)?,
        BODY
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/tshark/required"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(
        manifest.pointer("/tshark/status"),
        Some(&serde_json::json!("partial"))
    );
    assert_eq!(
        manifest.get("export_status"),
        Some(&serde_json::json!("complete"))
    );
    assert_eq!(
        manifest.pointer("/discovery_coverage/status"),
        Some(&serde_json::json!("partial"))
    );
    assert_eq!(
        manifest.get("incomplete_components"),
        Some(&serde_json::json!([]))
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn required_tshark_status_lists_the_failed_component() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    let empty_path = temporary.path().join("empty-path");
    fs::create_dir(&empty_path)?;
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let output =
        export_with_tshark_flags(&capture, &destination, &empty_path, &["--require-tshark"])?;

    assert_eq!(output.status.code(), Some(3));
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(
        summary.starts_with("L2Solver capture export\nOverall export: partial (exit status 3)\n")
    );
    assert!(
        summary.contains("Incomplete components:\n- tshark_export:"),
        "{summary}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/tshark/required"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        manifest
            .get("export_status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    assert!(
        manifest
            .get("incomplete_components")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|components| {
                components.iter().any(|component| {
                    component
                        .get("component")
                        .and_then(serde_json::Value::as_str)
                        == Some("tshark_export")
                        && component
                            .get("reason")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|reason| reason.contains("not found"))
                })
            })
    );
    Ok(())
}

#[test]
fn late_artifact_exports() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("late-body.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    let body = tiny_png()?;
    let filler_count = Limits::default().bytes / usize::try_from(l2_pcap::MAX_FRAME_LENGTH)? + 1;
    let capture_bytes = capture_with_late_http(
        &body,
        filler_count,
        usize::try_from(l2_pcap::MAX_FRAME_LENGTH)?,
    )?;
    assert!(capture_bytes.len() > Limits::default().bytes);
    fs::write(&capture, capture_bytes)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;
    if should_retain_export_fixture(&destination, &output) {
        retain_failed_export_fixture(temporary, &destination, &output);
    }

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut matching_artifacts = Vec::new();
    for path in artifact_paths(&destination)? {
        if fs::read(&path)? == body {
            matching_artifacts.push(path);
        }
    }
    assert_eq!(
        matching_artifacts.len(),
        1,
        "late artifact is missing or duplicated"
    );
    assert_eq!(
        fs::read(
            matching_artifacts
                .first()
                .ok_or("late artifact is missing")?
        )?,
        body
    );

    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    assert!(summary.contains("Full-source ingest: complete to EOF"));
    assert!(
        summary.contains(
            "Artifact discovery within retained supported-transport flow Cases, bounded unordered source/scope/IP-pair cohorts, and known TShark object types: complete"
        ),
        "{summary}\n{limitations}"
    );
    assert!(!summary.contains("SHA-256:"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let source_bytes = manifest_u64(&manifest, "/full_source_coverage/source/bytes")?;
    assert!(source_bytes > u64::try_from(Limits::default().bytes)?);
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/analysis/flows")?,
        1
    );
    let provenance = manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .ok_or("late PNG provenance is missing")?;
    assert!(provenance.iter().any(|origin| {
        origin
            .pointer("/selection/validation_evidence_node")
            .and_then(serde_json::Value::as_u64)
            .is_some()
    }));
    Ok(())
}

#[test]
fn late_artifact_after_former_record_limit_exports_with_full_source_coverage()
-> Result<(), Box<dyn Error>> {
    const FORMER_RECORD_LIMIT: usize = 65_536;

    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("late-record-body.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    let body = tiny_png()?;
    let filler_count = FORMER_RECORD_LIMIT + 1;
    let capture_bytes = capture_with_late_http(&body, filler_count, 60)?;
    assert!(capture_bytes.len() < 16 * 1024 * 1024);
    fs::write(&capture, &capture_bytes)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;
    if should_retain_export_fixture(&destination, &output) {
        retain_failed_export_fixture(temporary, &destination, &output);
    }

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let artifacts = artifact_paths(&destination)?;
    let artifact_bytes = artifacts
        .iter()
        .map(|path| Ok((path, fs::read(path)?)))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    assert_eq!(
        artifact_bytes
            .iter()
            .filter(|(_, bytes)| bytes == &body)
            .count(),
        1,
        "late PNG bytes should be exported exactly once: {artifacts:?}"
    );

    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Full-source ingest: complete to EOF"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/source/packet_records")?,
        u64::try_from(filler_count + 2)?
    );
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/source/bytes")?,
        u64::try_from(capture_bytes.len())?
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/source/supported_transport_records"
        )?,
        2
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/source/packets_without_supported_transport"
        )?,
        u64::try_from(filler_count)?
    );
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/analysis/flows")?,
        1
    );
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/analysis/complete_flows")?,
        1
    );
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/analysis/incomplete_flows")?,
        0
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/analysis/omitted_flow_records"
        )?,
        0
    );
    Ok(())
}

#[test]
fn later_same_flow_page_exports_validated_artifact_with_exact_provenance()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("late-same-flow.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    let body = tiny_png()?;
    let (capture_bytes, expected_packet, expected_offset) =
        capture_with_late_same_flow_http(&body)?;
    assert!(capture_bytes.len() > Limits::default().bytes);
    fs::write(&capture, &capture_bytes)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(3),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        fs::read(
            artifacts
                .first()
                .ok_or("late same-flow artifact is missing")?
        )?,
        body
    );

    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    assert!(summary.contains("Per-flow analysis: partial"));
    assert!(summary.contains(
        "Supplementary flow pages: 1 across 1 flows; selected records: 1; retained records: 1; omitted records: 0"
    ));
    assert!(limitations.contains("selected records 1, retained records 1, omitted records 0"));
    assert!(limitations.contains(
        "Supplementary flow pages: 1 across 1 flows; selected records 1; retained records 1; omitted records 0; each page was analyzed independently"
    ));
    assert!(
        limitations.contains("TCP/session/application state was not joined across page boundaries")
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_supplementary_page_coverage(&manifest)?;
    assert_eq!(
        manifest
            .pointer("/discovery_coverage/status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    let source_id = manifest
        .pointer("/full_source_coverage/source/source_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("full-source identity is missing")?;
    assert!(
        manifest_has_exact_origin_range(
            &manifest,
            source_id,
            expected_packet,
            expected_offset,
            u64::try_from(body.len())?
        ),
        "{:#?}",
        manifest.pointer("/artifacts/0/provenance")
    );
    Ok(())
}

fn assert_supplementary_page_coverage(manifest: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let base = "/full_source_coverage/analysis/supplementary_pages";
    for (field, expected) in [
        ("pages", 1),
        ("selected_records", 1),
        ("retained_records", 1),
        ("omitted_records", 0),
    ] {
        assert_eq!(
            manifest_u64(manifest, &format!("{base}/{field}"))?,
            expected
        );
    }
    Ok(())
}

fn manifest_has_exact_origin_range(
    manifest: &serde_json::Value,
    source_id: &str,
    packet: u64,
    offset: u64,
    length: u64,
) -> bool {
    manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|provenance| {
            provenance.iter().any(|origin| {
                origin
                    .pointer("/selection/source_ranges")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|ranges| {
                        ranges.iter().any(|range| {
                            range.get("source").and_then(serde_json::Value::as_str)
                                == Some(source_id)
                                && range.get("packet").and_then(serde_json::Value::as_u64)
                                    == Some(packet)
                                && range.get("offset").and_then(serde_json::Value::as_u64)
                                    == Some(offset)
                                && range.get("length").and_then(serde_json::Value::as_u64)
                                    == Some(length)
                        })
                    })
            })
        })
}

#[test]
fn incomplete_zip_signature_stays_binary() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("incomplete-zip.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(&capture, capture_with_http_body(b"PK\x03\x04")?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(destination.join("summary.txt")).unwrap_or_default()
    );
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(artifacts.len(), 1);
    let artifact = artifacts.first().ok_or("HTTP body is missing")?;
    assert_eq!(
        artifact
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("bin")
    );
    assert_eq!(fs::read(artifact)?, b"PK\x03\x04");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let origin = manifest
        .pointer("/artifacts/0/provenance/0")
        .ok_or("HTTP body provenance is missing")?;
    assert_ne!(
        origin
            .pointer("/selection/validated_as")
            .and_then(serde_json::Value::as_str),
        Some("zip"),
        "an incomplete ZIP signature must not be recorded as validated"
    );
    Ok(())
}

#[test]
fn duplicate_flows_merge() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("duplicate-flows.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(
        &capture,
        capture_with_http_flows(&[(40_000, BODY), (40_001, BODY)])?,
    )?;

    let output = export_with_tshark(&capture, &destination, &executable)?;
    if should_retain_export_fixture(&destination, &output) {
        retain_failed_export_fixture(temporary, &destination, &output);
    }

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let artifacts = artifact_paths(&destination)?;
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        fs::read(
            artifacts
                .first()
                .ok_or("deduplicated artifact is missing")?
        )?,
        BODY
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest_u64(
            &manifest,
            "/discovery_coverage/artifacts/references_retained"
        )?,
        2
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/discovery_coverage/artifacts/unique_artifacts_retained"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/discovery_coverage/artifacts/duplicate_byte_references_grouped"
        )?,
        1
    );
    assert!(
        manifest_u64(
            &manifest,
            "/discovery_coverage/artifacts/same_origin_references_suppressed"
        )? >= 1
    );
    let provenance = manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifact provenance is missing")?;
    assert_eq!(provenance.len(), 2);
    let first_flow = provenance
        .first()
        .and_then(|origin| origin.pointer("/flow/id"))
        .and_then(serde_json::Value::as_i64);
    let second_flow = provenance
        .get(1)
        .and_then(|origin| origin.pointer("/flow/id"))
        .and_then(serde_json::Value::as_i64);
    assert!(first_flow.is_some());
    assert!(second_flow.is_some());
    assert_ne!(first_flow, second_flow);
    Ok(())
}

#[test]
fn cohort_origin_dedup() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("cohort-http.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(&capture, capture_with_http_and_peer(BODY)?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(artifact_paths(&destination)?.len(), 1);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert!(
        manifest_u64(
            &manifest,
            "/discovery_coverage/artifacts/same_origin_references_suppressed"
        )? >= 1
    );
    let provenance = manifest
        .pointer("/artifacts/0/provenance")
        .and_then(serde_json::Value::as_array)
        .ok_or("HTTP artifact provenance is missing")?;
    let native_http_origins = provenance
        .iter()
        .filter(|origin| {
            origin
                .pointer("/category")
                .and_then(serde_json::Value::as_str)
                == Some("native_http_body")
        })
        .count();
    assert_eq!(native_http_origins, 1);
    Ok(())
}

#[test]
fn partial_flow_preserves_artifact() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("limited-flow.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    let chunk_length = 60_000;
    let long_flow_chunks = Limits::default().bytes / (chunk_length + 54) + 1;
    fs::write(
        &capture,
        capture_with_independent_http_and_long_flow(BODY, long_flow_chunks, chunk_length)?,
    )?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(artifact_paths(&destination)?.len(), 1);
    assert_eq!(
        fs::read(
            artifact_paths(&destination)?
                .first()
                .ok_or("independent artifact is missing")?
        )?,
        BODY
    );
    assert_partial_flow_coverage(&destination, long_flow_chunks)?;
    Ok(())
}

#[test]
fn reports_default_limit_reconstruction_omissions_from_supplementary_pages()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("supplementary-range-omission.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    fs::write(&capture, capture_with_supplementary_range_omission()?)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(
        output.status.code(),
        Some(3),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;

    assert_eq!(
        manifest
            .pointer("/discovery_coverage/status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/analysis/supplementary_pages/pages"
        )?,
        2
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/analysis/supplementary_pages/selected_records"
        )?,
        u64::try_from(Limits::default().units + 2)?
    );
    assert_exact_supplementary_reconstruction_omissions(&manifest)?;
    let page_omissions = "Supplementary page reconstruction omissions: 0 TCP records, 0 fragments, 1 ranges, 1 TCP byte positions affected by omitted observations or rejected ranges, 1 TCP observations, 0 fragment byte positions affected by omitted observations or rejected ranges, 0 fragment observations, 0 state observations, 0 unmeasured ranges (in 1 of 2 Cases)";
    assert!(summary.contains("Per-flow analysis: partial"));
    assert!(summary.contains(page_omissions), "{summary}");
    assert!(limitations.contains(page_omissions), "{limitations}");
    Ok(())
}

fn assert_exact_supplementary_reconstruction_omissions(
    manifest: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let page = "/full_source_coverage/analysis/supplementary_pages/reconstruction_omissions";
    for (field, expected) in [
        ("cases", 2),
        ("cases_with_omissions", 1),
        ("omitted_tcp_records", 0),
        ("omitted_fragments", 0),
        ("omitted_sequence_ranges", 1),
        ("omitted_tcp_bytes", 1),
        ("omitted_tcp_observations", 1),
        ("omitted_fragment_bytes", 0),
        ("omitted_fragment_observations", 0),
        ("unmeasured_omitted_ranges", 0),
        ("omitted_state_observations", 0),
    ] {
        assert_eq!(
            manifest_u64(manifest, &format!("{page}/{field}"))?,
            expected,
            "unexpected supplementary-page reconstruction counter: {field}"
        );
    }
    for field in [
        "omitted_tcp_records",
        "omitted_fragments",
        "omitted_sequence_ranges",
        "omitted_tcp_bytes",
        "omitted_tcp_observations",
        "omitted_fragment_bytes",
        "omitted_fragment_observations",
        "unmeasured_omitted_ranges",
        "omitted_state_observations",
    ] {
        assert_eq!(
            manifest_u64(manifest, &format!("/full_source_coverage/analysis/{field}"))?,
            0,
            "supplementary-page omission leaked into primary flow coverage: {field}"
        );
    }
    Ok(())
}

fn assert_partial_flow_coverage(
    destination: &Path,
    long_flow_chunks: usize,
) -> Result<(), Box<dyn Error>> {
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    let chunks = u64::try_from(long_flow_chunks)?;

    assert_partial_flow_summary(&summary);
    assert_partial_flow_record_coverage(&manifest, chunks)?;
    assert_partial_flow_reconstruction_coverage(&manifest, &summary)?;
    assert_partial_flow_limitations(&limitations, long_flow_chunks);
    assert_partial_cohort_coverage(&manifest)?;
    assert_eq!(
        manifest
            .pointer("/discovery_coverage/status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    Ok(())
}

fn assert_partial_flow_summary(summary: &str) {
    assert!(summary.contains("Full-source ingest: complete to EOF"));
    assert!(summary.contains("Per-flow analysis: partial"));
    assert!(summary.contains("and known TShark object types: partial"));
    assert!(
        summary.contains(
            "Supplementary flow pages: 1 across 1 flows; selected records: 1; retained records: 1; omitted records: 0"
        ),
        "{summary}"
    );
}

fn assert_partial_flow_record_coverage(
    manifest: &serde_json::Value,
    chunks: u64,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        manifest_u64(manifest, "/full_source_coverage/analysis/flows")?,
        2
    );
    assert_eq!(
        manifest_u64(manifest, "/full_source_coverage/analysis/incomplete_flows")?,
        1
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/selected_flow_records"
        )?,
        3 + chunks
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/retained_flow_records"
        )?,
        2 + chunks
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/omitted_flow_records"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(manifest, "/full_source_coverage/analysis/flows")?,
        2
    );
    assert_partial_page_record_coverage(manifest)?;
    Ok(())
}

fn assert_partial_page_record_coverage(manifest: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let base = "/full_source_coverage/analysis/supplementary_pages";
    assert_eq!(manifest_u64(manifest, &format!("{base}/flows"))?, 1);
    assert_eq!(manifest_u64(manifest, &format!("{base}/pages"))?, 1);
    assert_eq!(
        manifest_u64(manifest, &format!("{base}/selected_records"))?,
        1
    );
    assert_eq!(
        manifest_u64(manifest, &format!("{base}/retained_records"))?,
        1
    );
    assert_eq!(
        manifest_u64(manifest, &format!("{base}/omitted_records"))?,
        0
    );
    Ok(())
}

fn assert_partial_flow_reconstruction_coverage(
    manifest: &serde_json::Value,
    summary: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/omitted_tcp_records"
        )?,
        0
    );
    assert_eq!(
        manifest_u64(manifest, "/full_source_coverage/analysis/omitted_fragments")?,
        0
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/omitted_sequence_ranges"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/omitted_state_observations"
        )?,
        0
    );
    assert_eq!(
        manifest_u64(manifest, "/full_source_coverage/analysis/omitted_tcp_bytes")?,
        12_600_000
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/omitted_tcp_observations"
        )?,
        210
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/unmeasured_omitted_ranges"
        )?,
        0
    );
    assert!(summary.contains(
        "Flow reconstruction omissions: 0 TCP records, 0 fragments, 1 ranges, 12600000 TCP byte positions affected by omitted observations or rejected ranges, 210 TCP observations, 0 fragment byte positions affected by omitted observations or rejected ranges, 0 fragment observations, 0 state observations, 0 unmeasured ranges (in 1 of 2 Cases)"
    ), "{summary}");
    Ok(())
}

fn assert_partial_flow_limitations(limitations: &str, long_flow_chunks: usize) {
    assert!(limitations.contains("1 split groups"));
    assert!(limitations.contains("1 oversized flows skipped"));
    assert!(limitations.contains(
        "Supplementary flow pages: 1 across 1 flows; selected records 1; retained records 1; omitted records 0; each page was analyzed independently"
    ));
    let selected = 1 + long_flow_chunks;
    let retained = long_flow_chunks;
    assert!(limitations.contains(&format!(
        "Flow analysis selected {selected} records, retained {retained}, and omitted 1; retention ceilings reached: bytes; reconstruction omissions: 0 TCP records, 0 fragments, 1 ranges, 12600000 TCP byte positions affected by omitted observations or rejected ranges, 210 TCP observations, 0 fragment byte positions affected by omitted observations or rejected ranges, 0 fragment observations, 0 state observations, 0 unmeasured ranges"
    )), "{limitations}");
    assert!(
        limitations
            .lines()
            .any(|line| { line.starts_with("- Flow ") && line.contains("Flow analysis selected") })
    );
}

fn assert_partial_cohort_coverage(manifest: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/cohort_analysis/split_groups"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/cohort_analysis/oversized_flows_skipped"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/selection_truncated_flows"
        )?,
        1
    );
    assert_eq!(
        manifest_u64(
            manifest,
            "/full_source_coverage/analysis/byte_limited_flows"
        )?,
        1
    );
    Ok(())
}

#[test]
fn stdin_reports_tshark_omission() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = capture_with_http_body(BODY)?;
    for (label, flags, expected_status) in [
        ("optional", &[][..], 0),
        ("required", &["--require-tshark"][..], 3),
    ] {
        let destination = temporary.path().join(label);
        let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("extract")
            .arg("-")
            .arg("--output")
            .arg(&destination)
            .args(flags)
            .env("PATH", temporary.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("child standard input is unavailable")?
            .write_all(&capture)?;
        let output = child.wait_with_output()?;

        assert_eq!(output.status.code(), Some(expected_status));
        let artifacts = artifact_paths(&destination)?;
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            fs::read(artifacts.first().ok_or("stdin artifact is missing")?)?,
            BODY
        );
        let summary = fs::read_to_string(destination.join("summary.txt"))?;
        assert!(summary.contains("TShark export omitted for standard input"));
        assert!(
        summary.contains(
            "Artifact discovery within retained supported-transport flow Cases, bounded unordered source/scope/IP-pair cohorts, and known TShark object types: partial"
        )
    );
    }
    Ok(())
}

#[test]
fn fragmented_packet_scope() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("mixed-flow.pcap");
    let destination = temporary.path().join("output");
    let executable = install_tshark(temporary.path(), "")?;
    let mut bytes = capture_with_http_body(BODY)?;
    append_record(&mut bytes, 2, &ipv4_fragment_frame()?)?;
    fs::write(&capture, &bytes)?;

    let output = export_with_tshark(&capture, &destination, &executable)?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(artifact_paths(&destination)?.len(), 1);
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Full-source ingest: complete to EOF"));
    assert!(summary.contains(
        "Artifact discovery within retained supported-transport flow Cases, bounded unordered source/scope/IP-pair cohorts, and known TShark object types: complete"
    ));
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    assert!(limitations.contains("1 packets without supported transport are outside that scope"));
    assert!(limitations.contains("fragments not assigned to an indexed flow"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .get("export_status")
            .and_then(serde_json::Value::as_str),
        Some("complete")
    );
    assert_eq!(
        manifest
            .pointer("/discovery_coverage/status")
            .and_then(serde_json::Value::as_str),
        Some("complete")
    );
    let incomplete_components = manifest
        .get("incomplete_components")
        .and_then(serde_json::Value::as_array)
        .ok_or("incomplete components are missing")?;
    assert!(incomplete_components.is_empty());
    assert!(
        summary.starts_with("L2Solver capture export\nOverall export: complete (exit status 0)\n")
    );
    assert_eq!(
        manifest_u64(&manifest, "/full_source_coverage/source/bytes")?,
        u64::try_from(bytes.len())?
    );
    assert_eq!(
        manifest_u64(
            &manifest,
            "/full_source_coverage/source/packets_without_supported_transport"
        )?,
        1
    );
    Ok(())
}

fn export(capture: &Path, destination: Option<&Path>) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
    command.arg("export").arg(capture);
    if let Some(destination) = destination {
        command.arg("--output").arg(destination);
    }
    run_with_private_xdg_directories(command)
}

fn run_with_private_xdg_directories(mut command: Command) -> Result<Output, std::io::Error> {
    let directories = tempfile::tempdir()?;
    let cache_home = directories.path().join("cache");
    let state_home = directories.path().join("state");
    fs::create_dir(&cache_home)?;
    fs::create_dir(&state_home)?;
    command
        .env("XDG_CACHE_HOME", cache_home)
        .env("XDG_STATE_HOME", state_home);
    command.output()
}

fn should_retain_export_fixture(destination: &Path, output: &Output) -> bool {
    output.status.code() != Some(0) || !destination.is_dir()
}

fn retain_failed_export_fixture(temporary: tempfile::TempDir, destination: &Path, output: &Output) {
    let fixture = temporary.keep();
    eprintln!("failed export fixture retained at {}", fixture.display());
    eprintln!("destination: {}", destination.display());
    for report_name in ["summary.txt", "limitations.txt"] {
        let Ok(report) = fs::read_to_string(destination.join(report_name)) else {
            continue;
        };
        eprintln!("{report_name} excerpt:");
        let summary = report_name == "summary.txt";
        for line in report
            .lines()
            .filter(|line| summary || line.starts_with("- "))
            .take(6)
        {
            let excerpt = line.chars().take(360).collect::<String>();
            eprintln!("  {excerpt}");
        }
    }
    eprintln!(
        "stdout excerpt: {}",
        String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(800)
            .collect::<String>()
    );
    eprintln!(
        "stderr excerpt: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(800)
            .collect::<String>()
    );
}

fn is_report(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name == "summary.txt"
            || name == "limitations.txt"
            || name == "manifest.json"
            || name == "evidence.jsonl"
            || name == "evidence.jsonl.gz"
    })
}

fn manifest_u64(manifest: &serde_json::Value, pointer: &str) -> Result<u64, Box<dyn Error>> {
    manifest
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("manifest count is missing at {pointer}").into())
}

fn artifact_paths(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    Ok(fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| !is_report(path))
        .collect())
}

fn export_with_tshark(
    capture: &Path,
    destination: &Path,
    executable_directory: &Path,
) -> Result<Output, std::io::Error> {
    export_with_tshark_flags(capture, destination, executable_directory, &[])
}

fn export_with_tshark_flags(
    capture: &Path,
    destination: &Path,
    executable_directory: &Path,
    flags: &[&str],
) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
    command
        .arg("export")
        .arg(capture)
        .arg("--output")
        .arg(destination)
        .args(flags)
        .env("PATH", executable_directory);
    run_with_private_xdg_directories(command)
}

#[cfg(unix)]
fn find_program(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let search_path = std::env::var_os("PATH").ok_or("PATH is unavailable")?;
    for directory in std::env::split_paths(&search_path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate.canonicalize()?);
        }
    }
    Err(format!("required test program is unavailable: {name}").into())
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[cfg(unix)]
fn install_tshark(directory: &Path, export: &str) -> Result<PathBuf, Box<dyn Error>> {
    install_tshark_for_protocol(directory, &["http", "ftp-data"], "http", export)
}

#[cfg(unix)]
fn install_tshark_for_protocol(
    directory: &Path,
    protocols: &[&str],
    export_protocol: &str,
    export: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    if protocols.is_empty()
        || !protocols.contains(&export_protocol)
        || protocols.iter().any(|protocol| {
            protocol.is_empty()
                || !protocol
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("fake TShark protocol types must be safe listed names".into());
    }
    let type_list = protocols
        .iter()
        .map(|protocol| format!("'     {protocol}'"))
        .collect::<Vec<_>>()
        .join(" ");

    let executable_directory = directory.join("fake-bin");
    fs::create_dir(&executable_directory)?;
    let executable = executable_directory.join("tshark");
    let script = r#"#!/bin/sh
set -eu
for argument in "$@"; do
  if [ "$argument" = help ]; then
    printf '%s\n' 'The available export object types for the "--export-objects" option are:' __TYPE_LIST__
    exit 0
  fi
done
capture_file=
destination=
read_capture=0
for argument in "$@"; do
  if [ "$read_capture" -eq 1 ]; then capture_file=$argument; read_capture=0; continue; fi
  case "$argument" in
    -r) read_capture=1 ;;
  esac
done
case "$capture_file" in *'/.l2solver-'*'/capture.bin') ;; *) exit 67 ;; esac
[ -f "$capture_file" ] && [ ! -L "$capture_file" ] || exit 68
for argument in "$@"; do
  case "$argument" in
    __EXPORT_PROTOCOL__,*) destination="${argument#__EXPORT_PROTOCOL__,}"; [ -d "$destination" ] || exit 69; __EXPORT__ ;;
  esac
done
exit 0
"#
    .replace("__TYPE_LIST__", &type_list)
    .replace("__EXPORT_PROTOCOL__", export_protocol)
    .replace("__EXPORT__", export);
    fs::write(&executable, script)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    Ok(executable_directory)
}

fn empty_capture() -> Vec<u8> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes
}

fn tiny_png() -> Result<Vec<u8>, Box<dyn Error>> {
    tiny_png_with_rgb([1, 2, 3])
}

fn tiny_png_with_rgb(pixel: [u8; 3]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header()?.write_image_data(&pixel)?;
    }
    Ok(bytes)
}

fn stored_archive(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let output = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(output);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in entries {
        archive.start_file(*name, options)?;
        archive.write_all(bytes)?;
    }
    Ok(archive.finish()?.into_inner())
}

fn capture_with_http_body(body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    capture_with_declared_http_body(body, body.len())
}

fn capture_with_partial_http_body(body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let declared = body.len().checked_add(1).ok_or("body length overflow")?;
    capture_with_declared_http_body(body, declared)
}

fn capture_with_declared_http_body(
    body: &[u8],
    declared_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {declared_length}\r\n\r\n"
    );
    let mut payload = payload.into_bytes();
    payload.extend_from_slice(body);

    let frames = [tcp_frame(100, 0x02, b"")?, tcp_frame(101, 0x18, &payload)?];
    capture_from_frames(&frames)
}

fn capture_with_ftp_candidate(body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let epsv_reply = b"229 Entering Extended Passive Mode (|||10000|)\r\n";
    let retrieve = b"RETR example.txt\r\n";
    let preliminary = b"150 Opening data connection\r\n";
    let completed = b"226 Transfer complete\r\n";
    let server_control_sequence = 501_u32;
    let after_epsv_reply = server_control_sequence
        .checked_add(u32::try_from(epsv_reply.len())?)
        .ok_or("FTP control sequence overflow")?;
    let after_retrieve = 107_u32
        .checked_add(u32::try_from(retrieve.len())?)
        .ok_or("FTP control sequence overflow")?;
    let after_preliminary = after_epsv_reply
        .checked_add(u32::try_from(preliminary.len())?)
        .ok_or("FTP control sequence overflow")?;
    let after_data = 801_u32
        .checked_add(u32::try_from(body.len())?)
        .ok_or("FTP data sequence overflow")?;

    let frames = vec![
        tcp_frame_on_connection(40_000, 21, false, 100, 0, 0x02, b"")?,
        tcp_frame_on_connection(40_000, 21, true, 500, 101, 0x12, b"")?,
        tcp_frame_on_connection(40_000, 21, false, 101, 501, 0x18, b"EPSV\r\n")?,
        tcp_frame_on_connection(40_000, 21, true, 501, 107, 0x18, epsv_reply)?,
        tcp_frame_on_connection(40_001, 10_000, false, 400, 0, 0x02, b"")?,
        tcp_frame_on_connection(40_001, 10_000, true, 800, 401, 0x12, b"")?,
        tcp_frame_on_connection(40_001, 10_000, false, 401, 801, 0x10, b"")?,
        tcp_frame_on_connection(40_000, 21, false, 107, after_epsv_reply, 0x18, retrieve)?,
        tcp_frame_on_connection(
            40_000,
            21,
            true,
            after_epsv_reply,
            after_retrieve,
            0x18,
            preliminary,
        )?,
        tcp_frame_on_connection(40_001, 10_000, true, 801, 401, 0x18, body)?,
        tcp_frame_on_connection(40_001, 10_000, false, 401, after_data, 0x10, b"")?,
        tcp_frame_on_connection(40_001, 10_000, true, after_data, 401, 0x11, b"")?,
        tcp_frame_on_connection(
            40_000,
            21,
            true,
            after_preliminary,
            after_retrieve,
            0x18,
            completed,
        )?,
    ];
    capture_from_frames(&frames)
}

fn capture_with_late_http(
    body: &[u8],
    filler_count: usize,
    filler_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = empty_capture();
    let filler = filler_frame(filler_length)?;
    let mut record_number = 0_u32;
    for _ in 0..filler_count {
        append_record(&mut capture, record_number, &filler)?;
        record_number = record_number
            .checked_add(1)
            .ok_or("synthetic capture record number overflow")?;
    }
    append_frames(
        &mut capture,
        &mut record_number,
        &http_flow_frames(40_000, 443, body)?,
    )?;
    Ok(capture)
}

struct LateSameFlowPrefix {
    record_timestamp: u32,
    selected_record_count: u64,
    sequence: u32,
}

fn append_full_same_flow_prefix(
    capture: &mut Vec<u8>,
    limits: Limits,
) -> Result<LateSameFlowPrefix, Box<dyn Error>> {
    let mut record_timestamp = 0_u32;
    let mut selected_record_count = 0_u64;
    let mut sequence = 100_u32;
    let syn = tcp_frame_on_connection(40_000, 443, false, sequence, 0, 0x02, b"")?;
    let retained_prefix_bytes = u64::try_from(syn.len())?;
    append_record(capture, record_timestamp, &syn)?;
    record_timestamp = record_timestamp
        .checked_add(1)
        .ok_or("synthetic capture timestamp overflow")?;
    selected_record_count = selected_record_count
        .checked_add(1)
        .ok_or("synthetic packet count overflow")?;
    sequence = sequence
        .checked_add(1)
        .ok_or("synthetic TCP sequence number overflow")?;

    let payload = vec![b'x'; 60_000];
    let full_data = tcp_frame_on_connection(40_000, 443, false, sequence, 0, 0x18, &payload)?;
    let full_frame_bytes = full_data.len();
    let remaining = limits
        .bytes
        .checked_sub(syn.len())
        .ok_or("synthetic prefix exceeds the reconstruction byte limit")?;
    let full_chunks = remaining / full_frame_bytes;
    let partial_frame_bytes = remaining % full_frame_bytes;
    let partial_payload_bytes = partial_frame_bytes
        .checked_sub(full_data.len() - payload.len())
        .ok_or("synthetic page boundary cannot be filled with TCP payload")?;

    let payload_length = u32::try_from(payload.len())?;
    let mut prefix_bytes = retained_prefix_bytes;
    for _ in 0..full_chunks {
        let frame = tcp_frame_on_connection(40_000, 443, false, sequence, 0, 0x18, &payload)?;
        append_record(capture, record_timestamp, &frame)?;
        record_timestamp = record_timestamp
            .checked_add(1)
            .ok_or("synthetic capture timestamp overflow")?;
        selected_record_count = selected_record_count
            .checked_add(1)
            .ok_or("synthetic packet count overflow")?;
        prefix_bytes = prefix_bytes
            .checked_add(u64::try_from(frame.len())?)
            .ok_or("synthetic prefix byte count overflow")?;
        sequence = sequence
            .checked_add(payload_length)
            .ok_or("synthetic TCP sequence number overflow")?;
    }
    if partial_payload_bytes != 0 {
        let partial_payload = vec![b'x'; partial_payload_bytes];
        let frame =
            tcp_frame_on_connection(40_000, 443, false, sequence, 0, 0x18, &partial_payload)?;
        append_record(capture, record_timestamp, &frame)?;
        record_timestamp = record_timestamp
            .checked_add(1)
            .ok_or("synthetic capture timestamp overflow")?;
        selected_record_count = selected_record_count
            .checked_add(1)
            .ok_or("synthetic packet count overflow")?;
        prefix_bytes = prefix_bytes
            .checked_add(u64::try_from(frame.len())?)
            .ok_or("synthetic prefix byte count overflow")?;
        sequence = sequence
            .checked_add(u32::try_from(partial_payload.len())?)
            .ok_or("synthetic TCP sequence number overflow")?;
    }
    if prefix_bytes != u64::try_from(limits.bytes)? {
        return Err("synthetic flow prefix did not exactly fill its reconstruction budget".into());
    }

    Ok(LateSameFlowPrefix {
        record_timestamp,
        selected_record_count,
        sequence,
    })
}

fn capture_with_late_same_flow_http(body: &[u8]) -> Result<(Vec<u8>, u64, u64), Box<dyn Error>> {
    let mut capture = empty_capture();
    let prefix = append_full_same_flow_prefix(&mut capture, Limits::default())?;

    let header = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request_payload = header.as_bytes().to_vec();
    request_payload.extend_from_slice(body);
    let request_frame = tcp_frame_on_connection(
        40_000,
        443,
        false,
        prefix.sequence,
        0,
        0x18,
        &request_payload,
    )?;
    let frame_header_length = request_frame
        .len()
        .checked_sub(request_payload.len())
        .ok_or("synthetic request frame is shorter than its payload")?;
    let body_offset = u64::try_from(capture.len())?
        .checked_add(16)
        .and_then(|offset| offset.checked_add(u64::try_from(frame_header_length).ok()?))
        .and_then(|offset| offset.checked_add(u64::try_from(header.len()).ok()?))
        .ok_or("synthetic artifact source offset overflow")?;
    let packet_number = prefix
        .selected_record_count
        .checked_add(1)
        .ok_or("synthetic packet number overflow")?;
    append_record(&mut capture, prefix.record_timestamp, &request_frame)?;
    Ok((capture, packet_number, body_offset))
}

fn capture_with_http_flows(flows: &[(u16, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = empty_capture();
    let mut record_number = 0_u32;
    for (client_port, body) in flows {
        append_frames(
            &mut capture,
            &mut record_number,
            &http_flow_frames(*client_port, 443, body)?,
        )?;
    }
    Ok(capture)
}

fn capture_with_http_and_peer(body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = empty_capture();
    let mut record_number = 0_u32;
    append_frames(
        &mut capture,
        &mut record_number,
        &http_flow_frames(40_000, 443, body)?,
    )?;
    let peer_frames = [
        tcp_frame_on_connection(40_001, 9_001, false, 100, 0, 0x02, b"")?,
        tcp_frame_on_connection(40_001, 9_001, false, 101, 0, 0x18, b"peer traffic")?,
    ];
    append_frames(&mut capture, &mut record_number, &peer_frames)?;
    Ok(capture)
}

fn capture_with_independent_http_and_long_flow(
    body: &[u8],
    long_flow_chunks: usize,
    chunk_length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = empty_capture();
    let mut record_number = 0_u32;
    append_frames(
        &mut capture,
        &mut record_number,
        &http_flow_frames(40_000, 443, body)?,
    )?;

    let mut sequence = 100_u32;
    let syn = tcp_frame_on_connection(40_001, 9_001, false, sequence, 0, 0x02, b"")?;
    append_record(&mut capture, record_number, &syn)?;
    record_number = record_number
        .checked_add(1)
        .ok_or("synthetic capture record number overflow")?;
    sequence = sequence
        .checked_add(1)
        .ok_or("synthetic TCP sequence number overflow")?;

    let payload = vec![b'x'; chunk_length];
    let payload_length = u32::try_from(chunk_length)?;
    for _ in 0..long_flow_chunks {
        let frame = tcp_frame_on_connection(40_001, 9_001, false, sequence, 0, 0x18, &payload)?;
        append_record(&mut capture, record_number, &frame)?;
        record_number = record_number
            .checked_add(1)
            .ok_or("synthetic capture record number overflow")?;
        sequence = sequence
            .checked_add(payload_length)
            .ok_or("synthetic TCP sequence number overflow")?;
    }
    Ok(capture)
}

fn http_flow_frames(
    client_port: u16,
    server_port: u16,
    body: &[u8],
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    Ok(vec![
        tcp_frame_on_connection(client_port, server_port, false, 100, 0, 0x02, b"")?,
        tcp_frame_on_connection(client_port, server_port, false, 101, 0, 0x18, &request)?,
    ])
}

fn append_frames(
    capture: &mut Vec<u8>,
    next_record: &mut u32,
    frames: &[Vec<u8>],
) -> Result<(), Box<dyn Error>> {
    for frame in frames {
        append_record(capture, *next_record, frame)?;
        *next_record = next_record
            .checked_add(1)
            .ok_or("synthetic capture record number overflow")?;
    }
    Ok(())
}

fn append_record(capture: &mut Vec<u8>, number: u32, frame: &[u8]) -> Result<(), Box<dyn Error>> {
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&number.to_le_bytes());
    let length = u32::try_from(frame.len())?;
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(frame);
    Ok(())
}

fn filler_frame(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = vec![0; length];
    frame
        .get_mut(12..14)
        .ok_or("synthetic filler frame is too short")?
        .copy_from_slice(&0x88b5_u16.to_be_bytes());
    Ok(frame)
}

fn ipv4_fragment_frame() -> Result<Vec<u8>, Box<dyn Error>> {
    let payload = b"fragment";
    let total_length = 20_u16
        .checked_add(u16::try_from(payload.len())?)
        .ok_or("fragment length overflow")?;
    let mut frame = vec![0; 14 + 20];
    write_frame_bytes(&mut frame, 12, &0x0800_u16.to_be_bytes())?;
    write_frame_byte(&mut frame, 14, 0x45)?;
    write_frame_bytes(&mut frame, 16, &total_length.to_be_bytes())?;
    write_frame_bytes(&mut frame, 18, &42_u16.to_be_bytes())?;
    write_frame_bytes(&mut frame, 20, &0x2001_u16.to_be_bytes())?;
    write_frame_byte(&mut frame, 22, 64)?;
    write_frame_byte(&mut frame, 23, 17)?;
    write_frame_bytes(&mut frame, 26, &[192, 0, 2, 30])?;
    write_frame_bytes(&mut frame, 30, &[198, 51, 100, 40])?;
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn write_frame_byte(frame: &mut [u8], offset: usize, value: u8) -> Result<(), Box<dyn Error>> {
    *frame
        .get_mut(offset)
        .ok_or("synthetic frame field is out of range")? = value;
    Ok(())
}

fn write_frame_bytes(frame: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or("synthetic frame range overflow")?;
    frame
        .get_mut(offset..end)
        .ok_or("synthetic frame field is out of range")?
        .copy_from_slice(bytes);
    Ok(())
}

fn capture_from_frames(frames: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = empty_capture();
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

fn capture_with_supplementary_range_omission() -> Result<Vec<u8>, Box<dyn Error>> {
    let limits = Limits::default();
    let page_observations = l2_workbench::tcp_range::MAX_OBSERVATIONS
        .checked_add(1)
        .ok_or("synthetic page observation count overflow")?;
    let total_records = limits
        .units
        .checked_mul(2)
        .and_then(|records| records.checked_add(2))
        .ok_or("synthetic supplementary capture record count overflow")?;
    let mut frames = Vec::with_capacity(total_records);

    frames.push(tcp_frame(100, 0x02, b"")?);
    for _ in 1..limits.units {
        frames.push(tcp_frame(101, 0x10, b"")?);
    }
    for offset in 0..page_observations {
        let sequence = 10_000_u32
            .checked_add(u32::try_from(offset)?)
            .ok_or("synthetic TCP sequence number overflow")?;
        frames.push(tcp_frame(sequence, 0x18, b"x")?);
    }
    let sequence_after_data = 10_000_u32
        .checked_add(u32::try_from(page_observations)?)
        .ok_or("synthetic TCP sequence number overflow")?;
    for _ in page_observations..limits.units {
        frames.push(tcp_frame(sequence_after_data, 0x10, b"")?);
    }
    for _ in 0..2 {
        frames.push(tcp_frame(sequence_after_data, 0x10, b"")?);
    }
    capture_from_frames(&frames)
}

fn tcp_frame(sequence: u32, flags: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    tcp_frame_on_connection(40_000, 443, false, sequence, 0, flags, payload)
}

fn tcp_frame_on_connection(
    client_port: u16,
    server_port: u16,
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
    let (source_address, destination_address, source_port, destination_port) = if reverse {
        ([192, 0, 2, 20], [192, 0, 2, 10], server_port, client_port)
    } else {
        ([192, 0, 2, 10], [192, 0, 2, 20], client_port, server_port)
    };
    frame.extend_from_slice(&source_address);
    frame.extend_from_slice(&destination_address);
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

#[test]
fn packet_block_drop_count_makes_full_source_export_partial() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("packet-block-drops.pcapng");
    let destination = temporary.path().join("output");
    let source = capture_with_packet_block_drops(&capture_with_http_body(BODY)?, 7)?;
    fs::write(&capture, source)?;

    let output = export(&capture, Some(&destination))?;

    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = fs::read_to_string(destination.join("summary.txt"))?;
    assert!(summary.contains("Overall export: partial (exit status 3)"));
    let limitations = fs::read_to_string(destination.join("limitations.txt"))?;
    assert!(
        limitations
            .contains("Obsolete Packet Blocks report 7 packets dropped between captured packets")
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest
            .get("export_status")
            .and_then(serde_json::Value::as_str),
        Some("partial")
    );
    assert_eq!(
        manifest
            .pointer("/full_source_coverage/source/collection_summary/packet_block_packets_dropped")
            .and_then(serde_json::Value::as_u64),
        Some(7)
    );
    Ok(())
}

fn capture_with_packet_block_drops(
    classic_capture: &[u8],
    drops_count: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut reader = l2_pcap::CaptureReader::new(Cursor::new(classic_capture))?;
    let first = reader.next_packet()?.ok_or("capture has no packets")?;
    let timestamp = first
        .metadata()
        .timestamp()
        .ok_or("capture packet has no timestamp")?;
    let configuration = l2_pcap::InterfaceConfig::new_with_link_type(
        first.metadata().link_type(),
        65_535,
        timestamp.resolution(),
        timestamp.offset_seconds(),
        first.metadata().fcs(),
    )?;
    let mut writer = l2_pcap::PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(first.metadata().interface(), configuration)?;
    writer.write_frame(&first)?;
    while let Some(frame) = reader.next_packet()? {
        writer.write_frame(&frame)?;
    }
    writer.finish()?;
    let mut bytes = writer.into_inner();
    let mut cursor = 0_usize;
    let mut packet_blocks = 0_u32;
    while cursor < bytes.len() {
        let header_end = cursor.checked_add(8).ok_or("block header overflow")?;
        let header = bytes
            .get(cursor..header_end)
            .ok_or("truncated generated block header")?;
        let block_type_bytes: [u8; 4] = header
            .get(..4)
            .ok_or("generated block type is missing")?
            .try_into()?;
        let block_length_bytes: [u8; 4] = header
            .get(4..8)
            .ok_or("generated block length is missing")?
            .try_into()?;
        let block_type = u32::from_le_bytes(block_type_bytes);
        let block_length = usize::try_from(u32::from_le_bytes(block_length_bytes))?;
        let block_end = cursor
            .checked_add(block_length)
            .ok_or("generated block length overflow")?;
        if block_length < 12 || block_end > bytes.len() {
            return Err("invalid generated block length".into());
        }
        if block_type == 6 {
            bytes
                .get_mut(cursor..cursor + 4)
                .ok_or("packet block type field is missing")?
                .copy_from_slice(&2_u32.to_le_bytes());
            if packet_blocks == 1 {
                bytes
                    .get_mut(cursor + 10..cursor + 12)
                    .ok_or("packet block drops field is missing")?
                    .copy_from_slice(&drops_count.to_le_bytes());
            }
            packet_blocks = packet_blocks
                .checked_add(1)
                .ok_or("packet block count overflow")?;
        }
        cursor = block_end;
    }
    if packet_blocks < 2 {
        return Err("generated capture needs two enhanced packet blocks".into());
    }
    Ok(bytes)
}
