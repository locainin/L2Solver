use super::*;

pub fn extraction_command(root: &Path, capture: &Path, destination: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
    command
        .arg("extract")
        .arg(capture)
        .arg("-o")
        .arg(destination)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"));
    command
}

#[test]
fn identical_extraction_reuses_the_published_result() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    let destination = root.join("result");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    let first = extraction_command(root, &capture, &destination).output()?;
    assert!(matches!(first.status.code(), Some(0 | 3)));
    let before = fs::read(destination.join("manifest.json"))?;
    let second = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(second.status.code(), first.status.code());
    assert!(String::from_utf8_lossy(&second.stdout).contains("Reused"));
    assert_eq!(fs::read(destination.join("manifest.json"))?, before);
    Ok(())
}

#[test]
fn older_evidence_compression_policy_does_not_reuse_the_published_result()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    let destination = root.join("result");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    let first = extraction_command(root, &capture, &destination).output()?;
    assert!(
        matches!(first.status.code(), Some(0 | 3)),
        "extraction failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let manifest_path = destination.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let settings = manifest
        .pointer_mut("/l2solver_result/identity/settings")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("result settings are missing")?;
    assert!(settings.remove("evidence_compression_policy").is_some());
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let stale = extraction_command(root, &capture, &destination).output()?;
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("policy or algorithm version differs"));
    assert!(!String::from_utf8_lossy(&stale.stdout).contains("Reused"));
    Ok(())
}

#[test]
fn warm_cached_extraction_matches_cold_and_uncached_outputs() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    let cold_destination = root.join("cold");
    let warm_destination = root.join("warm");
    let uncached_destination = root.join("uncached");
    fs::write(&capture, capture_with_http_body(BODY)?)?;

    let cold = extraction_command(root, &capture, &cold_destination)
        .args(["--progress", "json"])
        .output()?;
    let warm = extraction_command(root, &capture, &warm_destination)
        .args(["--progress", "json"])
        .output()?;
    let uncached = extraction_command(root, &capture, &uncached_destination)
        .args(["--no-cache", "--progress", "json"])
        .output()?;

    for result in [&cold, &warm, &uncached] {
        assert_eq!(
            result.status.code(),
            Some(0),
            "extract failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(warm.status.code(), cold.status.code());
    assert_eq!(uncached.status.code(), cold.status.code());

    assert_export_outputs_match(&cold_destination, &warm_destination)?;
    assert_export_outputs_match(&cold_destination, &uncached_destination)?;

    let cold_counters = result_counters(&cold_destination)?;
    let warm_counters = result_counters(&warm_destination)?;
    let uncached_counters = result_counters(&uncached_destination)?;
    assert_eq!(cold_counters.ingestion_state, "completed");
    assert_eq!(warm_counters.ingestion_state, "skipped");
    assert_eq!(uncached_counters.ingestion_state, "completed");
    assert!(
        cold_counters.cache_misses > 0,
        "cold run did not write cache work"
    );
    assert!(
        cold_counters.candidates_examined > 0,
        "cold run did no recovery work"
    );
    assert!(warm_counters.cache_hits > cold_counters.cache_hits);
    assert!(
        warm_counters.candidates_examined < cold_counters.candidates_examined,
        "warm run did not skip completed recovery work"
    );
    assert_eq!(uncached_counters.cache_hits, 0);
    assert_eq!(uncached_counters.cache_misses, 0);
    assert_eq!(
        uncached_counters.candidates_examined, cold_counters.candidates_examined,
        "no-cache run should recompute the same recovery candidates"
    );
    assert_eq!(fs::read(&capture)?, capture_with_http_body(BODY)?);
    Ok(())
}

#[test]
fn moved_and_copied_capture_cache_reuse_matches_uncached_origins() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let original = root.join("original.pcap");
    let moved = root.join("moved.pcap");
    let copied = root.join("copied.pcap");
    let later_copy = root.join("later-copy.pcap");
    let cold_destination = root.join("cold");
    let moved_destination = root.join("moved");
    let moved_uncached_destination = root.join("moved-uncached");
    let warm_destination = root.join("warm");
    let uncached_destination = root.join("uncached");
    let later_destination = root.join("later");
    let later_uncached_destination = root.join("later-uncached");
    fs::write(&original, capture_with_http_body(BODY)?)?;
    let cold = extraction_command(root, &original, &cold_destination).output()?;
    fs::rename(&original, &moved)?;
    fs::copy(&moved, &copied)?;
    fs::copy(&moved, &later_copy)?;

    let moved_warm = extraction_command(root, &moved, &moved_destination).output()?;
    let moved_uncached = extraction_command(root, &moved, &moved_uncached_destination)
        .arg("--no-cache")
        .output()?;
    let warm = extraction_command(root, &copied, &warm_destination).output()?;
    let uncached = extraction_command(root, &copied, &uncached_destination)
        .arg("--no-cache")
        .output()?;
    let later = extraction_command(root, &later_copy, &later_destination).output()?;
    let later_uncached = extraction_command(root, &later_copy, &later_uncached_destination)
        .arg("--no-cache")
        .output()?;

    for result in [
        &cold,
        &moved_warm,
        &moved_uncached,
        &warm,
        &uncached,
        &later,
        &later_uncached,
    ] {
        assert_eq!(
            result.status.code(),
            Some(0),
            "extract failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    assert_current_source_label(&moved_destination, "moved.pcap")?;
    assert_current_source_label(&warm_destination, "copied.pcap")?;
    assert_current_source_label(&later_destination, "later-copy.pcap")?;
    assert_export_outputs_match(&moved_destination, &moved_uncached_destination)?;
    assert_export_outputs_match(&warm_destination, &uncached_destination)?;
    assert_export_outputs_match(&later_destination, &later_uncached_destination)?;
    assert_eq!(
        artifact_contents(&cold_destination)?,
        artifact_contents(&moved_destination)?
    );
    assert_eq!(
        artifact_contents(&cold_destination)?,
        artifact_contents(&warm_destination)?
    );
    assert_eq!(
        artifact_contents(&cold_destination)?,
        artifact_contents(&later_destination)?
    );
    let cold_counters = result_counters(&cold_destination)?;
    for destination in [&moved_destination, &warm_destination, &later_destination] {
        let counters = result_counters(destination)?;
        assert!(
            counters.cache_hits > cold_counters.cache_hits,
            "copied capture did not reuse cached work"
        );
        assert!(
            counters.candidates_examined < cold_counters.candidates_examined,
            "copied capture repeated completed recovery work"
        );
    }
    Ok(())
}

fn assert_current_source_label(
    directory: &Path,
    expected_label: &str,
) -> Result<(), Box<dyn Error>> {
    for record in evidence_records(directory)? {
        let sources = case_sources(&record)?;
        let current_sources = sources
            .iter()
            .filter(|source| {
                source.get("label").and_then(serde_json::Value::as_str) == Some(expected_label)
            })
            .collect::<Vec<_>>();
        let labels = sources
            .iter()
            .filter_map(|source| source.get("label").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            current_sources.len(),
            1,
            "expected source label {expected_label:?}, observed labels {labels:?}"
        );
        let current_source = current_sources
            .first()
            .ok_or("current evidence source disappeared")?;
        let aliases = current_source
            .get("aliases")
            .and_then(serde_json::Value::as_array)
            .ok_or("evidence source is missing its aliases")?;
        assert!(aliases.is_empty(), "source retained a prior request label");
    }
    Ok(())
}

fn case_sources(record: &serde_json::Value) -> Result<&[serde_json::Value], Box<dyn Error>> {
    record
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "evidence Case is missing its sources".into())
}

#[test]
fn unrelated_destination_is_rejected_before_reading_a_capture() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let destination = root.join("result");
    fs::create_dir(&destination)?;
    fs::write(destination.join("keep.txt"), b"user data")?;
    let capture = root.join("invalid.pcap");
    fs::write(&capture, b"not a capture")?;
    let result = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("destination") || error.contains("output"),
        "{error}"
    );
    assert!(!root.join("cache").exists());
    assert_eq!(fs::read(destination.join("keep.txt"))?, b"user data");
    Ok(())
}

#[test]
fn matching_partial_extraction_returns_the_recorded_partial_status() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcapng");
    let destination = root.join("result");
    fs::write(
        &capture,
        capture_with_packet_block_drops(&capture_with_http_body(BODY)?, 7)?,
    )?;
    let first = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(first.status.code(), Some(3));
    let original_manifest = fs::read(destination.join("manifest.json"))?;

    let reused = extraction_command(root, &capture, &destination).output()?;

    assert_eq!(reused.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&reused.stdout).contains("Reused"));
    assert_eq!(
        fs::read(destination.join("manifest.json"))?,
        original_manifest
    );
    Ok(())
}

#[test]
fn deeper_profile_reuses_the_index_and_keeps_progress_as_json() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    let normal = extraction_command(root, &capture, &root.join("normal")).output()?;
    assert!(matches!(normal.status.code(), Some(0 | 3)));

    let deep = extraction_command(root, &capture, &root.join("deep"))
        .args(["--profile", "deep", "--progress", "json"])
        .output()?;

    assert!(matches!(deep.status.code(), Some(0 | 3)));
    let mut index_reused = false;
    for line in String::from_utf8(deep.stderr)?.lines() {
        let event: serde_json::Value = serde_json::from_str(line)?;
        index_reused |= event
            .get("phases")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|phases| {
                phases.iter().any(|phase| {
                    phase.get("phase").and_then(serde_json::Value::as_str) == Some("ingestion")
                        && phase.get("state").and_then(serde_json::Value::as_str) == Some("skipped")
                })
            });
    }
    assert!(index_reused, "deep run did not report a reused index");
    Ok(())
}

fn assert_export_outputs_match(expected: &Path, actual: &Path) -> Result<(), Box<dyn Error>> {
    assert_eq!(artifact_contents(expected)?, artifact_contents(actual)?);
    // Decompressed JSONL bytes keep the complete evidence records byte-identical
    assert_eq!(evidence_jsonl(expected)?, evidence_jsonl(actual)?);
    assert_eq!(semantic_manifest(expected)?, semantic_manifest(actual)?);
    assert_eq!(
        fs::read(expected.join("summary.txt"))?,
        fs::read(actual.join("summary.txt"))?
    );
    assert_eq!(
        optional_file(expected.join("limitations.txt"))?,
        optional_file(actual.join("limitations.txt"))?
    );
    Ok(())
}

pub type ArtifactContents = Vec<(std::ffi::OsString, Vec<u8>)>;

pub fn artifact_contents(directory: &Path) -> Result<ArtifactContents, Box<dyn Error>> {
    let mut paths = artifact_paths(directory)?;
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .ok_or("artifact path has no filename")?
                .to_os_string();
            Ok((name, fs::read(path)?))
        })
        .collect()
}

fn evidence_jsonl(directory: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = fs::File::open(directory.join("evidence.jsonl.gz"))?;
    let mut decoder = flate2::read::MultiGzDecoder::new(file);
    let mut bytes = Vec::new();
    decoder.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn evidence_records(directory: &Path) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    String::from_utf8(evidence_jsonl(directory)?)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn optional_file(path: PathBuf) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn semantic_manifest(directory: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    let receipt = manifest
        .as_object_mut()
        .and_then(|fields| fields.get_mut("l2solver_result"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("result receipt is missing")?;
    normalize_job_snapshot(
        receipt
            .get_mut("job")
            .ok_or("result receipt job snapshot is missing")?,
    )?;
    normalize_output_stamps(
        receipt
            .get_mut("output_files")
            .ok_or("result receipt output stamps are missing")?,
    )?;
    Ok(manifest)
}

fn normalize_job_snapshot(snapshot: &mut serde_json::Value) -> Result<(), Box<dyn Error>> {
    let fields = snapshot
        .as_object_mut()
        .ok_or("result job snapshot is invalid")?;
    // Work counters and timings change when a cached stage skips computation
    fields.remove("created_at_unix_ms");
    fields.remove("elapsed_ms");
    fields.remove("counters");
    let phases = fields
        .get_mut("phases")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("result job phases are missing")?;
    for phase in phases {
        let fields = phase.as_object_mut().ok_or("result job phase is invalid")?;
        if fields.get("phase").and_then(serde_json::Value::as_str) == Some("ingestion") {
            fields.insert(
                "state".to_owned(),
                serde_json::Value::String("cache_dependent".to_owned()),
            );
        }
        fields.remove("completed");
        fields.remove("total");
        fields.remove("elapsed_ms");
        fields.remove("progress_percent");
        fields.remove("rate_per_second");
        fields.remove("eta_seconds");
        fields.remove("message");
    }
    Ok(())
}

fn normalize_output_stamps(stamps: &mut serde_json::Value) -> Result<(), Box<dyn Error>> {
    let stamps = stamps
        .as_array_mut()
        .ok_or("result output stamps are invalid")?;
    for stamp in stamps {
        let fields = stamp
            .as_object_mut()
            .ok_or("result output stamp is invalid")?;
        // Destination inode and timestamps vary while file bytes and digests remain stable
        fields.remove("device_id");
        fields.remove("file_id");
        fields.remove("modified_seconds");
        fields.remove("modified_nanoseconds");
        fields.remove("changed_seconds");
        fields.remove("changed_nanoseconds");
    }
    Ok(())
}

pub struct ResultCounters {
    pub(super) cache_hits: u64,
    pub(super) cache_misses: u64,
    pub(super) candidates_examined: u64,
    pub(super) ingestion_state: String,
}

pub fn result_counters(directory: &Path) -> Result<ResultCounters, Box<dyn Error>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    let counters = manifest
        .pointer("/l2solver_result/job/counters")
        .ok_or("result job counters are missing")?;
    let ingestion_state = manifest
        .pointer("/l2solver_result/job/phases")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|phase| phase.get("phase").and_then(serde_json::Value::as_str) == Some("ingestion"))
        .and_then(|phase| phase.get("state"))
        .and_then(serde_json::Value::as_str)
        .ok_or("result ingestion phase is missing")?
        .to_owned();
    let counter = |name| {
        counters
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Ok(ResultCounters {
        cache_hits: counter("cache_hits"),
        cache_misses: counter("cache_misses"),
        candidates_examined: counter("candidates_examined"),
        ingestion_state,
    })
}
