mod budget;
mod count;
mod model;
mod objects;
mod process;

pub use budget::{ObjectExportBudget, ObjectExportStatus, ObjectExportUsage};
pub use objects::{ExportObjectSet, export_objects};

use crate::arguments::TsharkOptions;
use count::CaptureCount;
use l2_workbench::sha256;
use model::{
    BudgetReceipt, Diagnostic, EnrichedPacket, InvocationReceipt, PacketCountReceipt, PluginRecord,
    ProfileReceipt, Provenance, SourceIdentity, ToolReceipt, TsharkReport,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::ExitStatus,
    time::{Duration, Instant},
};

const PROFILE: &str = "l2solver-offline";
const PREFERENCES: &str = "# L2Solver isolated offline profile\n\
gui.packet_list_show_related: FALSE\n\
ip.defragment: TRUE\n\
ipv6.defragment: TRUE\n\
tcp.desegment_tcp_streams: TRUE\n\
http.desegment_headers: TRUE\n\
http.desegment_body: TRUE\n\
tls.desegment_ssl_records: TRUE\n\
tls.desegment_ssl_application_data: TRUE\n";
const REASSEMBLY_PREFERENCES: &[&str] = &[
    "ip.defragment=TRUE",
    "ipv6.defragment=TRUE",
    "tcp.desegment_tcp_streams=TRUE",
    "http.desegment_headers=TRUE",
    "http.desegment_body=TRUE",
    "tls.desegment_ssl_records=TRUE",
    "tls.desegment_ssl_application_data=TRUE",
];

struct Snapshot {
    source_path: PathBuf,
    source_file: crate::input::InputFile,
    path: PathBuf,
    identity: SourceIdentity,
}

struct Profile {
    config_directory: PathBuf,
    extcap_directory: PathBuf,
    home_directory: PathBuf,
    xdg_config_directory: PathBuf,
    xdg_data_directory: PathBuf,
    temporary_directory: PathBuf,
    preferences_sha256: String,
}

struct PreparedCapture {
    directory: tempfile::TempDir,
    source: Snapshot,
    keylog: Option<Snapshot>,
    profile: Profile,
    environment: Vec<(OsString, OsString)>,
    executable: PathBuf,
    executable_requested: String,
    executable_bytes: u64,
    executable_sha256: String,
    deadline: Instant,
    timeout_seconds: u32,
    input_maximum: u64,
    metadata_maximum: usize,
    output_maximum: usize,
    diagnostic_maximum: usize,
}

struct CapturePreparation {
    capture: PathBuf,
    executable: PathBuf,
    keylog: Option<PathBuf>,
    timeout: Duration,
    timeout_seconds: u32,
    input_maximum: u64,
    metadata_maximum: usize,
    output_maximum: usize,
    diagnostic_maximum: usize,
}

struct ToolInspection {
    version: String,
    version_output: process::Output,
    plugin_args: Vec<OsString>,
    plugin_output: process::Output,
    preferences_args: Vec<OsString>,
    preferences_output: process::Output,
    plugins: Vec<PluginRecord>,
    verified_profile_preferences: BTreeMap<String, String>,
    effective_preferences_count: usize,
}

struct CaptureDecode {
    arguments: Vec<OsString>,
    output: process::Output,
    packets: Vec<EnrichedPacket>,
}

/// Enrich one regular offline capture with `TShark` and emit its source-bound receipt
pub(super) fn run(
    options: &TsharkOptions,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut prepared = prepare_capture(options)?;
    let inspection = inspect_tool(&prepared)?;
    let counted = count::capture(&prepared)?;
    let decoded = decode_capture(&prepared)?;
    // A consecutive decoded prefix is complete only when it covers the separate source traversal
    if u64::try_from(decoded.packets.len())? != counted.receipt.count {
        return Err("TShark decoded packet count differs from the source packet count".into());
    }
    verify_prepared_capture(&mut prepared)?;
    verify_executable_unchanged(
        &prepared.executable,
        prepared.executable_bytes,
        &prepared.executable_sha256,
    )?;
    let report = build_report(prepared, inspection, counted, decoded);
    serde_json::to_writer(output, &report)?;
    Ok(true)
}

fn prepare_capture(options: &TsharkOptions) -> Result<PreparedCapture, Box<dyn Error>> {
    prepare_capture_from(
        CapturePreparation {
            capture: options.capture.clone(),
            executable: options.executable.clone(),
            keylog: options.tls_keylog.clone(),
            timeout: Duration::from_secs(u64::from(options.timeout_seconds)),
            timeout_seconds: options.timeout_seconds,
            input_maximum: mib_to_bytes(options.max_input_mib)?,
            metadata_maximum: usize::try_from(mib_to_bytes(options.max_metadata_mib)?)?,
            output_maximum: usize::try_from(mib_to_bytes(options.max_output_mib)?)?,
            diagnostic_maximum: usize::try_from(mib_to_bytes(options.max_diagnostics_mib)?)?,
        },
        None,
    )
}

fn prepare_export_capture(
    capture: &Path,
    temporary_parent: &Path,
) -> Result<PreparedCapture, Box<dyn Error>> {
    const DISCOVERY_TIMEOUT: Duration = Duration::from_mins(2);
    const METADATA_MAXIMUM: usize = 1024 * 1024;
    const DIAGNOSTIC_MAXIMUM: usize = 1024 * 1024;
    // Publisher paths may use /proc/self/fd; children need a normal path after exec
    let temporary_parent = temporary_parent.canonicalize()?;

    prepare_capture_from(
        CapturePreparation {
            capture: capture.to_owned(),
            executable: PathBuf::from("tshark"),
            keylog: None,
            timeout: DISCOVERY_TIMEOUT,
            timeout_seconds: 0,
            input_maximum: u64::MAX,
            // Type discovery is a small fixed inventory, while object bytes stream to files
            metadata_maximum: METADATA_MAXIMUM,
            output_maximum: 0,
            diagnostic_maximum: DIAGNOSTIC_MAXIMUM,
        },
        Some(&temporary_parent),
    )
}

fn prepare_capture_from(
    preparation: CapturePreparation,
    temporary_parent: Option<&Path>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    prepare_capture_from_at(preparation, temporary_parent, Instant::now())
}

fn prepare_capture_from_at(
    preparation: CapturePreparation,
    temporary_parent: Option<&Path>,
    started_at: Instant,
) -> Result<PreparedCapture, Box<dyn Error>> {
    if preparation.capture == Path::new("-") {
        return Err("TShark enrichment requires a regular offline capture file".into());
    }
    let CapturePreparation {
        capture,
        executable: executable_program,
        keylog: keylog_path,
        timeout,
        timeout_seconds,
        input_maximum,
        metadata_maximum,
        output_maximum,
        diagnostic_maximum,
    } = preparation;
    let executable_requested = executable_program.to_string_lossy().into_owned();
    let executable = resolve_executable(&executable_program)?;
    let (executable_bytes, executable_sha256) = hash_executable(&executable)?;
    let directory = match temporary_parent {
        Some(parent) => tempfile::tempdir_in(parent)?,
        None => tempfile::tempdir()?,
    };
    // The shared budget starts before source bytes are copied
    let deadline = started_at
        .checked_add(timeout)
        .ok_or("configured time budget exceeds the platform clock range")?;
    ensure_before_deadline(deadline)?;
    let source = snapshot(
        &capture,
        directory.path(),
        "capture.bin",
        input_maximum,
        "capture",
        deadline,
    )?;
    // Count the optional key log alongside the capture instead of granting it a second budget
    let keylog_maximum = input_maximum
        .checked_sub(source.identity.length)
        .ok_or("capture exceeds the combined input budget")?;
    let keylog = keylog_path
        .as_deref()
        .map(|path| {
            snapshot(
                path,
                directory.path(),
                "tls-keylog.txt",
                keylog_maximum,
                "keylog",
                deadline,
            )
        })
        .transpose()?;
    if keylog
        .as_ref()
        .is_some_and(|snapshot| snapshot.identity.length == 0)
    {
        return Err("TLS key log must be nonempty when explicitly supplied".into());
    }
    let profile = create_profile(directory.path())?;
    let environment = profile_environment(&profile);
    ensure_before_deadline(deadline)?;
    Ok(PreparedCapture {
        directory,
        source,
        keylog,
        profile,
        environment,
        executable,
        executable_requested,
        executable_bytes,
        executable_sha256,
        deadline,
        timeout_seconds,
        input_maximum,
        metadata_maximum,
        output_maximum,
        diagnostic_maximum,
    })
}

fn inspect_tool(prepared: &PreparedCapture) -> Result<ToolInspection, Box<dyn Error>> {
    let version_args = [OsString::from("-n"), OsString::from("-v")];
    let version_output = run_phase(
        &prepared.executable,
        &version_args,
        &prepared.environment,
        prepared.deadline,
        prepared.metadata_maximum,
        prepared.diagnostic_maximum,
    )?;
    require_success("version", version_output.status, &version_output.stderr)?;
    let version = String::from_utf8(version_output.stdout.clone())?
        .lines()
        .next()
        .ok_or("TShark did not report its version")?
        .trim()
        .to_owned();
    if version.is_empty() {
        return Err("TShark reported an empty version".into());
    }

    let profile_args = [
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
    ];
    let mut plugin_args = profile_args.to_vec();
    plugin_args.extend([OsString::from("-G"), OsString::from("plugins")]);
    let plugin_output = run_phase(
        &prepared.executable,
        &plugin_args,
        &prepared.environment,
        prepared.deadline,
        prepared.metadata_maximum,
        prepared.diagnostic_maximum,
    )?;
    require_success(
        "plugin inventory",
        plugin_output.status,
        &plugin_output.stderr,
    )?;
    let plugins = parse_plugins(&plugin_output.stdout)?;

    let mut preferences_args = profile_args.to_vec();
    preferences_args.extend([OsString::from("-G"), OsString::from("currentprefs")]);
    let preferences_output = run_phase(
        &prepared.executable,
        &preferences_args,
        &prepared.environment,
        prepared.deadline,
        prepared.metadata_maximum,
        prepared.diagnostic_maximum,
    )?;
    require_success(
        "effective preferences",
        preferences_output.status,
        &preferences_output.stderr,
    )?;
    let verified_profile_preferences = verify_effective_preferences(&preferences_output.stdout)?;
    let effective_preferences_count = preference_count(&preferences_output.stdout)?;
    Ok(ToolInspection {
        version,
        version_output,
        plugin_args,
        plugin_output,
        preferences_args,
        preferences_output,
        plugins,
        verified_profile_preferences,
        effective_preferences_count,
    })
}

fn decode_capture(prepared: &PreparedCapture) -> Result<CaptureDecode, Box<dyn Error>> {
    let mut arguments = vec![
        OsString::from("-n"),
        OsString::from("-2"),
        OsString::from("-q"),
        OsString::from("-C"),
        OsString::from(PROFILE),
    ];
    if let Some(keylog) = &prepared.keylog {
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(format!(
            "tls.keylog_file:{}",
            keylog.path.display()
        )));
    }
    arguments.extend([
        OsString::from("-r"),
        prepared.source.path.as_os_str().to_os_string(),
        OsString::from("-T"),
        OsString::from("json"),
        // Keep repeated protocol trees and field values in arrays instead of overwriting keys
        OsString::from("--no-duplicate-keys"),
    ]);
    let packet_output = run_phase(
        &prepared.executable,
        &arguments,
        &prepared.environment,
        prepared.deadline,
        prepared.output_maximum,
        prepared.diagnostic_maximum,
    )?;
    require_success(
        "offline decode",
        packet_output.status,
        &packet_output.stderr,
    )?;
    let packets = decode_packets(&packet_output.stdout)?;
    Ok(CaptureDecode {
        arguments,
        output: packet_output,
        packets,
    })
}

fn verify_prepared_capture(prepared: &mut PreparedCapture) -> io::Result<()> {
    verify_source_unchanged(
        &mut prepared.source.source_file,
        &prepared.source.source_path,
        &prepared.source.identity.sha256,
        prepared.source.identity.length,
    )?;
    if let Some(keylog) = &mut prepared.keylog {
        verify_source_unchanged(
            &mut keylog.source_file,
            &keylog.source_path,
            &keylog.identity.sha256,
            keylog.identity.length,
        )?;
    }
    Ok(())
}

fn build_report(
    prepared: PreparedCapture,
    inspection: ToolInspection,
    counted: CaptureCount,
    decoded: CaptureDecode,
) -> TsharkReport {
    let invocations = invocation_receipts(&prepared, &inspection, &counted, &decoded);
    let diagnostics = phase_diagnostics(&inspection, &counted, &decoded);
    let (source, tool) = build_tool_receipt(prepared, inspection, invocations, diagnostics);
    TsharkReport {
        schema_version: 2,
        source,
        source_packet_count: counted.receipt,
        provenance: Provenance {
            source_change_verified: true,
            tool_derived: true,
            tls_decryption: if tool.profile.tls_keylog.is_some() {
                "explicit_keylog"
            } else {
                "disabled"
            }
            .to_owned(),
            physical_byte_ranges: "not_reported".to_owned(),
        },
        tool,
        output_sha256: sha256(&decoded.output.stdout),
        packets: decoded.packets,
    }
}

fn invocation_receipts(
    prepared: &PreparedCapture,
    inspection: &ToolInspection,
    counted: &CaptureCount,
    decoded: &CaptureDecode,
) -> Vec<InvocationReceipt> {
    vec![
        invocation_receipt(
            "version",
            &[OsString::from("-n"), OsString::from("-v")],
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "plugins",
            &inspection.plugin_args,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "preferences",
            &inspection.preferences_args,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "packet_count",
            &counted.arguments,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "decode",
            &decoded.arguments,
            &prepared.source.path,
            prepared
                .keylog
                .as_ref()
                .map(|snapshot| snapshot.path.as_path()),
        ),
    ]
}

fn phase_diagnostics(
    inspection: &ToolInspection,
    counted: &CaptureCount,
    decoded: &CaptureDecode,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    add_diagnostic(
        &mut diagnostics,
        "version",
        &inspection.version_output.stderr,
    );
    add_diagnostic(
        &mut diagnostics,
        "plugins",
        &inspection.plugin_output.stderr,
    );
    add_diagnostic(
        &mut diagnostics,
        "preferences",
        &inspection.preferences_output.stderr,
    );
    add_diagnostic(&mut diagnostics, "packet_count", &counted.stderr);
    add_diagnostic(&mut diagnostics, "decode", &decoded.output.stderr);
    diagnostics
}

fn build_tool_receipt(
    prepared: PreparedCapture,
    inspection: ToolInspection,
    invocations: Vec<InvocationReceipt>,
    diagnostics: Vec<Diagnostic>,
) -> (SourceIdentity, ToolReceipt) {
    let plugin_inventory_sha256 = sha256(&inspection.plugin_output.stdout);
    let version_output_sha256 = sha256(&inspection.version_output.stdout);
    let effective_preferences_sha256 = sha256(&inspection.preferences_output.stdout);
    let source = prepared.source.identity;
    let tool = ToolReceipt {
        executable_requested: prepared.executable_requested,
        executable: prepared.executable.to_string_lossy().into_owned(),
        executable_bytes: prepared.executable_bytes,
        executable_sha256: prepared.executable_sha256,
        version: inspection.version,
        budgets: BudgetReceipt {
            timeout_seconds: prepared.timeout_seconds,
            combined_input_bytes: prepared.input_maximum,
            metadata_stdout_bytes_per_phase: prepared.metadata_maximum,
            json_output_bytes: prepared.output_maximum,
            diagnostic_bytes_per_phase: prepared.diagnostic_maximum,
        },
        profile: ProfileReceipt {
            name: PROFILE.to_owned(),
            preferences_sha256: prepared.profile.preferences_sha256,
            name_resolution: "disabled_by_-n".to_owned(),
            reassembly_preferences: REASSEMBLY_PREFERENCES
                .iter()
                .map(|preference| (*preference).to_owned())
                .collect(),
            process_environment: "private_home_xdg_and_temp; private_empty_extcap_directory; C_locale; UTC; inherited_PATH_and_Windows_SystemRoot_only".to_owned(),
            tls_keylog: prepared.keylog.map(|snapshot| snapshot.identity),
        },
        plugins: inspection.plugins,
        plugin_inventory_sha256,
        version_output_sha256,
        effective_preferences_sha256,
        effective_preferences_count: inspection.effective_preferences_count,
        verified_profile_preferences: inspection.verified_profile_preferences,
        invocations,
        diagnostics,
    };
    (source, tool)
}

fn snapshot(
    source_path: &Path,
    directory: &Path,
    snapshot_name: &str,
    maximum: u64,
    fallback_label: &str,
    deadline: Instant,
) -> Result<Snapshot, Box<dyn Error>> {
    snapshot_with_clock(
        source_path,
        directory,
        snapshot_name,
        maximum,
        fallback_label,
        deadline,
        Instant::now,
    )
}

fn snapshot_with_clock(
    source_path: &Path,
    directory: &Path,
    snapshot_name: &str,
    maximum: u64,
    fallback_label: &str,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
) -> Result<Snapshot, Box<dyn Error>> {
    ensure_before_deadline_at(deadline, now())?;
    // Following a path link is safe after the opened target is verified regular
    let mut source_file = crate::input::regular(source_path)?;
    ensure_before_deadline_at(deadline, now())?;
    if source_file.metadata()?.len() > maximum {
        return Err(format!("source exceeds the configured {maximum}-byte input budget").into());
    }
    let snapshot_path = directory.join(snapshot_name);
    let mut snapshot_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&snapshot_path)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        ensure_before_deadline_at(deadline, now())?;
        let count = source_file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ensure_before_deadline_at(deadline, now())?;
        length = length
            .checked_add(u64::try_from(count)?)
            .ok_or("source length overflow")?;
        if length > maximum {
            return Err(
                format!("source exceeds the configured {maximum}-byte input budget").into(),
            );
        }
        let bytes = buffer
            .get(..count)
            .ok_or("source read exceeded its fixed buffer")?;
        hasher.update(bytes);
        snapshot_file.write_all(bytes)?;
        ensure_before_deadline_at(deadline, now())?;
    }
    snapshot_file.flush()?;
    ensure_before_deadline_at(deadline, now())?;
    if length != source_file.metadata()?.len() {
        return Err("source changed while its private snapshot was being created".into());
    }
    source_file.seek(SeekFrom::Start(0))?;
    Ok(Snapshot {
        source_path: source_path.to_owned(),
        source_file,
        path: snapshot_path,
        identity: SourceIdentity {
            label: super::label(source_path, fallback_label).to_owned(),
            length,
            sha256: format!("{:x}", hasher.finalize()),
        },
    })
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), process::ProcessError> {
    ensure_before_deadline_at(deadline, Instant::now())
}

fn ensure_before_deadline_at(deadline: Instant, now: Instant) -> Result<(), process::ProcessError> {
    if now >= deadline {
        Err(process::ProcessError::TimedOut)
    } else {
        Ok(())
    }
}

fn create_profile(directory: &Path) -> io::Result<Profile> {
    let config_directory = directory.join("config");
    let extcap_directory = directory.join("extcap");
    let home_directory = directory.join("home");
    let xdg_config_directory = home_directory.join(".config");
    let xdg_data_directory = home_directory.join(".local").join("share");
    let profile_directory = config_directory.join("profiles").join(PROFILE);
    fs::create_dir_all(&profile_directory)?;
    fs::create_dir_all(&xdg_config_directory)?;
    fs::create_dir_all(&xdg_data_directory)?;
    // Offline reads need no external capture helpers, including helpers probed at startup
    fs::create_dir(&extcap_directory)?;
    fs::write(profile_directory.join("preferences"), PREFERENCES)?;
    Ok(Profile {
        config_directory,
        extcap_directory,
        home_directory,
        xdg_config_directory,
        xdg_data_directory,
        temporary_directory: directory.to_owned(),
        preferences_sha256: sha256(PREFERENCES.as_bytes()),
    })
}

fn profile_environment(profile: &Profile) -> Vec<(OsString, OsString)> {
    let mut environment = [
        ("WIRESHARK_CONFIG_DIR", &profile.config_directory),
        ("WIRESHARK_EXTCAP_DIR", &profile.extcap_directory),
        ("HOME", &profile.home_directory),
        ("XDG_CONFIG_HOME", &profile.xdg_config_directory),
        ("XDG_DATA_HOME", &profile.xdg_data_directory),
        ("USERPROFILE", &profile.home_directory),
        ("APPDATA", &profile.config_directory),
        ("TMPDIR", &profile.temporary_directory),
        ("TMP", &profile.temporary_directory),
        ("TEMP", &profile.temporary_directory),
    ]
    .into_iter()
    .map(|(name, path)| (OsString::from(name), path.as_os_str().to_os_string()))
    .collect::<Vec<_>>();
    environment.extend(
        [("LC_ALL", "C"), ("LANG", "C"), ("TZ", "UTC")]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    );
    environment
}

fn resolve_executable(program: &Path) -> io::Result<PathBuf> {
    let has_path_component = program.is_absolute()
        || program.components().count() > 1
        || program
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty());
    if has_path_component {
        return executable_file(program)?.ok_or_else(|| executable_not_found(program));
    }
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&search_path) {
        let candidate = directory.join(program);
        if let Some(resolved) = executable_file(&candidate)? {
            return Ok(resolved);
        }
        #[cfg(windows)]
        if candidate.extension().is_none()
            && let Some(resolved) = executable_file(&candidate.with_extension("exe"))?
        {
            return Ok(resolved);
        }
    }
    Err(executable_not_found(program))
}

fn executable_file(path: &Path) -> io::Result<Option<PathBuf>> {
    let resolved = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = fs::metadata(&resolved)?;
    if !metadata.is_file() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Ok(None);
        }
    }
    Ok(Some(resolved))
}

fn executable_not_found(program: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("TShark executable not found: {}", program.display()),
    )
}

fn hash_executable(path: &Path) -> io::Result<(u64, String)> {
    let mut file = crate::input::regular_no_follow(path)?;
    hash_file(&mut file, u64::MAX)
}

fn verify_executable_unchanged(path: &Path, length: u64, digest: &str) -> io::Result<()> {
    let (current_length, current_digest) = hash_executable(path)?;
    if current_length != length || current_digest != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TShark executable changed while enrichment was running",
        ));
    }
    Ok(())
}

fn run_phase(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    deadline: Instant,
    stdout_maximum: usize,
    stderr_maximum: usize,
) -> Result<process::Output, Box<dyn Error>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(process::ProcessError::TimedOut.into());
    }
    Ok(process::run(
        executable,
        arguments,
        environment,
        remaining,
        stdout_maximum,
        stderr_maximum,
    )?)
}

fn require_success(phase: &str, status: ExitStatus, stderr: &[u8]) -> Result<(), Box<dyn Error>> {
    if status.success() {
        return Ok(());
    }
    let diagnostics = String::from_utf8_lossy(stderr);
    Err(format!(
        "TShark {phase} failed with {status}: {}",
        diagnostics.trim()
    )
    .into())
}

fn parse_plugins(bytes: &[u8]) -> Result<Vec<PluginRecord>, Box<dyn Error>> {
    let text = std::str::from_utf8(bytes)?;
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut columns = line.split('\t');
            let name = columns.next().ok_or("TShark plugin name is missing")?;
            let version = columns.next().ok_or("TShark plugin version is missing")?;
            let kind = columns.next().ok_or("TShark plugin type is missing")?;
            let path = columns.next().ok_or("TShark plugin path is missing")?;
            if columns.next().is_some()
                || [name, version, kind, path]
                    .iter()
                    .any(|value| value.is_empty())
            {
                return Err("TShark returned a malformed plugin record".into());
            }
            Ok(PluginRecord {
                name: name.to_owned(),
                version: version.to_owned(),
                kind: kind.to_owned(),
                path: path.to_owned(),
            })
        })
        .collect()
}

fn preference_count(bytes: &[u8]) -> Result<usize, Box<dyn Error>> {
    Ok(std::str::from_utf8(bytes)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count())
}

fn invocation_receipt(
    phase: &'static str,
    arguments: &[OsString],
    source_snapshot: &Path,
    keylog_snapshot: Option<&Path>,
) -> InvocationReceipt {
    let keylog_argument =
        keylog_snapshot.map(|path| OsString::from(format!("tls.keylog_file:{}", path.display())));
    let argv = arguments
        .iter()
        .map(|argument| {
            if argument == source_snapshot.as_os_str() {
                "<source-snapshot>".to_owned()
            } else if keylog_argument
                .as_ref()
                .is_some_and(|expected| expected.as_os_str() == argument.as_os_str())
            {
                "tls.keylog_file:<keylog-snapshot>".to_owned()
            } else {
                argument.to_string_lossy().into_owned()
            }
        })
        .collect();
    InvocationReceipt {
        phase: phase.to_owned(),
        argv,
    }
}

fn verify_effective_preferences(bytes: &[u8]) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let expected = PREFERENCES
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .ok_or("invalid setting in the built-in TShark profile")?;
            Ok((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn Error>>>()?;
    let text = std::str::from_utf8(bytes)?;
    let mut observed = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        // Wireshark comments out settings that still equal their defaults
        let line = line.strip_prefix('#').unwrap_or(line).trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if expected.contains_key(name) {
            observed.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    for (name, value) in &expected {
        if observed.get(name) != Some(value) {
            return Err(
                format!("TShark profile setting {name} did not take effect as configured").into(),
            );
        }
    }
    Ok(observed)
}

fn add_diagnostic(diagnostics: &mut Vec<Diagnostic>, phase: &'static str, stderr: &[u8]) {
    if stderr.is_empty() {
        return;
    }
    diagnostics.push(Diagnostic {
        phase: phase.to_owned(),
        message: String::from_utf8_lossy(stderr).into_owned(),
        sha256: sha256(stderr),
    });
}

/// Parse `TShark`'s JSON array while binding every item to its original frame number
fn decode_packets(bytes: &[u8]) -> Result<Vec<EnrichedPacket>, Box<dyn Error>> {
    let root: serde_json::Value = serde_json::from_slice(bytes)?;
    let serde_json::Value::Array(entries) = root else {
        return Err("TShark JSON output must be an array of packets".into());
    };
    let mut packets = Vec::with_capacity(entries.len());
    for mut entry in entries {
        let layers = entry
            .get_mut("_source")
            .and_then(|source| source.get_mut("layers"))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("TShark packet is missing its structured layer object")?;
        let number = layers
            .get("frame")
            .and_then(|frame| frame.get("frame.number"))
            .and_then(json_u64)
            .ok_or("TShark packet is missing its source frame number")?;
        let expected = u64::try_from(packets.len())?
            .checked_add(1)
            .ok_or("TShark packet number overflow")?;
        if number != expected {
            return Err("TShark packet numbers are missing, skipped, or out of order".into());
        }
        // Move the TShark layer tree into the receipt instead of duplicating large JSON output
        let fields = serde_json::Value::Object(std::mem::take(layers));
        let mut reassembled_fields = BTreeSet::new();
        collect_reassembled_fields(&fields, &mut reassembled_fields);
        packets.push(EnrichedPacket {
            packet_number: number,
            tool_derived: true,
            fields,
            reassembled_fields,
        });
    }
    Ok(packets)
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|text| text.parse::<u64>().ok())
        .or_else(|| value.as_u64())
}

fn collect_reassembled_fields(value: &serde_json::Value, fields: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (name, value) in object {
                if name.contains("reassembled") {
                    fields.insert(name.clone());
                }
                collect_reassembled_fields(value, fields);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_reassembled_fields(value, fields);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

/// Verify both the open source object and its current path against the initial digest
fn verify_source_unchanged(
    open_file: &mut (impl Read + Seek),
    source_path: &Path,
    expected_hash: &str,
    expected_length: u64,
) -> io::Result<()> {
    let opened_hash = hash_file(open_file, expected_length)?;
    let mut current_path = crate::input::regular(source_path)?;
    let path_hash = hash_file(&mut current_path, expected_length)?;
    if opened_hash.0 != expected_length
        || path_hash.0 != expected_length
        || opened_hash.1 != expected_hash
        || path_hash.1 != expected_hash
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source bytes changed while TShark was running",
        ));
    }
    Ok(())
}

fn hash_file(file: &mut (impl Read + Seek), maximum: u64) -> io::Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = crate::input::io_buffer()?;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("source length overflow"))?;
        if length > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source bytes changed while TShark was running",
            ));
        }
        hasher.update(
            buffer
                .get(..count)
                .ok_or_else(|| io::Error::other("source read exceeded its fixed buffer"))?,
        );
    }
    Ok((length, format!("{:x}", hasher.finalize())))
}

fn mib_to_bytes(mebibytes: u32) -> Result<u64, Box<dyn Error>> {
    u64::from(mebibytes)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "configured MiB budget overflowed".into())
}

#[cfg(test)]
#[path = "../../../tests/workbench/tshark.rs"]
mod tests;
