use super::{
    executable::resolve_executable,
    profile::{Profile, create_profile, profile_environment},
    sandbox,
    secure_files::{self, Workspace},
    snapshot::{Snapshot, ensure_before_deadline, hash_file, snapshot, verify_source_unchanged},
};
use crate::arguments::TsharkOptions;
use std::{
    error::Error,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) struct PreparedCapture {
    pub(super) directory: Workspace,
    pub(super) source: Snapshot,
    pub(super) keylog: Option<Snapshot>,
    pub(super) profile: Profile,
    pub(super) environment: Vec<(OsString, OsString)>,
    pub(super) executable: secure_files::VerifiedExecutable,
    pub(super) sandbox: sandbox::Sandbox,
    pub(super) executable_requested: String,
    pub(super) executable_bytes: u64,
    pub(super) executable_sha256: String,
    pub(super) deadline: Instant,
    pub(super) timeout_seconds: u32,
    pub(super) input_maximum: u64,
    pub(super) metadata_maximum: usize,
    pub(super) output_maximum: usize,
    pub(super) diagnostic_maximum: usize,
}

pub(super) struct CapturePreparation {
    pub(super) capture: PathBuf,
    pub(super) executable: PathBuf,
    pub(super) keylog: Option<PathBuf>,
    pub(super) timeout: Duration,
    pub(super) timeout_seconds: u32,
    pub(super) input_maximum: u64,
    pub(super) metadata_maximum: usize,
    pub(super) output_maximum: usize,
    pub(super) diagnostic_maximum: usize,
}

pub(super) fn prepare_capture(options: &TsharkOptions) -> Result<PreparedCapture, Box<dyn Error>> {
    prepare_capture_from(
        CapturePreparation {
            capture: options.capture.clone(),
            executable: options.executable.clone(),
            keylog: options.tls_keylog.clone(),
            timeout: Duration::from_secs(u64::from(options.timeout_seconds)),
            timeout_seconds: options.timeout_seconds,
            input_maximum: mib_to_bytes(options.max_input_mib),
            metadata_maximum: usize::try_from(mib_to_bytes(options.max_metadata_mib))?,
            output_maximum: usize::try_from(mib_to_bytes(options.max_output_mib))?,
            diagnostic_maximum: usize::try_from(mib_to_bytes(options.max_diagnostics_mib))?,
        },
        None,
    )
}

pub(super) fn prepare_export_capture(
    capture: &Path,
    temporary_parent: &Path,
) -> Result<PreparedCapture, Box<dyn Error>> {
    const DISCOVERY_TIMEOUT: Duration = Duration::from_mins(2);
    const METADATA_MAXIMUM: usize = 1024 * 1024;
    const DIAGNOSTIC_MAXIMUM: usize = 1024 * 1024;
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
        Some(temporary_parent),
    )
}

pub(super) fn prepare_capture_from(
    preparation: CapturePreparation,
    temporary_parent: Option<&Path>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    // Optional dissection never inherits elevated credentials or capabilities
    sandbox::check_privileges()?;
    prepare_capture_from_at(preparation, temporary_parent, Instant::now())
}

pub(super) fn prepare_capture_from_at(
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
    let mut executable =
        secure_files::VerifiedExecutable::open(&resolve_executable(&executable_program)?)?;
    let (executable_bytes, executable_sha256) = hash_file(&mut executable.file, u64::MAX)?;
    let directory = Workspace::new(temporary_parent)?;
    // The shared budget starts before source bytes are copied
    let deadline = started_at
        .checked_add(timeout)
        .ok_or("configured time budget exceeds the platform clock range")?;
    ensure_before_deadline(deadline)?;
    let source = snapshot(
        &capture,
        &directory,
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
                &directory,
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
    let sandbox = sandbox::Sandbox::new(
        &directory,
        &executable,
        Some(&source.file),
        keylog.as_ref().map(|snapshot| &snapshot.file),
    )?;
    ensure_before_deadline(deadline)?;
    Ok(PreparedCapture {
        directory,
        source,
        keylog,
        profile,
        environment,
        executable,
        sandbox,
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

pub(super) fn verify_prepared_capture(prepared: &mut PreparedCapture) -> io::Result<()> {
    verify_snapshot(&mut prepared.source)?;
    verify_source_unchanged(
        &mut prepared.source.source_file,
        &prepared.source.source_path,
        &prepared.source.identity.sha256,
        prepared.source.identity.length,
    )?;
    if let Some(keylog) = &mut prepared.keylog {
        verify_snapshot(keylog)?;
        verify_source_unchanged(
            &mut keylog.source_file,
            &keylog.source_path,
            &keylog.identity.sha256,
            keylog.identity.length,
        )?;
    }
    Ok(())
}

fn verify_snapshot(snapshot: &mut Snapshot) -> io::Result<()> {
    let (length, digest) = hash_file(&mut snapshot.file, snapshot.identity.length)?;
    if length != snapshot.identity.length || digest != snapshot.identity.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private TShark snapshot changed",
        ));
    }
    Ok(())
}

fn mib_to_bytes(mebibytes: u32) -> u64 {
    // Every u32 MiB count fits in u64 bytes
    u64::from(mebibytes) * 1024 * 1024
}
