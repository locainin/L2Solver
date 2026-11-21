use super::{
    executable::resolve_executable,
    profile::{Profile, create_profile, profile_environment},
    resources, sandbox,
    secure_files::{self, Workspace},
    snapshot::{
        HashControl, Snapshot, ensure_before_deadline, hash_file, snapshot, snapshot_retained,
        verify_source_unchanged,
    },
};
use crate::arguments::TsharkOptions;
use l2_workbench::job::{InputSize, Job, ProcessWorkingSet, ResourcePlan};
use l2_workbench::tshark::SourceIdentity;
use std::{
    error::Error,
    ffi::OsString,
    fs::File,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/preparation.rs"]
mod tests;

pub(super) struct PreparedCapture {
    pub(super) resources: ResourcePlan,
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
    _reservation: Option<ProcessWorkingSet>,
}

pub(super) struct CapturePreparation {
    pub(super) capture: PathBuf,
    pub(super) executable: PathBuf,
    pub(super) keylog: Option<PathBuf>,
    pub(super) timeout: Duration,
    pub(super) timeout_seconds: u32,
    pub(super) input_maximum: Option<u64>,
    pub(super) object_budget: Option<super::ObjectExportBudget>,
    pub(super) metadata_maximum: usize,
    pub(super) output_maximum: usize,
    pub(super) diagnostic_maximum: usize,
}

struct Admission {
    resources: ResourcePlan,
    parent: File,
    deadline: Instant,
    source_bytes: u64,
    keylog_bytes: u64,
    // The reservation remains active until the admitted resources are dropped
    reservation: Option<ProcessWorkingSet>,
}

pub(super) fn prepare_capture(options: &TsharkOptions) -> Result<PreparedCapture, Box<dyn Error>> {
    prepare_capture_from(
        &CapturePreparation {
            capture: options.capture.clone(),
            executable: options.executable.clone(),
            keylog: options.tls_keylog.clone(),
            timeout: Duration::from_secs(u64::from(options.timeout_seconds)),
            timeout_seconds: options.timeout_seconds,
            input_maximum: options.max_input_mib.map(mib_to_bytes),
            object_budget: None,
            metadata_maximum: usize::try_from(mib_to_bytes(options.max_metadata_mib))?,
            output_maximum: usize::try_from(mib_to_bytes(options.max_output_mib))?,
            diagnostic_maximum: usize::try_from(mib_to_bytes(options.max_diagnostics_mib))?,
        },
        None,
    )
}

pub(super) fn prepare_export_capture(
    capture: &Path,
    source_file: &mut File,
    identity: &SourceIdentity,
    temporary_parent: &Path,
    budget: super::ObjectExportBudget,
    job: Option<&Job>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    const DISCOVERY_TIMEOUT: Duration = Duration::from_mins(2);
    const METADATA_MAXIMUM: usize = 1024 * 1024;
    const DIAGNOSTIC_MAXIMUM: usize = 1024 * 1024;
    sandbox::check_privileges()?;
    prepare_capture_from_input(
        &CapturePreparation {
            capture: capture.to_owned(),
            executable: PathBuf::from("tshark"),
            keylog: None,
            timeout: DISCOVERY_TIMEOUT,
            timeout_seconds: 0,
            input_maximum: Some(identity.length),
            object_budget: Some(budget),
            // Type discovery is a small fixed inventory, while object bytes stream to files
            metadata_maximum: METADATA_MAXIMUM,
            output_maximum: 0,
            diagnostic_maximum: DIAGNOSTIC_MAXIMUM,
        },
        Some(temporary_parent),
        Instant::now(),
        Some((source_file, identity)),
        job,
    )
}

pub(super) fn prepare_capture_from(
    preparation: &CapturePreparation,
    temporary_parent: Option<&Path>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    // Optional dissection never inherits elevated credentials or capabilities
    sandbox::check_privileges()?;
    prepare_capture_from_at(preparation, temporary_parent, Instant::now())
}

pub(super) fn prepare_capture_from_at(
    preparation: &CapturePreparation,
    temporary_parent: Option<&Path>,
    started_at: Instant,
) -> Result<PreparedCapture, Box<dyn Error>> {
    prepare_capture_from_input(preparation, temporary_parent, started_at, None, None)
}

fn prepare_capture_from_input(
    preparation: &CapturePreparation,
    temporary_parent: Option<&Path>,
    started_at: Instant,
    retained: Option<(&mut File, &SourceIdentity)>,
    job: Option<&Job>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    let retained_input = retained
        .as_ref()
        .map(|(file, identity)| (&**file, *identity));
    let admission = admit(
        preparation,
        temporary_parent,
        started_at,
        retained_input,
        job,
    )?;
    prepare_admitted(preparation, admission, retained, job)
}

fn admit(
    preparation: &CapturePreparation,
    temporary_parent: Option<&Path>,
    started_at: Instant,
    retained: Option<(&File, &SourceIdentity)>,
    job: Option<&Job>,
) -> Result<Admission, Box<dyn Error>> {
    let (source_bytes, keylog_bytes) = input_sizes(preparation, retained)?;
    let configuration =
        resources::operator_configuration(preparation.object_budget, std::env::var_os)?;
    let parent_memory = parent_allowance(
        preparation.metadata_maximum,
        preparation.output_maximum,
        preparation.diagnostic_maximum,
        configuration.objects.map(|request| request.budget),
    )?;
    let job_memory_ceiling = resources::job_ceiling(job, parent_memory)?;
    let (resources, parent) = resources::resolve(
        temporary_parent,
        InputSize {
            capture_bytes: Some(source_bytes),
            keylog_bytes,
        },
        preparation.input_maximum,
        configuration,
        preparation.timeout,
        job_memory_ceiling,
        parent_memory,
    )?;
    let deadline = started_at
        .checked_add(resources.limits().timeout)
        .ok_or("configured time budget exceeds the platform clock range")?;
    let reservation = resources::reserve(job, &resources, parent_memory)?;
    let admission = Admission {
        resources,
        parent,
        deadline,
        source_bytes,
        keylog_bytes,
        reservation,
    };
    ensure_before_deadline(admission.deadline)?;
    Ok(admission)
}

fn input_sizes(
    preparation: &CapturePreparation,
    retained: Option<(&File, &SourceIdentity)>,
) -> Result<(u64, u64), Box<dyn Error>> {
    // Admission uses actual file lengths before any private workspace is created
    let source_bytes = if let Some((file, identity)) = retained {
        // The copy checks again because the retained file can change after admission
        if file.metadata()?.len() != identity.length {
            return Err("retained source length changed".into());
        }
        identity.length
    } else {
        if preparation.capture == Path::new("-") {
            return Err("TShark enrichment requires a regular offline capture file".into());
        }
        crate::input::regular(&preparation.capture)?
            .metadata()?
            .len()
    };
    let keylog_bytes = preparation
        .keylog
        .as_deref()
        .map(|path| {
            crate::input::regular(path)?
                .metadata()
                .map(|metadata| metadata.len())
        })
        .transpose()?
        .unwrap_or(0);
    if preparation.keylog.is_some() && keylog_bytes == 0 {
        return Err("TLS key log must be nonempty when explicitly supplied".into());
    }
    if preparation.input_maximum.is_some_and(|maximum| {
        source_bytes
            .checked_add(keylog_bytes)
            .is_none_or(|bytes| bytes > maximum)
    }) {
        return Err("source exceeds the configured combined input budget".into());
    }
    Ok((source_bytes, keylog_bytes))
}

fn prepare_admitted(
    preparation: &CapturePreparation,
    admission: Admission,
    retained: Option<(&mut File, &SourceIdentity)>,
    job: Option<&Job>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    let executable_requested = preparation.executable.to_string_lossy().into_owned();
    let mut executable =
        secure_files::VerifiedExecutable::open(&resolve_executable(&preparation.executable)?)?;
    let executable_limit = executable.file.metadata()?.len();
    let control = HashControl {
        deadline: admission.deadline,
        job,
    };
    let (executable_bytes, executable_sha256) =
        hash_file(&mut executable.file, executable_limit, control)?;
    let directory = Workspace::in_parent(admission.parent)?;
    ensure_before_deadline(admission.deadline)?;
    let source = if let Some((source_file, identity)) = retained {
        snapshot_retained(source_file, identity, &directory, admission.deadline, job)?
    } else {
        snapshot(
            &preparation.capture,
            &directory,
            "capture.bin",
            admission.source_bytes,
            "capture",
            admission.deadline,
        )?
    };
    // Count the optional key log alongside the capture instead of granting it a second budget
    let keylog = preparation
        .keylog
        .as_deref()
        .map(|path| {
            snapshot(
                path,
                &directory,
                "tls-keylog.txt",
                admission.keylog_bytes,
                "keylog",
                admission.deadline,
            )
        })
        .transpose()?;
    let object_files = preparation
        .object_budget
        .map(|_| admission.resources.limits().object_files.get());
    let profile = create_profile(directory.path(), object_files)?;
    let environment = profile_environment(&profile);
    let sandbox = sandbox::Sandbox::new(
        &directory,
        &executable,
        Some(&source.file),
        keylog.as_ref().map(|snapshot| &snapshot.file),
        &admission.resources,
        admission.deadline,
    )?;
    ensure_before_deadline(admission.deadline)?;
    Ok(PreparedCapture {
        resources: admission.resources,
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
        deadline: admission.deadline,
        timeout_seconds: preparation.timeout_seconds,
        input_maximum: admission.resources.limits().capture_bytes.get(),
        metadata_maximum: preparation.metadata_maximum,
        output_maximum: preparation.output_maximum,
        diagnostic_maximum: preparation.diagnostic_maximum,
        _reservation: admission.reservation,
    })
}

fn parent_allowance(
    metadata: usize,
    output: usize,
    diagnostics: usize,
    objects: Option<super::ObjectExportBudget>,
) -> Result<u64, Box<dyn Error>> {
    // Include retained metadata records, raw output and simultaneous object-tree scans
    let metadata = u64::try_from(metadata)?.checked_mul(32);
    let diagnostics = u64::try_from(diagnostics)?.checked_mul(4);
    let tree = objects.map_or(Some(0), |budget| budget.temporary_files.checked_mul(4096));
    metadata
        .and_then(|bytes| bytes.checked_add(u64::try_from(output).ok()?))
        .and_then(|bytes| bytes.checked_add(diagnostics?))
        .and_then(|bytes| bytes.checked_add(tree?))
        .and_then(|bytes| bytes.checked_add(2 * 64 * 1024))
        .ok_or_else(|| "TShark parent memory allowance overflow".into())
}

pub(super) fn verify_prepared_capture(
    prepared: &mut PreparedCapture,
    job: Option<&Job>,
) -> io::Result<()> {
    let control = HashControl {
        deadline: prepared.deadline,
        job,
    };
    verify_snapshot(&mut prepared.source, control)?;
    if let Some(keylog) = &mut prepared.keylog {
        verify_snapshot(keylog, control)?;
    }
    Ok(())
}

fn verify_snapshot(snapshot: &mut Snapshot, control: HashControl<'_>) -> io::Result<()> {
    let (length, digest) = hash_file(&mut snapshot.file, snapshot.identity.length, control)?;
    if length != snapshot.identity.length || digest != snapshot.identity.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private TShark snapshot changed",
        ));
    }
    if let Some((source_path, source_file)) = &mut snapshot.original {
        verify_source_unchanged(
            source_file,
            source_path,
            &snapshot.identity.sha256,
            snapshot.identity.length,
            control,
        )?;
    }
    Ok(())
}

fn mib_to_bytes(mebibytes: u32) -> u64 {
    // Every u32 MiB count fits in u64 bytes
    u64::from(mebibytes) * 1024 * 1024
}
