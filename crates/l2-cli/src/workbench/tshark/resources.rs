//! Resolve optional dissector limits before creating its private files

use super::budget::ObjectExportBudget;
#[cfg(target_os = "linux")]
use super::secure_files;
use l2_workbench::job::{
    HostCapacity, InputSize, Job, ObjectLimitMode, ProcessWorkingSet, ResourceLimits, ResourcePlan,
    workspace_capacity,
};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{
    env, error::Error, ffi::OsString, fs::File, io, num::NonZeroU64, path::Path, time::Duration,
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/resources.rs"]
mod tests;
#[cfg(test)]
pub(super) use tests::test_plan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObjectRequest {
    pub(super) budget: ObjectExportBudget,
    pub(super) mode: ObjectLimitMode,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OperatorConfiguration {
    pub(super) memory_bytes: Option<u64>,
    pub(super) swap_bytes: Option<u64>,
    pub(super) tasks: Option<u64>,
    pub(super) temporary_bytes: Option<u64>,
    pub(super) tmp_bytes: Option<u64>,
    pub(super) shm_bytes: Option<u64>,
    pub(super) objects: Option<ObjectRequest>,
}

pub(super) fn operator_configuration(
    objects: Option<ObjectExportBudget>,
    mut lookup: impl FnMut(&'static str) -> Option<OsString>,
) -> io::Result<OperatorConfiguration> {
    const MIB: u64 = 1024 * 1024;
    let memory_bytes = optional_request("MEMORY_MIB", lookup("L2SOLVER_TSHARK_MEMORY_MIB"), MIB)?;
    let swap_bytes = optional_request("SWAP_MIB", lookup("L2SOLVER_TSHARK_SWAP_MIB"), MIB)?;
    let tasks = optional_request("TASKS", lookup("L2SOLVER_TSHARK_TASKS"), 1)?;
    let temporary_bytes = optional_request(
        "TEMPORARY_MIB",
        lookup("L2SOLVER_TSHARK_TEMPORARY_MIB"),
        MIB,
    )?;
    let tmp_bytes = optional_request("TMP_MIB", lookup("L2SOLVER_TSHARK_TMP_MIB"), MIB)?;
    let shm_bytes = optional_request("SHM_MIB", lookup("L2SOLVER_TSHARK_SHM_MIB"), MIB)?;
    let objects = objects
        .map(|budget| {
            object_request(
                budget,
                lookup("L2SOLVER_TSHARK_OBJECT_MIB"),
                lookup("L2SOLVER_TSHARK_OBJECT_FILES"),
            )
        })
        .transpose()?;
    Ok(OperatorConfiguration {
        memory_bytes,
        swap_bytes,
        tasks,
        temporary_bytes,
        tmp_bytes,
        shm_bytes,
        objects,
    })
}

fn optional_request(name: &str, value: Option<OsString>, unit: u64) -> io::Result<Option<u64>> {
    value
        .map(|value| request(name, Some(value), 0, unit))
        .transpose()
}

pub(super) fn job_ceiling(
    job: Option<&Job>,
    parent_bytes: u64,
) -> Result<Option<u64>, Box<dyn Error>> {
    job.and_then(Job::memory_budget)
        .map(|memory| {
            let snapshot = memory.snapshot()?;
            snapshot
                .limit_bytes
                .checked_sub(snapshot.used_bytes)
                .and_then(|remaining| remaining.checked_sub(snapshot.working_sets.reserved_bytes))
                .and_then(|remaining| remaining.checked_sub(parent_bytes))
                .map(workspace_capacity)
                .ok_or_else(|| "job memory accounting exceeds its limit".into())
        })
        .transpose()
}

pub(super) fn reserve(
    job: Option<&Job>,
    plan: &ResourcePlan,
    parent_bytes: u64,
) -> Result<Option<ProcessWorkingSet>, Box<dyn Error>> {
    let bytes = plan
        .limits()
        .child_memory_bytes
        .get()
        .checked_add(parent_bytes)
        .ok_or("TShark memory allowance overflow")?;
    // Keep future capacity separate from measured heap and kernel RSS
    Ok(job
        .and_then(Job::memory_budget)
        .map(|memory| memory.try_process_working_set(bytes))
        .transpose()?)
}

pub(super) fn resolve(
    parent: Option<&Path>,
    input: InputSize,
    capture_maximum: Option<u64>,
    configuration: OperatorConfiguration,
    timeout: Duration,
    job_memory_ceiling: Option<u64>,
    parent_memory_bytes: u64,
) -> Result<(ResourcePlan, File), Box<dyn Error>> {
    let parent = open_parent(parent)?;
    let swap = configuration.swap_bytes.unwrap_or(0);
    let mut capacity = observe(&parent, swap)?;
    capacity.memory_bytes = capacity
        .memory_bytes
        .checked_sub(parent_memory_bytes)
        .ok_or("TShark parent buffers exceed available memory")?;
    if capture_maximum == Some(0) && input.capture_bytes != Some(0) {
        return Err("zero capture limit requires an empty source".into());
    }
    let (limits, object_mode) = limits(
        capacity,
        capture_maximum,
        configuration,
        timeout,
        job_memory_ceiling,
    )?;
    let plan = ResourcePlan::new(capacity, input, limits, None, object_mode)?;
    Ok((plan, parent))
}

fn limits(
    capacity: HostCapacity,
    capture_maximum: Option<u64>,
    configuration: OperatorConfiguration,
    timeout: Duration,
    job_memory_ceiling: Option<u64>,
) -> Result<(ResourceLimits, ObjectLimitMode), Box<dyn Error>> {
    let memory = memory_request(
        configuration.memory_bytes,
        capacity.memory_bytes,
        job_memory_ceiling,
        page_size()?,
    )?;
    let scratch = nonzero(memory.get() / 16, "child scratch")?;
    let tasks = u64::try_from(std::thread::available_parallelism()?.get())?
        .checked_mul(4)
        .and_then(|tasks| tasks.checked_add(8))
        .ok_or("child task count overflow")?;
    let (objects, mode) = configuration.objects.map_or(
        (
            ObjectExportBudget {
                temporary_bytes: 1,
                temporary_files: 1,
            },
            ObjectLimitMode::Automatic,
        ),
        |request| (request.budget, request.mode),
    );
    let capture = capture_maximum
        .unwrap_or_else(|| workspace_capacity(capacity.workspace_bytes))
        .clamp(1, l2_pcap::ABSOLUTE_MAX_INPUT_BYTES);
    Ok((
        ResourceLimits {
            capture_bytes: nonzero(capture, "capture")?,
            temporary_bytes: nonzero(
                configuration
                    .temporary_bytes
                    .unwrap_or_else(|| workspace_capacity(capacity.workspace_bytes)),
                "temporary storage",
            )?,
            object_bytes: nonzero(objects.temporary_bytes, "object bytes")?,
            object_files: nonzero(objects.temporary_files, "object count")?,
            child_memory_bytes: memory,
            child_swap_bytes: configuration.swap_bytes.unwrap_or(0),
            child_tasks: nonzero(
                configuration
                    .tasks
                    .unwrap_or_else(|| tasks.min(capacity.tasks / 2)),
                "child tasks",
            )?,
            timeout,
            tmpfs_bytes: nonzero(
                configuration.tmp_bytes.unwrap_or_else(|| scratch.get()),
                "child temporary filesystem",
            )?,
            shm_bytes: nonzero(
                configuration.shm_bytes.unwrap_or_else(|| scratch.get()),
                "child shared memory",
            )?,
        },
        mode,
    ))
}

pub(super) fn object_request(
    budget: ObjectExportBudget,
    bytes: Option<OsString>,
    files: Option<OsString>,
) -> io::Result<ObjectRequest> {
    let explicit = bytes.is_some() || files.is_some() || budget != ObjectExportBudget::DEFAULT;
    let budget = ObjectExportBudget {
        temporary_bytes: object_value("OBJECT_MIB", bytes, budget.temporary_bytes, 1024 * 1024)?,
        temporary_files: object_value("OBJECT_FILES", files, budget.temporary_files, 1)?,
    };
    Ok(ObjectRequest {
        budget,
        mode: if explicit {
            ObjectLimitMode::Explicit
        } else {
            ObjectLimitMode::Automatic
        },
    })
}

fn object_value(name: &str, value: Option<OsString>, default: u64, unit: u64) -> io::Result<u64> {
    if value.as_ref().is_some_and(|value| {
        value.to_str().is_none_or(|value| {
            value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) {
        return Err(invalid_request(name));
    }
    let value = request(name, value, default, unit)?;
    if value == 0 {
        return Err(invalid_request(name));
    }
    Ok(value)
}

fn memory_request(
    value: Option<u64>,
    available: u64,
    ceiling: Option<u64>,
    page: u64,
) -> io::Result<NonZeroU64> {
    if page == 0 {
        return Err(invalid());
    }
    let explicit = value.is_some();
    let mut memory = value.unwrap_or(available / 2);
    if let Some(ceiling) = ceiling {
        if explicit && memory > ceiling {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requested child memory exceeds the remaining job budget",
            ));
        }
        memory = memory.min(ceiling);
    }
    // Round down before admission because the kernel rounds memory.max up to a page
    nonzero(memory / page * page, "child memory")
}

#[cfg(target_os = "linux")]
fn open_parent(parent: Option<&Path>) -> io::Result<File> {
    let default_parent;
    let parent = if let Some(parent) = parent {
        parent
    } else {
        default_parent = env::temp_dir();
        &default_parent
    };
    secure_files::open_trusted_directory(parent)
}

#[cfg(not(target_os = "linux"))]
fn open_parent(_parent: Option<&Path>) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TShark resource containment requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn observe(parent: &File, requested_swap: u64) -> io::Result<HostCapacity> {
    use crate::recovery_job::system_memory::{Reader, hierarchy};
    let storage = rustix::fs::fstatvfs(parent)?;
    let workspace_bytes = storage
        .f_bavail
        .checked_mul(storage.f_frsize)
        .ok_or_else(invalid)?;
    let meminfo = text(Path::new("/proc/meminfo"))?;
    let mut memory_bytes = available_memory(&meminfo)?;
    if let Some(cgroup) = Reader::open(Path::new("/proc/self"))?.sample()?.cgroup
        && let Some(headroom) = cgroup.max_headroom_bytes
    {
        memory_bytes = memory_bytes.min(headroom);
    }
    let hierarchy = hierarchy(
        &text(Path::new("/proc/self/cgroup"))?,
        &text(Path::new("/proc/self/mountinfo"))?,
    )?;
    let mut tasks = task_headroom(
        &text(Path::new("/proc/sys/kernel/threads-max"))?,
        &text(Path::new("/proc/loadavg"))?,
    )?;
    if let Some(headroom) = cgroup_headroom(&hierarchy, "pids")? {
        tasks = tasks.min(headroom);
    }
    if requested_swap != 0 {
        check_swap_request(
            requested_swap,
            swap_free(&meminfo)?,
            cgroup_headroom(&hierarchy, "memory.swap")?,
        )?;
    }
    Ok(HostCapacity {
        memory_bytes,
        workspace_bytes,
        tasks,
        allocation_granule: nonzero(page_size()?, "page size")?,
    })
}

#[cfg(not(target_os = "linux"))]
fn observe(_parent: &File, _requested_swap: u64) -> io::Result<HostCapacity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TShark resource containment requires Linux",
    ))
}

#[cfg(any(target_os = "linux", test))]
fn available_memory(contents: &str) -> io::Result<u64> {
    meminfo_kib(contents, "MemAvailable:")
}

#[cfg(target_os = "linux")]
fn swap_free(contents: &str) -> io::Result<u64> {
    meminfo_kib(contents, "SwapFree:")
}

#[cfg(any(target_os = "linux", test))]
fn meminfo_kib(contents: &str, field: &str) -> io::Result<u64> {
    let mut lines = contents.lines().filter_map(|line| line.strip_prefix(field));
    let mut values = lines.next().ok_or_else(invalid)?.split_whitespace();
    let kibibytes = values
        .next()
        .ok_or_else(invalid)?
        .parse::<u64>()
        .map_err(|_| invalid())?;
    if values.next() != Some("kB") || values.next().is_some() || lines.next().is_some() {
        return Err(invalid());
    }
    kibibytes.checked_mul(1024).ok_or_else(invalid)
}

#[cfg(any(target_os = "linux", test))]
fn task_headroom(maximum: &str, loadavg: &str) -> io::Result<u64> {
    let maximum = maximum.trim().parse::<u64>().map_err(|_| invalid())?;
    let mut fields = loadavg.split_whitespace();
    let counts = fields.nth(3).ok_or_else(invalid)?;
    let (running, total) = counts.split_once('/').ok_or_else(invalid)?;
    let running = running.parse::<u64>().map_err(|_| invalid())?;
    let total = total.parse::<u64>().map_err(|_| invalid())?;
    if running > total || fields.next().is_none() || fields.next().is_some() {
        return Err(invalid());
    }
    Ok(maximum.saturating_sub(total))
}

#[cfg(target_os = "linux")]
fn cgroup_headroom(hierarchy: &[PathBuf], controller: &str) -> io::Result<Option<u64>> {
    let mut headroom: Option<u64> = None;
    for directory in hierarchy {
        let maximum = match text(&directory.join(format!("{controller}.max"))) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if maximum.trim() == "max" {
            continue;
        }
        let maximum = maximum.trim().parse::<u64>().map_err(|_| invalid())?;
        let current = text(&directory.join(format!("{controller}.current")))?
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid())?;
        let remaining = maximum.saturating_sub(current);
        headroom = Some(headroom.map_or(remaining, |previous| previous.min(remaining)));
    }
    Ok(headroom)
}

#[cfg(target_os = "linux")]
fn check_swap_request(requested: u64, free: u64, inherited: Option<u64>) -> io::Result<()> {
    if requested > inherited.map_or(free, |limit| free.min(limit)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "requested swap exceeds available headroom",
        ));
    }
    Ok(())
}

fn request(name: &str, value: Option<OsString>, automatic: u64, unit: u64) -> io::Result<u64> {
    value.map_or(Ok(automatic), |value| {
        value
            .to_str()
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|value| value.checked_mul(unit))
            .filter(|value| *value != u64::MAX)
            .ok_or_else(|| invalid_request(name))
    })
}

fn invalid_request(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid L2SOLVER_TSHARK_{name} resource request"),
    )
}

fn nonzero(value: u64, name: &str) -> io::Result<NonZeroU64> {
    NonZeroU64::new(value).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no capacity for {name}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn text(path: &Path) -> io::Result<String> {
    crate::recovery_job::system_memory::read_bounded(File::open(path)?, 1024 * 1024)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid kernel resource observation",
    )
}

#[cfg(target_os = "linux")]
fn page_size() -> io::Result<u64> {
    u64::try_from(rustix::param::page_size()).map_err(io::Error::other)
}

#[cfg(not(target_os = "linux"))]
fn page_size() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "page-size observation requires Linux",
    ))
}
