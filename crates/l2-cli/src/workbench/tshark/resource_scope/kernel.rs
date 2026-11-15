//! Read and validate the kernel controls behind a sandbox scope

use super::super::secure_files::descriptor_source;
use super::{Limits, MAX_PROC_BYTES, PROC_SUPER_MAGIC, invalid};
use crate::recovery_job::system_memory::{field, hierarchy, read_bounded};
use l2_workbench::{
    job::CgroupMemoryEvents,
    tshark::{ScopeReceipt, ScopeUsage},
};
use rustix::fs::{self, CWD, Mode, OFlags};
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const MAX_CONTROL_BYTES: u64 = 4096;

pub(super) fn open_cgroup(path: &Path) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let directory = File::from(fs::openat(CWD, path, flags, Mode::empty())?);
    // A normal directory must never be mistaken for kernel controls
    if u64::try_from(fs::fstatfs(&directory)?.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
        return Err(invalid("TShark scope is not on cgroup v2"));
    }
    Ok(directory)
}

pub(super) fn parent_cgroups(mounts: &str) -> io::Result<Vec<(File, fs::Stat)>> {
    // A threaded hierarchy can place the caller and leader in different groups
    let groups = proc_text(Path::new("/proc/thread-self/cgroup"), MAX_PROC_BYTES)?;
    let paths = hierarchy(&groups, mounts)?;
    if paths.is_empty() {
        return Err(invalid("unified parent cgroup is unavailable"));
    }
    let leader = proc_text(Path::new("/proc/self/cgroup"), MAX_PROC_BYTES)?;
    if hierarchy(&leader, mounts)? != paths {
        return Err(invalid("TShark parent threads have different cgroups"));
    }
    let mut result = Vec::with_capacity(paths.len());
    for (index, path) in paths.into_iter().enumerate() {
        let directory = open_cgroup(&path)?;
        if index == 0 {
            ensure_domain(&control_text(&directory, "cgroup.type")?)?;
        }
        let stat = fs::fstat(&directory)?;
        result.push((directory, stat));
    }
    Ok(result)
}

pub(super) fn ensure_parent_outside(
    parent: &[(File, fs::Stat)],
    group: &fs::Stat,
) -> io::Result<()> {
    // A cleanup signal must never target the parent or one of its ancestors
    if parent
        .iter()
        .any(|(_, stat)| stat.st_dev == group.st_dev && stat.st_ino == group.st_ino)
    {
        return Err(invalid("TShark scope contains its parent"));
    }
    Ok(())
}

pub(super) fn proc_text(path: &Path, maximum: u64) -> io::Result<String> {
    let file = File::from(fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if u64::try_from(fs::fstatfs(&file)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
        return Err(invalid("TShark scope process metadata is not procfs"));
    }
    read_bounded(file, maximum)
}

pub(super) fn control_text(directory: &File, name: &str) -> io::Result<String> {
    let file = File::from(fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    read_bounded(file, MAX_CONTROL_BYTES)
}

fn inherit_limit(directory: &File, name: &str, root: bool, effective: &mut u64) -> io::Result<()> {
    let value = match control_text(directory, name) {
        Ok(value) => value,
        Err(error) if root && error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    // A finite ancestor can only make the child's effective limit smaller
    if value.trim() != "max" {
        *effective = (*effective).min(parse_integer(&value)?);
    }
    Ok(())
}

pub(super) fn scope_receipt(
    limits: &Limits,
    directory: &File,
    hierarchy: &[PathBuf],
) -> io::Result<ScopeReceipt> {
    let memory = control_text(directory, "memory.max")?;
    let high = control_text(directory, "memory.high")?;
    let swap = control_text(directory, "memory.swap.max")?;
    let tasks = control_text(directory, "pids.max")?;
    let actual = check_controls(
        limits,
        &memory,
        &high,
        &swap,
        &tasks,
        &control_text(directory, "memory.oom.group")?,
    )?;
    if !parse_populated(&control_text(directory, "cgroup.events")?)? {
        return Err(invalid("TShark scope is already empty"));
    }
    let mut receipt = ScopeReceipt {
        memory_max_bytes: actual.memory_max,
        memory_high_bytes: actual.memory_high,
        swap_max_bytes: actual.swap_max,
        tasks_max: actual.tasks_max,
        effective_memory_max_bytes: actual.memory_max,
        effective_memory_high_bytes: actual.memory_high,
        effective_swap_max_bytes: actual.swap_max,
        effective_tasks_max: actual.tasks_max,
        usage: None,
    };
    for (index, ancestor) in hierarchy.iter().enumerate().skip(1) {
        let ancestor = open_cgroup(ancestor)?;
        let root = index + 1 == hierarchy.len();
        inherit_limit(
            &ancestor,
            "memory.max",
            root,
            &mut receipt.effective_memory_max_bytes,
        )?;
        inherit_limit(
            &ancestor,
            "memory.high",
            root,
            &mut receipt.effective_memory_high_bytes,
        )?;
        inherit_limit(
            &ancestor,
            "memory.swap.max",
            root,
            &mut receipt.effective_swap_max_bytes,
        )?;
        inherit_limit(
            &ancestor,
            "pids.max",
            root,
            &mut receipt.effective_tasks_max,
        )?;
    }
    Ok(receipt)
}

pub(super) fn observe_usage(directory: &File, observed_after_stop: bool) -> Option<ScopeUsage> {
    // The manager may remove an empty scope before all counters can be read
    let memory_peak_bytes = optional_counter(directory, "memory.peak");
    let tasks_peak = optional_counter(directory, "pids.peak");
    let memory_events = control_text(directory, "memory.events")
        .ok()
        .and_then(|events| {
            Some(CgroupMemoryEvents {
                high: field(&events, "high").ok()??,
                max: field(&events, "max").ok()??,
                oom: field(&events, "oom").ok()??,
                oom_kill: field(&events, "oom_kill").ok()??,
            })
        });
    let tasks_max_events = control_text(directory, "pids.events")
        .ok()
        .and_then(|events| field(&events, "max").ok().flatten());
    if memory_peak_bytes.is_none()
        && tasks_peak.is_none()
        && memory_events.is_none()
        && tasks_max_events.is_none()
    {
        return None;
    }
    Some(ScopeUsage {
        memory_peak_bytes,
        tasks_peak,
        memory_events,
        tasks_max_events,
        observed_after_stop,
        observed_while_frozen: false,
    })
}

fn optional_counter(directory: &File, name: &str) -> Option<u64> {
    control_text(directory, name)
        .ok()
        .and_then(|value| parse_integer(&value).ok())
}

fn parse_integer(text: &str) -> io::Result<u64> {
    text.trim()
        .parse::<u64>()
        .map_err(|_| invalid("invalid TShark scope limit"))
}

pub(super) fn ensure_unlimited(value: &str) -> io::Result<()> {
    if value.trim() == "max" {
        return Ok(());
    }
    // Reject malformed records as well as finite limits rather than guessing
    parse_integer(value)?;
    Err(invalid("TShark scope would escape a finite parent limit"))
}

pub(super) fn ensure_domain(value: &str) -> io::Result<()> {
    if value.trim() == "domain" {
        Ok(())
    } else {
        Err(invalid("threaded TShark parent cgroups are unsupported"))
    }
}

pub(super) fn check_controls(
    limits: &Limits,
    memory: &str,
    high: &str,
    swap: &str,
    tasks: &str,
    oom: &str,
) -> io::Result<Limits> {
    let memory = parse_integer(memory)?;
    let high = parse_integer(high)?;
    let swap = parse_integer(swap)?;
    let tasks = parse_integer(tasks)?;
    let oom = parse_integer(oom)?;
    if memory == 0
        || memory > limits.memory_max
        || high > limits.memory_high
        || swap > limits.swap_max
        || tasks == 0
        || tasks > limits.tasks_max
        || oom != 1
    {
        return Err(invalid("TShark scope controls are not enforced"));
    }
    Ok(Limits {
        memory_max: memory,
        memory_high: high,
        swap_max: swap,
        tasks_max: tasks,
    })
}

pub(super) fn parse_populated(text: &str) -> io::Result<bool> {
    parse_event(text, "populated")
}

pub(super) fn parse_frozen(text: &str) -> io::Result<bool> {
    parse_event(text, "frozen")
}

fn parse_event(text: &str, name: &str) -> io::Result<bool> {
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(name) {
            let value = match (fields.next(), fields.next()) {
                (Some("0"), None) => false,
                (Some("1"), None) => true,
                _ => return Err(invalid("invalid TShark scope state")),
            };
            // Conflicting duplicate fields cannot prove that cleanup finished
            if found.replace(value).is_some() {
                return Err(invalid("invalid TShark scope state"));
            }
        }
    }
    found.ok_or_else(|| invalid("invalid TShark scope state"))
}

pub(super) fn sole_member(text: &str, expected: u32) -> io::Result<()> {
    let mut processes = text.split_whitespace();
    if processes.next().and_then(|pid| pid.parse::<u32>().ok()) != Some(expected)
        || processes.next().is_some()
    {
        return Err(invalid("TShark scope has unexpected live processes"));
    }
    Ok(())
}

pub(super) fn reject_subgroups(directory: &File) -> io::Result<()> {
    const MAX_ENTRIES: usize = 1024;
    let path = descriptor_source(directory)?;
    for (index, entry) in std::fs::read_dir(path)?.enumerate() {
        if index >= MAX_ENTRIES {
            return Err(invalid("TShark scope directory is too large"));
        }
        if entry?.file_type()?.is_dir() {
            return Err(invalid("TShark scope has a child cgroup"));
        }
    }
    Ok(())
}

pub(super) fn scope_removed(error: &io::Error) -> bool {
    // An already removed cgroup cannot contain any live processes
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENODEV))
}
