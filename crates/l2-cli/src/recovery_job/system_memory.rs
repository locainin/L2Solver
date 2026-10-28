//! Read bounded Linux memory observations without changing kernel limits

mod monitor;
pub(super) use monitor::Monitor;

#[cfg(test)]
#[path = "../../tests/recovery_job/system_memory.rs"]
mod tests;

use l2_workbench::job::{CgroupMemoryEvents, CgroupMemorySnapshot, SystemMemorySnapshot};
use std::{
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

const MAX_PROC_BYTES: u64 = 64 * 1024;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const MAX_ANCESTORS: usize = 128;

pub(super) struct Reader {
    status: PathBuf,
    hierarchy: Vec<PathBuf>,
}

impl Reader {
    pub(super) fn open(proc_directory: &Path) -> io::Result<Self> {
        let cgroups = text(&proc_directory.join("cgroup"), MAX_PROC_BYTES)?;
        let mounts = text(&proc_directory.join("mountinfo"), MAX_MOUNTINFO_BYTES)?;
        Ok(Self {
            status: proc_directory.join("status"),
            hierarchy: hierarchy(&cgroups, &mounts)?,
        })
    }

    pub(super) fn sample(&self) -> io::Result<SystemMemorySnapshot> {
        let status = text(&self.status, MAX_PROC_BYTES)?;
        let rss = status_bytes(&status, "VmRSS:")?;
        let peak_rss = status_bytes(&status, "VmHWM:")?;
        Ok(SystemMemorySnapshot {
            process_rss_bytes: rss,
            process_peak_rss_bytes: peak_rss,
            cgroup: self.cgroup_sample()?,
        })
    }

    fn cgroup_sample(&self) -> io::Result<Option<CgroupMemorySnapshot>> {
        let Some(leaf) = self.hierarchy.first() else {
            return Ok(None);
        };
        let current = match text(&leaf.join("memory.current"), MAX_PROC_BYTES) {
            Ok(value) => integer(value.trim())?,
            // A unified hierarchy can exist without a delegated memory controller
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let stat = text(&leaf.join("memory.stat"), MAX_PROC_BYTES)?;
        let events = text(&leaf.join("memory.events"), MAX_PROC_BYTES)?;
        let mut sample = CgroupMemorySnapshot {
            current_bytes: current,
            peak_bytes: optional_integer(&leaf.join("memory.peak"))?,
            anonymous_bytes: field(&stat, "anon")?,
            file_bytes: field(&stat, "file")?,
            kernel_bytes: field(&stat, "kernel")?,
            shared_bytes: field(&stat, "shmem")?,
            dirty_file_bytes: field(&stat, "file_dirty")?,
            writeback_file_bytes: field(&stat, "file_writeback")?,
            inactive_file_bytes: field(&stat, "inactive_file")?,
            effective_max_bytes: None,
            effective_high_bytes: None,
            max_headroom_bytes: None,
            high_headroom_bytes: None,
            events: CgroupMemoryEvents {
                high: field(&events, "high")?.ok_or_else(invalid)?,
                max: field(&events, "max")?.ok_or_else(invalid)?,
                oom: field(&events, "oom")?.ok_or_else(invalid)?,
                oom_kill: field(&events, "oom_kill")?.ok_or_else(invalid)?,
            },
        };
        for (index, directory) in self.hierarchy.iter().enumerate() {
            let mount_root = index + 1 == self.hierarchy.len();
            let maximum = limit(&directory.join("memory.max"), mount_root)?;
            let high = limit(&directory.join("memory.high"), mount_root)?;
            if maximum.is_none() && high.is_none() {
                continue;
            }
            let used = if index == 0 {
                current
            } else {
                integer(text(&directory.join("memory.current"), MAX_PROC_BYTES)?.trim())?
            };
            inherit(&mut sample.effective_max_bytes, maximum);
            inherit(&mut sample.effective_high_bytes, high);
            inherit(
                &mut sample.max_headroom_bytes,
                maximum.map(|limit| limit.saturating_sub(used)),
            );
            inherit(
                &mut sample.high_headroom_bytes,
                high.map(|limit| limit.saturating_sub(used)),
            );
        }
        Ok(Some(sample))
    }
}

fn hierarchy(cgroups: &str, mounts: &str) -> io::Result<Vec<PathBuf>> {
    let Some(path) = cgroups.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(Vec::new());
    };
    let path = Path::new(path);
    validate_absolute(path)?;
    let mut selected = None;
    for line in mounts.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            return Err(invalid());
        };
        if after.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let mut fields = before.split_whitespace().skip(3);
        let root = decode_path(fields.next().ok_or_else(invalid)?)?;
        let mount = decode_path(fields.next().ok_or_else(invalid)?)?;
        validate_absolute(&root)?;
        validate_absolute(&mount)?;
        if let Ok(relative) = path.strip_prefix(&root)
            && selected
                .as_ref()
                .is_none_or(|(previous, _): &(PathBuf, PathBuf)| {
                    root.components().count() > previous.components().count()
                })
        {
            let leaf = mount.join(relative);
            selected = Some((root, leaf));
        }
    }
    let Some((root, leaf)) = selected else {
        return Err(invalid());
    };
    // Reconstruct the visible mount boundary without assuming /sys/fs/cgroup
    let suffix_count = path
        .strip_prefix(root)
        .map_err(|_| invalid())?
        .components()
        .count();
    if suffix_count >= MAX_ANCESTORS {
        return Err(invalid());
    }
    Ok(leaf
        .ancestors()
        .take(suffix_count + 1)
        .map(Path::to_path_buf)
        .collect())
}

fn validate_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid());
    }
    Ok(())
}

fn decode_path(value: &str) -> io::Result<PathBuf> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte == b'\\' {
            let escape = [
                input.next().ok_or_else(invalid)?,
                input.next().ok_or_else(invalid)?,
                input.next().ok_or_else(invalid)?,
            ];
            let decoded = match &escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid()),
            };
            bytes.push(decoded);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|_| invalid())
}

fn text(path: &Path, maximum: u64) -> io::Result<String> {
    let mut value = String::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_string(&mut value)?;
    if u64::try_from(value.len()).map_err(|_| invalid())? > maximum {
        return Err(invalid());
    }
    Ok(value)
}

fn integer(value: &str) -> io::Result<u64> {
    value.parse().map_err(|_| invalid())
}

fn optional_integer(path: &Path) -> io::Result<Option<u64>> {
    match text(path, MAX_PROC_BYTES) {
        Ok(value) => integer(value.trim()).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn limit(path: &Path, mount_root: bool) -> io::Result<Option<u64>> {
    match text(path, MAX_PROC_BYTES) {
        Ok(value) if value.trim() == "max" => Ok(None),
        Ok(value) => integer(value.trim()).map(Some),
        // Root cgroups do not expose memory.max and memory.high
        Err(error) if mount_root && error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn field(text: &str, name: &str) -> io::Result<Option<u64>> {
    let mut found = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some(name) {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(integer(words.next().ok_or_else(invalid)?)?);
            if words.next().is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(found)
}

fn status_bytes(text: &str, name: &str) -> io::Result<u64> {
    let mut lines = text.lines().filter_map(|line| line.strip_prefix(name));
    let mut words = lines.next().ok_or_else(invalid)?.split_whitespace();
    let amount = integer(words.next().ok_or_else(invalid)?)?;
    if words.next() != Some("kB") || words.next().is_some() || lines.next().is_some() {
        return Err(invalid());
    }
    amount.checked_mul(1024).ok_or_else(invalid)
}

fn inherit(effective: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *effective = Some(effective.map_or(value, |previous| previous.min(value)));
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Linux memory observation",
    )
}
