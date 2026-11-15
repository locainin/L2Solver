//! Put the sandbox in a verified child cgroup before it can start

use super::{
    sandbox::{Launch, trusted_system_executable},
    secure_files::descriptor_source,
};
mod kernel;

use self::kernel::{
    control_text, ensure_parent_outside, ensure_unlimited, observe_usage, open_cgroup,
    parent_cgroups, parse_frozen, parse_populated, proc_text, reject_subgroups, scope_receipt,
    scope_removed, sole_member,
};
use crate::recovery_job::system_memory::{hierarchy, read_bounded};
use l2_workbench::tshark::ScopeReceipt;
use rustix::{
    fs::{self, AtFlags, CWD, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write},
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/resource_scope.rs"]
mod tests;

const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const MAX_PROC_BYTES: u64 = 64 * 1024;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const GATE_SCRIPT: &str = "[[ $PPID == \"$1\" ]] || exit 126; shift; IFS= read -r token && [[ $token == scope ]] || exit 126; exec \"$@\"";
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

/// Hold a pinned systemd launcher and the controls for one sandbox process
pub(super) struct ResourceScope {
    limits: Limits,
    systemd: File,
    setpriv: File,
    runtime: File,
    runtime_micros: u64,
    unit: String,
}

#[derive(Clone, Copy)]
struct Limits {
    memory_max: u64,
    memory_high: u64,
    swap_max: u64,
    tasks_max: u64,
}

impl Limits {
    fn new(memory: NonZeroU64, swap: u64, tasks: NonZeroU64, page: u64) -> io::Result<Self> {
        if page == 0 {
            return Err(invalid("invalid memory page size"));
        }
        // The kernel rounds memory limits upward, so round down before sending them
        let memory_max = memory.get() / page * page;
        if memory_max == 0 {
            return Err(invalid("TShark memory limit is smaller than a page"));
        }
        let high = memory_max - memory_max / 4;
        Ok(Self {
            memory_max,
            memory_high: high / page * page,
            swap_max: swap / page * page,
            tasks_max: tasks.get(),
        })
    }
}

impl ResourceScope {
    pub(super) fn new(
        memory_max: NonZeroU64,
        swap_max: u64,
        tasks_max: NonZeroU64,
        remaining: Duration,
    ) -> io::Result<Self> {
        let runtime_micros = runtime_micros(remaining)?;
        let page = u64::try_from(rustix::param::page_size())
            .map_err(|_| invalid("invalid memory page size"))?;
        let limits = Limits::new(memory_max, swap_max, tasks_max, page)?;
        let systemd = trusted_system_executable(Path::new("/usr/bin/systemd-run"))?;
        let setpriv = trusted_system_executable(Path::new("/usr/bin/setpriv"))?;
        let runtime = trusted_runtime()?;
        let sequence = NEXT_SCOPE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| io::Error::other("TShark scope identifiers exhausted"))?;
        let unit = format!("l2solver-{}-{sequence}.scope", std::process::id());
        Ok(Self {
            limits,
            systemd,
            setpriv,
            runtime,
            runtime_micros,
            unit,
        })
    }

    /// Hold every descriptor until the caller finishes monitoring the child
    pub(super) fn wrap(self, mut launch: Launch) -> io::Result<Launch> {
        if launch.scope.is_some() {
            return Err(invalid("TShark launch already has a resource scope"));
        }
        let systemd = descriptor_source(&self.systemd)?;
        let setpriv = descriptor_source(&self.setpriv)?;
        let runtime = descriptor_source(&self.runtime)?;
        let gate_shell = launch.executable;
        let mut arguments = vec![
            OsString::from("--no-new-privs"),
            OsString::from("--pdeathsig"),
            OsString::from("KILL"),
            systemd.into_os_string(),
        ];
        arguments.extend(
            [
                "--user".to_owned(),
                "--scope".to_owned(),
                "--collect".to_owned(),
                "--quiet".to_owned(),
                "--no-ask-password".to_owned(),
                "--expand-environment=no".to_owned(),
                format!("--unit={}", self.unit),
                format!("--property=MemoryMax={}", self.limits.memory_max),
                format!("--property=MemoryHigh={}", self.limits.memory_high),
                format!("--property=MemorySwapMax={}", self.limits.swap_max),
                format!("--property=TasksMax={}", self.limits.tasks_max),
                "--property=OOMPolicy=kill".to_owned(),
                format!("--property=RuntimeMaxSec={}us", self.runtime_micros),
                "--property=KillSignal=SIGKILL".to_owned(),
                "--property=KillMode=control-group".to_owned(),
                "--".to_owned(),
            ]
            .into_iter()
            .map(OsString::from),
        );
        arguments.push(gate_shell.as_os_str().to_owned());
        arguments.extend(
            ["--noprofile", "--norc", "-c", GATE_SCRIPT, "l2solver-gate"]
                .into_iter()
                .map(OsString::from),
        );
        arguments.push(OsString::from(std::process::id().to_string()));
        arguments.push(gate_shell.into_os_string());
        arguments.append(&mut launch.arguments);
        launch.executable = setpriv;
        launch.arguments = arguments;
        launch
            .environment
            .push((OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()));
        launch
            .handles
            .extend([self.systemd, self.setpriv, self.runtime]);
        launch.scope = Some(Gate {
            unit: self.unit,
            limits: self.limits,
            verified: None,
            stopped: false,
            claimed: false,
        });
        Ok(launch)
    }
}

/// The running process cannot pass the gate until the parent verifies its scope
pub(super) struct Gate {
    unit: String,
    limits: Limits,
    verified: Option<VerifiedScope>,
    stopped: bool,
    claimed: bool,
}

struct VerifiedScope {
    child_pid: u32,
    directory: File,
    kill: File,
    freeze: File,
    freeze_requested: bool,
    frozen: bool,
    receipt: ScopeReceipt,
}

impl Gate {
    /// Consume this gate before spawning so failed starts cannot be retried
    pub(super) fn claim(&mut self) -> io::Result<()> {
        if self.claimed {
            return Err(invalid("TShark scope gate cannot be reused"));
        }
        self.claimed = true;
        Ok(())
    }

    /// Return false while the launcher is still joining its unique scope
    pub(super) fn verify(&mut self, child_pid: u32) -> io::Result<bool> {
        if !self.claimed {
            return Err(invalid("TShark scope gate was not claimed"));
        }
        if let Some(scope) = &self.verified {
            if scope.child_pid == child_pid && !self.stopped {
                return Ok(true);
            }
            return Err(invalid("TShark scope gate cannot be reused"));
        }
        if self.stopped {
            return Err(invalid("TShark scope gate cannot be reused"));
        }
        let child_proc = PathBuf::from(format!("/proc/{child_pid}"));
        let mounts = proc_text(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        let child_groups = proc_text(&child_proc.join("cgroup"), MAX_PROC_BYTES)?;
        let child_hierarchy = hierarchy(&child_groups, &mounts)?;
        let Some(leaf) = child_hierarchy.first() else {
            return Err(invalid("unified TShark cgroup is unavailable"));
        };
        if leaf.file_name() != Some(OsStr::new(&self.unit)) {
            return Ok(false);
        }
        let directory = open_cgroup(leaf)?;
        let child_stat = fs::fstat(&directory)?;
        let mut child_ancestors = Vec::with_capacity(child_hierarchy.len());
        for path in &child_hierarchy {
            let stat = fs::fstat(open_cgroup(path)?)?;
            child_ancestors.push((stat.st_dev, stat.st_ino));
        }
        let parent_hierarchy = parent_cgroups(&mounts)?;
        ensure_parent_outside(&parent_hierarchy, &child_stat)?;
        for (parent, metadata) in &parent_hierarchy {
            if !child_ancestors.contains(&(metadata.st_dev, metadata.st_ino)) {
                // Moving to a sibling must not escape an operator's finite hard limit
                for name in ["memory.max", "memory.high", "memory.swap.max", "pids.max"] {
                    match control_text(parent, name) {
                        Ok(value) => ensure_unlimited(&value)?,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        let receipt = scope_receipt(&self.limits, &directory, &child_hierarchy)?;
        // Opening the kernel kill control now proves cleanup is available before release
        let kill = File::from(fs::openat(
            &directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        // Refuse to start if the kernel cannot freeze this exact scope
        let freeze = File::from(fs::openat(
            &directory,
            "cgroup.freeze",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        self.verified = Some(VerifiedScope {
            child_pid,
            directory,
            kill,
            freeze,
            freeze_requested: false,
            frozen: false,
            receipt,
        });
        Ok(true)
    }

    /// Return no receipt until the scope identity and its controls are verified
    pub(super) fn receipt(&self) -> Option<ScopeReceipt> {
        self.verified.as_ref().map(|scope| scope.receipt)
    }

    /// Ask the kernel to stop every task in the verified child scope
    pub(super) fn request_freeze(&mut self) -> io::Result<()> {
        let stopped = self.stopped;
        let scope = self
            .verified
            .as_mut()
            .filter(|_| !stopped)
            .ok_or_else(|| invalid("TShark scope was not verified"))?;
        if scope.freeze_requested {
            return Err(invalid("TShark scope freeze was already requested"));
        }
        let stat = fs::fstat(&scope.directory)?;
        let mounts = proc_text(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        ensure_parent_outside(&parent_cgroups(&mounts)?, &stat)?;
        scope.freeze.write_all(b"1")?;
        scope.freeze_requested = true;
        Ok(())
    }

    /// Check once whether the kernel has finished freezing the scope
    pub(super) fn poll_frozen(&mut self) -> io::Result<bool> {
        let stopped = self.stopped;
        let scope = self
            .verified
            .as_mut()
            .filter(|_| !stopped)
            .ok_or_else(|| invalid("TShark scope was not verified"))?;
        if !scope.freeze_requested {
            return Err(invalid("TShark scope freeze was not requested"));
        }
        scope.frozen = parse_frozen(&control_text(&scope.directory, "cgroup.events")?)?;
        Ok(scope.frozen)
    }

    /// Accept final counters only after the frozen scope contains just the supervisor
    pub(super) fn verify_only_members(&mut self, outer_pid: u32) -> io::Result<()> {
        let stopped = self.stopped;
        let scope = self
            .verified
            .as_mut()
            .filter(|scope| !stopped && scope.frozen)
            .ok_or_else(|| invalid("TShark scope is not frozen"))?;
        if outer_pid != scope.child_pid {
            return Err(invalid("TShark scope supervisor does not match"));
        }
        if !parse_frozen(&control_text(&scope.directory, "cgroup.events")?)? {
            return Err(invalid("TShark scope is no longer frozen"));
        }
        reject_subgroups(&scope.directory)?;
        sole_member(&control_text(&scope.directory, "cgroup.procs")?, outer_pid)?;
        let mut usage = observe_usage(&scope.directory, false);
        if !parse_frozen(&control_text(&scope.directory, "cgroup.events")?)? {
            return Err(invalid("TShark scope is no longer frozen"));
        }
        if let Some(usage) = usage.as_mut() {
            usage.observed_while_frozen = true;
        }
        scope.receipt.usage = usage;
        Ok(())
    }

    /// Bind a sandbox bootstrap process to the same cgroup as the verified launcher
    pub(super) fn verify_member(&self, process: &File) -> io::Result<()> {
        let scope = self
            .verified
            .as_ref()
            .filter(|_| !self.stopped)
            .ok_or_else(|| invalid("TShark scope was not verified"))?;
        let file = File::from(fs::openat(
            process,
            "cgroup",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if u64::try_from(fs::fstatfs(&file)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
            return Err(invalid("TShark bootstrap metadata is not procfs"));
        }
        let groups = read_bounded(file, MAX_PROC_BYTES)?;
        let mounts = proc_text(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        let paths = hierarchy(&groups, &mounts)?;
        let leaf = paths
            .first()
            .ok_or_else(|| invalid("TShark bootstrap cgroup is unavailable"))?;
        let member = fs::fstat(open_cgroup(leaf)?)?;
        let expected = fs::fstat(&scope.directory)?;
        if member.st_dev != expected.st_dev || member.st_ino != expected.st_ino {
            return Err(invalid("TShark bootstrap is outside its verified scope"));
        }
        Ok(())
    }

    /// Kill the same verified scope and wait for all of its processes to leave
    pub(super) fn stop_verified_scope(&mut self, deadline: Instant) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        let scope = self
            .verified
            .as_mut()
            .ok_or_else(|| invalid("TShark scope was not verified"))?;
        let scope_stat = match fs::fstat(&scope.directory) {
            Ok(stat) => stat,
            Err(error) => {
                let error: io::Error = error.into();
                if scope_removed(&error) {
                    self.stopped = true;
                    return Ok(());
                }
                return Err(error);
            }
        };
        // The parent may have moved since startup, so check again before signalling
        let mounts = proc_text(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        ensure_parent_outside(&parent_cgroups(&mounts)?, &scope_stat)?;
        let frozen_sample = scope
            .receipt
            .usage
            .is_some_and(|usage| usage.observed_while_frozen);
        if !frozen_sample {
            scope.receipt.usage = observe_usage(&scope.directory, false);
        }
        if let Err(error) = scope.kill.write_all(b"1") {
            if scope_removed(&error) {
                self.stopped = true;
                return Ok(());
            }
            return Err(error);
        }
        loop {
            match control_text(&scope.directory, "cgroup.events") {
                Ok(events) if !parse_populated(&events)? => {
                    if !frozen_sample && let Some(usage) = observe_usage(&scope.directory, true) {
                        scope.receipt.usage = Some(usage);
                    }
                    self.stopped = true;
                    return Ok(());
                }
                Ok(_) => {}
                Err(error) if scope_removed(&error) => {
                    self.stopped = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TShark scope did not stop before its cleanup deadline",
                ));
            }
            thread::sleep(remaining.min(Duration::from_millis(3)));
        }
    }
}

fn trusted_runtime() -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let run = File::from(fs::openat(CWD, "/run", flags, Mode::empty())?);
    check_directory(&run, 0, 0o022)?;
    let users = File::from(fs::openat(&run, "user", flags, Mode::empty())?);
    check_directory(&users, 0, 0o022)?;
    let uid = geteuid().as_raw();
    let runtime = File::from(fs::openat(&users, uid.to_string(), flags, Mode::empty())?);
    check_directory(&runtime, uid, 0o077)?;
    let bus = fs::statat(&runtime, "bus", AtFlags::SYMLINK_NOFOLLOW)?;
    if bus.st_uid != uid || !FileType::from_raw_mode(bus.st_mode).is_socket() {
        return Err(invalid("TShark scope user bus is not trusted"));
    }
    Ok(runtime)
}

fn check_directory(directory: &File, owner: u32, forbidden_mode: u32) -> io::Result<()> {
    let metadata = fs::fstat(directory)?;
    if metadata.st_uid != owner || metadata.st_mode & forbidden_mode != 0 {
        return Err(invalid("TShark scope runtime directory is not trusted"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn runtime_micros(remaining: Duration) -> io::Result<u64> {
    let micros = u64::try_from(remaining.as_micros())
        .map_err(|_| invalid("TShark runtime limit is too large"))?;
    if micros == 0 || micros == u64::MAX {
        return Err(invalid("TShark runtime limit must be finite and positive"));
    }
    Ok(micros)
}
