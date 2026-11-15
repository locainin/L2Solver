//! Build a mandatory, descriptor-bound sandbox for each offline `TShark` process

use super::secure_files::{VerifiedExecutable, Workspace};
use l2_workbench::job::ResourcePlan;
use std::{ffi::OsString, fs::File, io, path::PathBuf, time::Instant};

#[cfg(target_os = "linux")]
use {
    super::secure_files::descriptor_source,
    rustix::fs::{self, CWD, Mode, OFlags},
    std::{
        ffi::OsStr,
        io::{Read, Write},
        os::unix::ffi::{OsStrExt, OsStringExt},
        path::Path,
    },
};

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/sandbox.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/sandbox_bridge.rs"]
mod bridge_tests;

#[cfg(target_os = "linux")]
const BRIDGE: &str = concat!(
    "shopt -s failglob || exit 126; ",
    "for fd in /proc/self/fd/*; do ",
    "fd=${fd##*/}; [[ $fd =~ ^[0-9]+$ ]] || exit 126; ",
    "if (( fd >= 3 )); then exec {fd}<&- || exit 126; fi; done; ",
    "exec 3<\"$1\" 4<\"$2\" 5<\"$3\" || exit 126; ",
    "if [[ -n $4 ]]; then exec 6<\"$4\" || exit 126; fi; ",
    "if [[ -n $5 ]]; then exec 7<\"$5\" || exit 126; fi; ",
    "if [[ -n $6 ]]; then exec 8<\"$6\" || exit 126; fi; ",
    "if [[ $7 == 1 ]]; then exec 9>&1 || exit 126; fi; ",
    "output=$7; shift 7; ",
    "if [[ $output != 1 ]]; then exec \"$@\"; fi; ",
    "\"$@\" <&0 & child=$!; ",
    "wait \"$child\"; status=$?; ",
    "printf 'L2_EXPORT_DONE:%d\\n' \"$status\" || exit 126; ",
    "exec 1>&- 9>&- 2>/dev/null || exit 126; ",
    "IFS= read -r || :; exit 0",
);

#[cfg(target_os = "linux")]
const OUTPUT_BOOTSTRAP: &str = concat!(
    "printf 'L2_EXPORT_READY\\n' || exit 126; ",
    "IFS= read -r reply || exit 126; ",
    "[[ $reply == L2_EXPORT_GO ]] || exit 126; ",
    "exec </dev/null >/dev/null || exit 126; ",
    "exec \"$@\"",
);

#[cfg(target_os = "linux")]
const BWRAP_OPTIONS: &[&str] = &[
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--disable-userns",
    "--uid",
    "65534",
    "--gid",
    "65534",
    "--cap-drop",
    "ALL",
    "--new-session",
    "--die-with-parent",
    "--as-pid-1",
    "--clearenv",
    "--setenv",
    "PATH",
    "/usr/bin:/bin",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/bin",
    "/bin",
    "--ro-bind-try",
    "/lib",
    "/lib",
    "--ro-bind-try",
    "/lib64",
    "/lib64",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--dir",
    "/tool",
];

#[cfg(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BLOCKED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_setns,
    libc::SYS_unshare,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_bpf,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
];

/// Own the trusted files used to prepare every sandboxed invocation
pub(super) struct Sandbox {
    #[cfg(target_os = "linux")]
    plan: ResourcePlan,
    #[cfg(target_os = "linux")]
    deadline: Instant,
    #[cfg(target_os = "linux")]
    workspace: File,
    #[cfg(target_os = "linux")]
    workspace_path: PathBuf,
    #[cfg(target_os = "linux")]
    executable: File,
    #[cfg(target_os = "linux")]
    capture: Option<File>,
    #[cfg(target_os = "linux")]
    keylog: Option<File>,
    #[cfg(target_os = "linux")]
    shell: File,
    #[cfg(target_os = "linux")]
    bubblewrap: File,
    #[cfg(target_os = "linux")]
    filter: File,
}

/// Hold the descriptors until the launched process and its sandbox have exited
pub(super) struct Launch {
    pub(super) executable: PathBuf,
    pub(super) arguments: Vec<OsString>,
    pub(super) environment: Vec<(OsString, OsString)>,
    #[cfg(target_os = "linux")]
    pub(super) handles: Vec<File>,
    #[cfg(target_os = "linux")]
    pub(super) scope: Option<super::resource_scope::Gate>,
    #[cfg(target_os = "linux")]
    pub(super) output_bootstrap: bool,
    #[cfg(target_os = "linux")]
    pub(super) output_storage: Option<super::output_storage::OutputStorage>,
}

impl Sandbox {
    /// Pin the launcher, target, workspace, and optional input files
    pub(super) fn new(
        workspace: &Workspace,
        executable: &VerifiedExecutable,
        capture: Option<&File>,
        keylog: Option<&File>,
        plan: &ResourcePlan,
        deadline: Instant,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            check_privileges()?;
            let shell = trusted_system_executable(Path::new("/usr/bin/bash"))?;
            let bubblewrap = trusted_system_executable(Path::new("/usr/bin/bwrap"))?;
            // The anonymous filter is bound to the held workspace, not a replaceable name
            let mut filter = tempfile::tempfile_in(descriptor_source(&workspace.handle)?)?;
            filter.write_all(&seccomp_filter()?)?;
            Ok(Self {
                plan: *plan,
                deadline,
                workspace: workspace.handle.try_clone()?,
                workspace_path: workspace.path().to_owned(),
                executable: executable.file.try_clone()?,
                capture: capture.map(File::try_clone).transpose()?,
                keylog: keylog.map(File::try_clone).transpose()?,
                shell,
                bubblewrap,
                filter,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workspace, executable, capture, keylog, plan, deadline);
            Err(unsupported())
        }
    }

    /// Build a launch with private, bounded output and pinned mount sources
    pub(super) fn command(
        &self,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        output: Option<&[String]>,
    ) -> io::Result<Launch> {
        #[cfg(target_os = "linux")]
        {
            check_privileges()?;
            let mut handles = Vec::new();
            let shell = held_source(&mut handles, &self.shell)?;
            let bubblewrap = held_source(&mut handles, &self.bubblewrap)?;
            let filter = held_source(&mut handles, &self.filter)?;
            let workspace = held_source(&mut handles, &self.workspace)?;
            let executable = held_source(&mut handles, &self.executable)?;
            let capture = self
                .capture
                .as_ref()
                .map(|file| held_source(&mut handles, file))
                .transpose()?;
            let keylog = self
                .keylog
                .as_ref()
                .map(|file| held_source(&mut handles, file))
                .transpose()?;
            // Clear inherited handles before opening only the sources this launch needs
            let mut command: Vec<OsString> =
                ["--noprofile", "--norc", "-c", BRIDGE, "l2solver-sandbox"]
                    .into_iter()
                    .map(OsString::from)
                    .collect();
            command.push(filter.into_os_string());
            command.push(workspace.into_os_string());
            command.push(executable.into_os_string());
            for source in [&capture, &keylog] {
                command.push(
                    source
                        .as_ref()
                        .map_or_else(OsString::new, |path| path.as_os_str().to_owned()),
                );
            }
            command.push(if output.is_some() {
                shell.as_os_str().to_owned()
            } else {
                OsString::new()
            });
            command.push(OsString::from(if output.is_some() { "1" } else { "0" }));
            command.push(bubblewrap.into_os_string());
            command.extend(BWRAP_OPTIONS.iter().map(OsString::from));
            self.append_mounts(&mut command, output, capture.is_some(), keylog.is_some())?;
            self.append_environment(&mut command, environment, output.is_some());
            self.append_target(&mut command, arguments, output.is_some());
            let launch = Launch {
                executable: shell,
                arguments: command,
                // No caller-controlled environment reaches the pre-sandbox shell or bwrap
                environment: Vec::new(),
                handles,
                scope: None,
                output_bootstrap: output.is_some(),
                output_storage: None,
            };
            self.scope_launch(launch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (arguments, environment, output);
            Err(unsupported())
        }
    }

    #[cfg(target_os = "linux")]
    fn scope_launch(&self, launch: Launch) -> io::Result<Launch> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TShark sandbox deadline expired",
            ));
        }
        let limits = self.plan.limits();
        super::resource_scope::ResourceScope::new(
            limits.child_memory_bytes,
            limits.child_swap_bytes,
            limits.child_tasks,
            remaining,
        )?
        .wrap(launch)
    }

    #[cfg(target_os = "linux")]
    fn append_target(&self, command: &mut Vec<OsString>, arguments: &[OsString], output: bool) {
        command.extend(
            ["--chdir", "/work", "--seccomp", "3", "--"]
                .into_iter()
                .map(OsString::from),
        );
        if output {
            command.extend(
                [
                    "/tool/bootstrap",
                    "--noprofile",
                    "--norc",
                    "-c",
                    OUTPUT_BOOTSTRAP,
                    "l2solver-object-export",
                ]
                .into_iter()
                .map(OsString::from),
            );
        }
        command.push(OsString::from("/tool/tshark"));
        command.extend(
            arguments
                .iter()
                .map(|argument| self.map_argument(argument, output)),
        );
    }

    #[cfg(target_os = "linux")]
    fn append_mounts(
        &self,
        command: &mut Vec<OsString>,
        output: Option<&[String]>,
        capture: bool,
        keylog: bool,
    ) -> io::Result<()> {
        let limits = self.plan.limits();
        append_tmpfs(command, "/tmp", limits.tmpfs_bytes.get(), "1777");
        append_tmpfs(command, "/dev/shm", limits.shm_bytes.get(), "1777");
        append_bind(command, "--ro-bind-fd", "4", "/work");
        append_bind(command, "--ro-bind-fd", "5", "/tool/tshark");
        if capture {
            append_bind(command, "--ro-bind-fd", "6", "/work/capture.bin");
        }
        if keylog {
            append_bind(command, "--ro-bind-fd", "7", "/work/tls-keylog.txt");
        }
        if let Some(protocols) = output {
            if protocols
                .iter()
                .any(|protocol| !super::objects::valid_type(protocol))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid output protocol",
                ));
            }
            append_tmpfs(command, "/output", limits.object_bytes.get(), "0700");
            for protocol in protocols {
                command.extend([
                    OsString::from("--dir"),
                    OsString::from(format!("/output/{protocol}")),
                ]);
            }
            append_bind(command, "--ro-bind-fd", "8", "/tool/bootstrap");
            command.extend([OsString::from("--json-status-fd"), OsString::from("9")]);
        }
        // The implicit root and device mounts must not provide spare writable space
        command.extend(
            ["--remount-ro", "/", "--remount-ro", "/dev"]
                .into_iter()
                .map(OsString::from),
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn append_environment(
        &self,
        command: &mut Vec<OsString>,
        environment: &[(OsString, OsString)],
        output: bool,
    ) {
        for (name, value) in environment {
            let value = if ["TMPDIR", "TMP", "TEMP"]
                .iter()
                .any(|candidate| name.as_os_str() == OsStr::new(candidate))
            {
                OsString::from("/tmp")
            } else {
                self.map_argument(value, output)
            };
            command.extend([OsString::from("--setenv"), name.clone(), value]);
        }
    }

    #[cfg(target_os = "linux")]
    fn map_argument(&self, argument: &OsStr, output: bool) -> OsString {
        let bytes = argument.as_bytes();
        if let Some(mapped) = self.map_path(bytes, output) {
            return OsString::from_vec(mapped);
        }
        // TShark embeds paths after a preference colon or an export protocol comma
        let prefix_length = if bytes.starts_with(b"tls.keylog_file:") {
            Some(b"tls.keylog_file:".len())
        } else {
            bytes
                .iter()
                .position(|byte| *byte == b',')
                .map(|index| index + 1)
        };
        if let Some(index) = prefix_length {
            let (prefix, path) = bytes.split_at(index);
            if let Some(mapped) = self.map_path(path, output) {
                let mut value = prefix.to_vec();
                value.extend_from_slice(&mapped);
                return OsString::from_vec(value);
            }
        }
        argument.to_owned()
    }

    #[cfg(target_os = "linux")]
    fn map_path(&self, path: &[u8], output: bool) -> Option<Vec<u8>> {
        let suffix = path.strip_prefix(self.workspace_path.as_os_str().as_bytes())?;
        if suffix.first().is_some_and(|byte| *byte != b'/') {
            return None;
        }
        if output
            && let Some(export_suffix) = suffix.strip_prefix(b"/export-objects")
            && export_suffix.first().is_none_or(|byte| *byte == b'/')
        {
            let mut mapped = b"/output".to_vec();
            mapped.extend_from_slice(export_suffix);
            return Some(mapped);
        }
        let mut mapped = b"/work".to_vec();
        mapped.extend_from_slice(suffix);
        Some(mapped)
    }
}

/// Reject root, inconsistent credentials, and any usable or inheritable capability
pub(super) fn check_privileges() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        const PROC_SUPER_MAGIC: u64 = 0x9fa0;
        const MAX_STATUS_BYTES: u64 = 65_536;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let proc_directory = File::from(fs::openat(CWD, "/proc", flags, Mode::empty())?);
        if u64::try_from(fs::fstatfs(&proc_directory)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
            return Err(unsupported());
        }
        // thread-self reports the exact calling thread even if another thread changed credentials
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let status = File::from(fs::openat(
            &proc_directory,
            "thread-self/status",
            flags,
            Mode::empty(),
        )?);
        if u64::try_from(fs::fstatfs(&status)?.f_type).ok() != Some(PROC_SUPER_MAGIC) {
            return Err(unsupported());
        }
        let mut contents = String::new();
        status
            .take(MAX_STATUS_BYTES)
            .read_to_string(&mut contents)?;
        check_status(&contents)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(unsupported())
    }
}

#[cfg(target_os = "linux")]
fn check_status(status: &str) -> io::Result<()> {
    let mut fields = [None; 6];
    let names = ["Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapAmb"];
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if let Some(index) = names.iter().position(|candidate| *candidate == name) {
            let slot = fields.get_mut(index).ok_or_else(invalid_status)?;
            if slot.replace(value.trim()).is_some() {
                return Err(invalid_status());
            }
        }
    }
    let [
        Some(uid),
        Some(gid),
        Some(inheritable),
        Some(permitted),
        Some(effective),
        Some(ambient),
    ] = fields
    else {
        return Err(invalid_status());
    };
    check_ids(uid)?;
    check_ids(gid)?;
    for capability in [inheritable, permitted, effective, ambient] {
        if u64::from_str_radix(capability, 16).ok() != Some(0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TShark sandbox requires no process capabilities",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_ids(value: &str) -> io::Result<()> {
    let ids: Vec<u32> = value
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| invalid_status())?;
    let [real, effective, saved, filesystem] = ids.as_slice() else {
        return Err(invalid_status());
    };
    if *real == 0 || real != effective || real != saved || real != filesystem {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TShark sandbox requires matching non-root credentials",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn invalid_status() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "cannot verify process credentials",
    )
}

#[cfg(target_os = "linux")]
pub(super) fn trusted_system_executable(path: &Path) -> io::Result<File> {
    let executable = VerifiedExecutable::open(path)?;
    if fs::fstat(&executable.file)?.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sandbox launcher is not owned by root",
        ));
    }
    // File capabilities could otherwise grant privileges before bwrap sets NoNewPrivs
    match fs::fgetxattr(&executable.file, "security.capability", &mut [0u8; 1]) {
        Err(rustix::io::Errno::NODATA) => Ok(executable.file),
        Ok(_) | Err(rustix::io::Errno::RANGE) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sandbox launcher has file capabilities",
        )),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn held_source(handles: &mut Vec<File>, file: &File) -> io::Result<PathBuf> {
    let held = file.try_clone()?;
    let source = descriptor_source(&held)?;
    handles.push(held);
    Ok(source)
}

#[cfg(target_os = "linux")]
fn append_bind(arguments: &mut Vec<OsString>, option: &str, source: &str, destination: &str) {
    arguments.extend([
        OsString::from(option),
        OsString::from(source),
        OsString::from(destination),
    ]);
}

#[cfg(target_os = "linux")]
fn append_tmpfs(arguments: &mut Vec<OsString>, destination: &str, size: u64, mode: &str) {
    arguments.extend([
        OsString::from("--size"),
        OsString::from(size.to_string()),
        OsString::from("--perms"),
        OsString::from(mode),
        OsString::from("--tmpfs"),
        OsString::from(destination),
    ]);
}

#[cfg(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn seccomp_filter() -> io::Result<Vec<u8>> {
    // seccomp_data begins with the syscall number, architecture, and instruction pointer
    const LOAD_WORD: u16 = 0x20;
    const JUMP_EQUAL: u16 = 0x15;
    const JUMP_GREATER_EQUAL: u16 = 0x35;
    const JUMP_BITS_SET: u16 = 0x45;
    const RETURN: u16 = 0x06;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const RETURN_ERRNO: u32 = 0x0005_0000;
    const ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    let mut instructions = Vec::new();
    push_instruction(&mut instructions, LOAD_WORD, 0, 0, 4);
    push_instruction(&mut instructions, JUMP_EQUAL, 1, 0, ARCH);
    push_instruction(&mut instructions, RETURN, 0, 0, KILL_PROCESS);
    push_instruction(&mut instructions, LOAD_WORD, 0, 0, 0);
    // The x32 ABI shares the x86-64 architecture code but has different syscall numbers
    #[cfg(target_arch = "x86_64")]
    {
        push_instruction(&mut instructions, JUMP_GREATER_EQUAL, 0, 1, 0x4000_0000);
        push_instruction(&mut instructions, RETURN, 0, 0, KILL_PROCESS);
    }
    #[cfg(target_arch = "aarch64")]
    let _ = JUMP_GREATER_EQUAL;
    let clone3 = u32::try_from(libc::SYS_clone3).map_err(|_| unsupported())?;
    push_instruction(&mut instructions, JUMP_EQUAL, 0, 1, clone3);
    // glibc retries ordinary clone when clone3 reports that it is unavailable
    push_instruction(
        &mut instructions,
        RETURN,
        0,
        0,
        RETURN_ERRNO | u32::try_from(libc::ENOSYS).map_err(|_| unsupported())?,
    );
    let clone = u32::try_from(libc::SYS_clone).map_err(|_| unsupported())?;
    push_instruction(&mut instructions, JUMP_EQUAL, 0, 4, clone);
    push_instruction(&mut instructions, LOAD_WORD, 0, 0, 16);
    let namespace_flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET;
    push_instruction(
        &mut instructions,
        JUMP_BITS_SET,
        0,
        1,
        u32::try_from(namespace_flags).map_err(|_| unsupported())?,
    );
    push_instruction(
        &mut instructions,
        RETURN,
        0,
        0,
        RETURN_ERRNO | u32::try_from(libc::EPERM).map_err(|_| unsupported())?,
    );
    push_instruction(&mut instructions, LOAD_WORD, 0, 0, 0);
    for &syscall in BLOCKED_SYSCALLS {
        push_instruction(
            &mut instructions,
            JUMP_EQUAL,
            0,
            1,
            u32::try_from(syscall).map_err(|_| unsupported())?,
        );
        push_instruction(
            &mut instructions,
            RETURN,
            0,
            0,
            RETURN_ERRNO | u32::try_from(libc::EPERM).map_err(|_| unsupported())?,
        );
    }
    push_instruction(&mut instructions, RETURN, 0, 0, ALLOW);
    Ok(instructions)
}

#[cfg(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn push_instruction(bytes: &mut Vec<u8>, code: u16, yes: u8, no: u8, value: u32) {
    // sock_filter stores these four fields in native byte order without padding
    bytes.extend_from_slice(&code.to_ne_bytes());
    bytes.extend_from_slice(&[yes, no]);
    bytes.extend_from_slice(&value.to_ne_bytes());
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn seccomp_filter() -> io::Result<Vec<u8>> {
    Err(unsupported())
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "mandatory TShark sandbox is unavailable",
    )
}
