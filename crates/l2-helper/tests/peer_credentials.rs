#![cfg(target_os = "linux")]

use std::{
    env,
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    process::{Command, Stdio},
};

use l2_helper::{FrontendTransport, TransportError};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, connect, listen,
    socket_with, socketpair,
};

const CHILD_SOCKET_ENV: &str = "L2SOLVER_HELPER_TEST_SOCKET";

#[test]
fn different_peer_snapshots_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(name) = env::var_os(CHILD_SOCKET_ENV) {
        return connect_child(&name);
    }

    let socket_dir = tempfile::Builder::new()
        .prefix("l2solver-helper-peer-")
        .tempdir()?;
    // The random basename keeps the address short even under a deeply nested temporary root
    let socket_name = socket_dir
        .path()
        .file_name()
        .ok_or_else(|| io::Error::other("temporary directory has no basename"))?
        .to_os_string();
    let address = SocketAddrUnix::new_abstract_name(socket_name.as_os_str().as_bytes())?;
    let listener = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    bind(&listener, &address)?;
    listen(&listener, 1)?;

    // The child connects after process creation so the kernel records its PID
    let current_test = env::current_exe()?;
    let mut child = Command::new(current_test)
        .args([
            "--exact",
            "different_peer_snapshots_are_rejected",
            "--nocapture",
        ])
        .env(CHILD_SOCKET_ENV, &socket_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let data = accept_with(&listener, SocketFlags::CLOEXEC)?;
    let status = child.wait()?;
    assert!(status.success(), "credential test child failed: {status}");

    // This channel records the parent as its socketpair-time peer
    let (control, _control_peer) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let result = FrontendTransport::from_owned_fds(data, control);
    assert!(matches!(
        result,
        Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    Ok(())
}

fn connect_child(name: &OsStr) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    connect(
        &socket,
        &SocketAddrUnix::new_abstract_name(name.as_bytes())?,
    )?;
    Ok(())
}
