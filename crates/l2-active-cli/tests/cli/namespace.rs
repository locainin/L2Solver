use std::{
    error::Error,
    os::unix::fs::MetadataExt,
    process::{Command, Output},
};

/// Build the command selected by the test environment
#[must_use]
pub fn command() -> Command {
    let main = std::env::var_os("L2_TEST_MAIN_BINARY");
    let binary = main
        .clone()
        .or_else(|| std::env::var_os("L2_TEST_ACTIVE_BINARY"))
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_l2solver-active").into());
    let mut command = Command::new(binary);
    if main.is_some() || std::env::var_os("L2_TEST_ACTIVE_MAIN").is_some() {
        command.arg("active");
    }
    command
}

/// Check that the network namespace differs from the parent
///
/// # Errors
/// Returns an error when either namespace identity cannot be read or parsed
///
/// # Panics
/// Panics when the current namespace matches the parent namespace
pub fn assert_owned() -> Result<(), Box<dyn Error>> {
    let parent = (
        std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse::<u64>()?,
        std::env::var("L2_TEST_PARENT_NET_INODE")?.parse::<u64>()?,
    );
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!((namespace.dev(), namespace.ino()), parent);
    Ok(())
}

/// Check the command output and return its report
///
/// # Errors
/// Returns an error when the report is not valid JSON
///
/// # Panics
/// Panics when the command or report does not show a completed observation
pub fn completed(output: &Output, operation: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.get("operation").and_then(serde_json::Value::as_str),
        Some(operation)
    );
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        report.get("completion").and_then(serde_json::Value::as_str),
        Some("complete")
    );
    assert_eq!(
        report
            .pointer("/rx/capture_loss")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/cleanup/confirmed")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(report)
}

/// Check that one packet with the expected size was accepted
///
/// # Panics
/// Panics when the packet or byte totals differ
pub fn accepted(report: &serde_json::Value, bytes: u64) {
    assert_eq!(
        report
            .pointer("/tx/accepted_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/tx/accepted_bytes")
            .and_then(serde_json::Value::as_u64),
        Some(bytes)
    );
}

/// Wait for the selected multicast membership to appear
///
/// # Errors
/// Returns an error if the child stops, the wait expires, or status or table lookup fails
pub fn await_membership(
    child: &mut std::process::Child,
    index: u32,
    group: &str,
    baseline: u32,
) -> Result<(), Box<dyn Error>> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_millis(1500);
    while memberships(index, group)? <= baseline {
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("listener did not join the expected group".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

/// Read the multicast membership count for an interface and group
///
/// # Errors
/// Returns an error when the kernel table cannot be read or parsed
pub fn memberships(index: u32, group: &str) -> Result<u32, Box<dyn Error>> {
    for line in std::fs::read_to_string("/proc/net/dev_mcast")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(raw_index) = fields.next() else {
            continue;
        };
        let _name = fields.next();
        let users = fields.next();
        let _global = fields.next();
        let address = fields.next();
        if raw_index.parse::<u32>()? == index && address == Some(group) {
            return Ok(users.ok_or("missing multicast user count")?.parse()?);
        }
    }
    Ok(0)
}
