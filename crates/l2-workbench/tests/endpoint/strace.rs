use l2_workbench::endpoint::parse_strace;
use std::{error::Error, process::Command};

#[test]
fn failed_zero_no_transferred_bytes() -> Result<(), Box<dyn Error>> {
    let trace = b"412 write(4, \"\\x41\", 1) = -1 EPIPE (Broken pipe)\n412 read(5, \"\", 1) = 0\n";
    let report = parse_strace(trace)?;
    assert_eq!(report.events.len(), 2);
    assert!(report.complete);
    let failed = report.events.first().ok_or("missing failed syscall")?;
    assert_eq!(failed.return_value, Some(-1));
    assert!(failed.bytes_complete);
    assert!(failed.bytes.is_empty());
    assert!(failed.data_source_range.is_some());
    let empty = report.events.get(1).ok_or("missing zero-length syscall")?;
    assert_eq!(empty.return_value, Some(0));
    assert!(empty.bytes_complete);
    assert!(empty.bytes.is_empty());
    assert!(empty.data_source_range.is_some());
    Ok(())
}

#[test]
fn final_syscall_without_parsed_once() -> Result<(), Box<dyn Error>> {
    let trace = b"412 write(4, \"\\x41\", 1) = 1\n412 write(4, \"\\x42\\x43\", 2) = 1";
    let report = parse_strace(trace)?;
    assert_eq!(report.events.len(), 2);
    assert!(report.complete);
    let first = report.events.first().ok_or("missing first syscall")?;
    assert_eq!(first.bytes, b"A");
    let last = report.events.get(1).ok_or("missing final syscall")?;
    assert_eq!(last.bytes, b"B");
    assert_eq!(last.return_value, Some(1));
    assert_eq!(last.source_range.offset, first.source_range.length + 1);
    assert_eq!(
        last.source_range.offset + last.source_range.length,
        u64::try_from(trace.len())?
    );
    Ok(())
}

#[test]
fn failed_pointer_complete_empty_observation() -> Result<(), Box<dyn Error>> {
    let trace = b"412 recvfrom(3<UDP:[127.0.0.1:48193->127.0.0.1:48194]>, 0x7f001234, 100, 0, 0x7f005678, [16]) = -1 EAGAIN (Resource temporarily unavailable)\n";
    let report = parse_strace(trace)?;
    let event = report
        .events
        .first()
        .ok_or("failed receive event missing")?;

    assert_eq!(event.return_value, Some(-1));
    assert!(event.bytes_complete);
    assert!(event.bytes.is_empty());
    assert!(event.data_source_range.is_none());
    assert_eq!(event.source_range.offset, 0);
    let syscall_line = trace
        .strip_suffix(b"\n")
        .ok_or("trace line terminator missing")?;
    assert_eq!(
        event.source_range.length,
        u64::try_from(syscall_line.len())?
    );
    assert!(report.complete);
    assert_eq!(report.incomplete_events, 0);
    Ok(())
}

#[test]
fn positive_result_without_buffer_incomplete() -> Result<(), Box<dyn Error>> {
    let trace = b"412 read(4, 0x7f001234, 8) = 3\n";
    let report = parse_strace(trace)?;
    let event = report.events.first().ok_or("read event missing")?;

    assert_eq!(event.return_value, Some(3));
    assert!(!event.bytes_complete);
    assert!(event.bytes.is_empty());
    assert!(event.data_source_range.is_none());
    assert!(!report.complete);
    assert_eq!(report.incomplete_events, 1);
    Ok(())
}

#[test]
fn quoted_sockaddr_not_receive_buffer() -> Result<(), Box<dyn Error>> {
    let trace = b"412 recvfrom(3<UDP:[127.0.0.1:48193->127.0.0.1:48194]>, 0x7f001234, 100, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"192.0.2.1\")}, [16]) = 4\n";
    let report = parse_strace(trace)?;
    let event = report.events.first().ok_or("receive event missing")?;

    assert_eq!(event.return_value, Some(4));
    assert!(!event.bytes_complete);
    assert!(event.bytes.is_empty());
    assert!(event.data_source_range.is_none());
    assert!(!report.complete);
    Ok(())
}

#[test]
fn quoted_buffer_exact_source_range() -> Result<(), Box<dyn Error>> {
    let trace = b"412 write(4, \"left,right\", 10) = 10\n";
    let report = parse_strace(trace)?;
    let event = report.events.first().ok_or("write event missing")?;

    assert_eq!(event.bytes, b"left,right");
    assert!(event.bytes_complete);
    let range = event
        .data_source_range
        .as_ref()
        .ok_or("quoted buffer range missing")?;
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or("quoted buffer range overflows")?;
    let literal = trace
        .get(usize::try_from(range.offset)?..usize::try_from(end)?)
        .ok_or("quoted buffer range is outside the trace")?;
    assert_eq!(literal, b"\"left,right\"");
    Ok(())
}

#[test]
fn successful_quoted_pointer_call_retained() -> Result<(), Box<dyn Error>> {
    let trace = b"412 recvfrom(3, 0x7f001234, 100, 0, 0x7f005678, [16]) = -1 EAGAIN (Resource temporarily unavailable)\n412 read(4, \"\\x41\\x42\", 2) = 2\n";
    let report = parse_strace(trace)?;
    let failed = report
        .events
        .first()
        .ok_or("failed receive event missing")?;
    let successful = report
        .events
        .get(1)
        .ok_or("successful read event missing")?;

    assert_eq!(report.events.len(), 2);
    assert_eq!(failed.return_value, Some(-1));
    assert!(failed.bytes.is_empty());
    assert!(failed.bytes_complete);
    assert!(failed.data_source_range.is_none());
    assert_eq!(successful.bytes, b"AB");
    assert!(successful.bytes_complete);
    let source_range = successful
        .data_source_range
        .as_ref()
        .ok_or("quoted buffer range missing")?;
    assert_eq!(source_range.source, report.source_sha256);
    assert!(source_range.length > 0);
    assert!(report.complete);
    Ok(())
}

#[test]
fn owned_nonblocking_receive_later_bytes() -> Result<(), Box<dyn Error>> {
    let output = Command::new("strace")
        .args([
            "-qq",
            "-xx",
            "-s",
            "65535",
            "-yy",
            "-e",
            "trace=recvfrom,sendto",
            "--",
            "python3",
            "-c",
            NONBLOCKING_UDP_SCRIPT,
        ])
        .output()?;
    assert!(output.status.success());
    let report = parse_strace(&output.stderr)?;
    let failed = report
        .events
        .iter()
        .find(|event| event.return_value.is_some_and(|value| value < 0))
        .ok_or("nonblocking receive failure was not captured")?;
    assert_eq!(failed.syscall, "recvfrom");
    let successful = report
        .events
        .iter()
        .find(|event| {
            event.bytes == b"owned-udp-response"
                && event.direction == super::IoDirection::IntoProcess
        })
        .ok_or("successful response bytes were not captured")?;

    assert!(failed.bytes_complete);
    assert!(failed.bytes.is_empty());
    assert!(failed.data_source_range.is_none());
    assert!(successful.bytes_complete);
    assert_eq!(successful.direction, super::IoDirection::IntoProcess);
    assert!(report.complete);
    Ok(())
}

const NONBLOCKING_UDP_SCRIPT: &str = r#"
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 0))
server.settimeout(2)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", 0))
client.setblocking(False)
try:
    client.recvfrom(100)
except BlockingIOError:
    pass
client.settimeout(2)
client.sendto(b"owned-udp-request", server.getsockname())
server.recvfrom(100)
server.sendto(b"owned-udp-response", client.getsockname())
client.recvfrom(100)
"#;
