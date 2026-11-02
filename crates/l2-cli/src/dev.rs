//! Read-only developer diagnostics built on production parsers and limits

use crate::{bounded_json, input};
use l2_cli::arguments::{DevCommand, DevDecodeCommand};
use l2_io::{LinkIo, ReplayLink};
use std::{error::Error, io::Read, io::Write, path::Path};

const MAX_DEV_INPUT_BYTES: u64 = 1024 * 1024;

pub fn run(command: &DevCommand, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    // Developer commands reuse production parsers and never add transmit authority
    match command {
        DevCommand::Catalog => {
            serde_json::to_writer_pretty(&mut *output, l2_audit::catalog())?;
            writeln!(output)?;
        }
        DevCommand::Planner { report } => planner(report, output)?,
        DevCommand::Decode(command) => decode(command, output)?,
        DevCommand::PcapNgBlocks { capture } => capture_blocks(capture, output)?,
        DevCommand::PolicyDump { policy } => policy_dump(policy, output)?,
        DevCommand::CanaryInspect { capture } => canary(capture, output)?,
        DevCommand::HelperDecode { capture } => helper(capture, output)?,
        DevCommand::ReportRender { report } => report_json(report, output)?,
        #[cfg(feature = "dev-fixtures")]
        DevCommand::FixtureInspect { name } => fixture(name, output)?,
        DevCommand::Limits => limits(output)?,
    }
    Ok(())
}

fn planner(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let report: serde_json::Value = bounded_json::read(input::regular(path)?, MAX_DEV_INPUT_BYTES)?;
    let plan = report.get("plan").ok_or("report does not contain a plan")?;
    serde_json::to_writer_pretty(&mut *output, plan)?;
    writeln!(output)?;
    Ok(())
}

fn decode(command: &DevDecodeCommand, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    match command {
        DevDecodeCommand::Ethernet { hex } => {
            let bytes = decode_hex(hex)?;
            let frame = l2_core::decode(&bytes)?;
            writeln!(output, "{frame:#?}")?;
        }
        DevDecodeCommand::Radiotap { capture } => {
            let bytes = read_bounded(capture)?;
            let frame = wifi_radiotap::decode(&bytes)?;
            writeln!(output, "{frame:#?}")?;
        }
    }
    Ok(())
}

fn capture_blocks(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let mut link = ReplayLink::new(input::capture(path)?)?;
    let mut frames = 0_u64;
    while let Some(frame) = link.recv()? {
        frames = frames.checked_add(1).ok_or("frame count overflow")?;
        writeln!(
            output,
            "frame={frames} source={}:{} link={} captured={} original={}",
            frame.metadata().interface().section,
            frame.metadata().interface().index,
            frame.metadata().link_type().name(),
            frame.captured_len(),
            frame.metadata().original_len()
        )?;
    }
    writeln!(output, "frames={frames}")?;
    Ok(())
}

fn policy_dump(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let policy: l2_audit::Policy = bounded_json::read(input::regular(path)?, 65_536)?;
    policy.validate()?;
    serde_json::to_writer_pretty(&mut *output, &policy)?;
    writeln!(output)?;
    Ok(())
}

fn canary(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let bytes = read_bounded(path)?;
    // No key is accepted here, so decoded bytes cannot be presented as authenticated
    let status = match bytes.len() {
        l2_canary::WIRE_LEN => "fixed-size unverified canary",
        length if length < l2_canary::WIRE_LEN => "truncated unverified canary",
        _ => "unverified canary with trailing bytes",
    };
    writeln!(
        output,
        "status={status} bytes={} expected={} authentication=not-attempted",
        bytes.len(),
        l2_canary::WIRE_LEN
    )?;
    Ok(())
}

fn helper(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let bytes = read_bounded(path)?;
    let message = l2_helper_protocol::decode(&bytes)?;
    writeln!(output, "{message:#?}")?;
    Ok(())
}

fn report_json(path: &Path, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let report: serde_json::Value = bounded_json::read(input::regular(path)?, MAX_DEV_INPUT_BYTES)?;
    serde_json::to_writer_pretty(&mut *output, &report)?;
    writeln!(output)?;
    Ok(())
}

#[cfg(feature = "dev-fixtures")]
fn fixture(name: &str, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    // Generated fixtures avoid file reads and path traversal through fixture names
    let bytes: &[u8] = match name {
        "lldp" => crate::capture_fixtures::LLDP,
        "linux-stp" => crate::capture_fixtures::LINUX_STP,
        _ => return Err("unknown fixture; available fixtures: lldp, linux-stp".into()),
    };
    writeln!(
        output,
        "fixture={} bytes={}",
        name.escape_debug(),
        bytes.len()
    )?;
    Ok(())
}

fn limits(output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let default_capture = l2_pcap::CaptureLimits::default();
    let streaming_capture = l2_pcap::CaptureLimits::STREAMING;
    // Name both profiles so diagnostic values cannot be mistaken for every command's policy
    writeln!(
        output,
        "capture.default.max_input_bytes={}",
        default_capture.max_input_bytes()
    )?;
    writeln!(
        output,
        "capture.default.max_records={}",
        default_capture.max_records()
    )?;
    writeln!(
        output,
        "capture.streaming.max_input_bytes={}",
        streaming_capture.max_input_bytes()
    )?;
    writeln!(
        output,
        "capture.streaming.max_records={}",
        streaming_capture.max_records()
    )?;
    writeln!(
        output,
        "ethernet.max_frame_bytes={}",
        l2_core::MAX_FRAME_LEN
    )?;
    writeln!(output, "ethernet.max_vlan_tags={}", l2_core::MAX_VLAN_TAGS)?;
    writeln!(
        output,
        "helper.max_message_bytes={}",
        l2_helper_protocol::MAX_MESSAGE_LENGTH
    )?;
    writeln!(output, "canary.wire_bytes={}", l2_canary::WIRE_LEN)?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = input::regular(path)?;
    let capacity = usize::try_from(MAX_DEV_INPUT_BYTES)?;
    let mut bytes = Vec::with_capacity(capacity.min(8_192));
    // Read one extra byte so an exact-limit input remains distinguishable
    Read::by_ref(&mut file)
        .take(MAX_DEV_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > MAX_DEV_INPUT_BYTES {
        return Err("developer input exceeds 1 MiB".into());
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    // ASCII validation makes two-byte chunk boundaries unambiguous
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("hex input must contain an even number of ASCII hexadecimal digits");
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| {
            let high = hex_nibble(high)?;
            let low = hex_nibble(low)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex input contains an invalid digit"),
    }
}
