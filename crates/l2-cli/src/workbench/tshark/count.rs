use super::{PROFILE, PacketCountReceipt, PreparedCapture, require_success, run_phase};
use l2_workbench::sha256;
use std::{error::Error, ffi::OsString};

pub(super) struct CaptureCount {
    pub(super) arguments: Vec<OsString>,
    pub(super) stderr: Vec<u8>,
    pub(super) receipt: PacketCountReceipt,
}

pub(super) fn capture(prepared: &PreparedCapture) -> Result<CaptureCount, Box<dyn Error>> {
    // Read every source frame without protocol dissection or a display filter
    let arguments = vec![
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
        OsString::from("--disable-all-protocols"),
        OsString::from("-r"),
        prepared.source.path.as_os_str().to_os_string(),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
    ];
    let output = run_phase(
        &prepared.executable,
        &arguments,
        &prepared.environment,
        prepared.deadline,
        prepared.metadata_maximum,
        prepared.diagnostic_maximum,
    )?;
    require_success("source packet count", output.status, &output.stderr)?;
    let receipt = PacketCountReceipt {
        count: parse(&output.stdout)?,
        output_sha256: sha256(&output.stdout),
    };
    Ok(CaptureCount {
        arguments,
        // The output hash and count retain the evidence without keeping another large buffer
        stderr: output.stderr,
        receipt,
    })
}

fn parse(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err("TShark source packet count output has a truncated final row".into());
    }
    let mut count = 0_u64;
    for line in std::str::from_utf8(bytes)?.lines() {
        let expected = count
            .checked_add(1)
            .ok_or("TShark source packet count exceeds the supported range")?;
        // Exact decimal rows exclude blanks, duplicate frames, extra columns, and overflow
        if !matches!(line.as_bytes().first(), Some(b'1'..=b'9'))
            || line.parse::<u64>().ok() != Some(expected)
        {
            return Err(
                "TShark source packet count output is not a complete frame sequence".into(),
            );
        }
        count = expected;
    }
    Ok(count)
}
