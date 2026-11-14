mod budget;
mod value;

pub(super) use self::budget::DecodeError;
use self::{budget::DecodeBudget, value::PacketSeed};
use super::{
    model::EnrichedPacket,
    phase::{require_success, run_phase},
    preparation::PreparedCapture,
    process,
    profile::PROFILE,
};
use l2_workbench::sha256;
use serde::de::DeserializeSeed;
use std::{error::Error, ffi::OsString};

pub(super) struct CaptureDecode {
    pub(super) arguments: Vec<OsString>,
    pub(super) stderr: Vec<u8>,
    pub(super) output_sha256: String,
    pub(super) packets: Vec<EnrichedPacket>,
}

pub(super) fn decode_capture(prepared: &PreparedCapture) -> Result<CaptureDecode, Box<dyn Error>> {
    let mut arguments = vec![
        OsString::from("-n"),
        OsString::from("-2"),
        OsString::from("-q"),
        OsString::from("-C"),
        OsString::from(PROFILE),
    ];
    if let Some(keylog) = &prepared.keylog {
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(format!(
            "tls.keylog_file:{}",
            keylog.path.display()
        )));
    }
    arguments.extend([
        OsString::from("-r"),
        prepared.source.path.as_os_str().to_os_string(),
        OsString::from("-T"),
        OsString::from("json"),
        // Preserve repeated protocol trees and field values as arrays
        OsString::from("--no-duplicate-keys"),
    ]);
    let process::Output {
        stdout,
        stderr,
        status,
    } = run_phase(prepared, &arguments, prepared.output_maximum)?;
    require_success("offline decode", status, &stderr)?;
    // Hash the original bytes before releasing them after decoding
    let output_sha256 = sha256(&stdout);
    let packets = decode_packets(&stdout, stdout.capacity(), prepared.output_maximum)?;
    drop(stdout);
    Ok(CaptureDecode {
        arguments,
        stderr,
        output_sha256,
        packets,
    })
}

/// Parse each packet once while accounting for the raw and retained JSON data
pub(super) fn decode_packets(
    bytes: &[u8],
    raw_capacity: usize,
    maximum: usize,
) -> Result<Vec<EnrichedPacket>, DecodeError> {
    let mut budget = DecodeBudget::new(maximum, raw_capacity, bytes)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = PacketSeed(&mut budget).deserialize(&mut deserializer);
    let packets = match result {
        Ok(packets) => packets,
        Err(error) => return Err(budget.take_failure().unwrap_or(DecodeError::Json(error))),
    };
    deserializer.end().map_err(DecodeError::Json)?;
    Ok(packets)
}
