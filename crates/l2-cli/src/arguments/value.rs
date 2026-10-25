use super::model::{ColorChoice, LiveLimit, OutputFormat, SourceMapping};
use l2_audit::AssessmentProfile;
use std::time::Duration;

const MAX_LIVE_PACKETS: u32 = 10_000;
const MAX_LIVE_DURATION_SECONDS: u64 = 5 * 60;
const INVALID_XOR_HEX: &str = "XOR key must contain only ASCII hexadecimal digits";

const BYTE_UNITS: &[(&str, u64)] = &[
    ("", 1),
    ("tib", 1_099_511_627_776),
    ("gib", 1_073_741_824),
    ("mib", 1_048_576),
    ("kib", 1_024),
    ("tb", 1_000_000_000_000),
    ("gb", 1_000_000_000),
    ("mb", 1_000_000),
    ("kb", 1_000),
    ("b", 1),
];

pub(super) fn nonzero_jobs(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| String::from("worker count must be a positive integer"))
}

/// Parse a byte count with optional decimal or binary units
///
/// # Errors
/// Returns an error when the count, unit, or multiplication overflows `u64`
pub fn parse_byte_size(value: &str) -> Result<u64, String> {
    let split = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    if digits.is_empty() {
        return Err(String::from("byte size must start with an integer"));
    }

    let count = digits
        .parse::<u64>()
        .map_err(|_| String::from("byte size is too large"))?;
    let unit = unit.to_ascii_lowercase();
    let multiplier = BYTE_UNITS
        .iter()
        .find_map(|(suffix, multiplier)| (*suffix == unit).then_some(*multiplier))
        .ok_or_else(|| String::from("byte size unit must be B, KB/MB/GB/TB, or KiB/MiB/GiB/TiB"))?;
    count
        .checked_mul(multiplier)
        .ok_or_else(|| String::from("byte size is too large"))
}

pub(super) fn output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "html" => Ok(OutputFormat::Html),
        _ => Err(String::from("format must be text, json, or html")),
    }
}

pub(super) fn compare_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(String::from("format must be text or json")),
    }
}

pub(super) fn capture_packet_index(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|index| (1..=l2_pcap::MAX_RECORD_COUNT).contains(index))
        .ok_or_else(|| {
            format!(
                "packet index must be from 1 to {}",
                l2_pcap::MAX_RECORD_COUNT
            )
        })
}

pub(super) fn byte_offset(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|offset| *offset <= crate::byte_compare::MAX_BYTE_OFFSET)
        .ok_or_else(|| String::from("byte offset must be from 0 to 65535"))
}

pub(super) fn byte_length(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|length| (1..=crate::byte_compare::MAX_SELECTED_BYTES).contains(length))
        .ok_or_else(|| String::from("byte length must be from 1 to 65535"))
}

pub(super) fn xor_key(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(String::from(
            "XOR key must be nonempty even-length hexadecimal",
        ));
    }
    if bytes.len() > crate::byte_compare::MAX_XOR_KEY_BYTES * 2 {
        return Err(String::from("XOR key must contain at most 256 bytes"));
    }
    let mut key = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let [high, low] = pair else {
            return Err(String::from(INVALID_XOR_HEX));
        };
        let high = hex_nibble(*high).ok_or_else(|| String::from(INVALID_XOR_HEX))?;
        let low = hex_nibble(*low).ok_or_else(|| String::from(INVALID_XOR_HEX))?;
        key.push((high << 4) | low);
    }
    Ok(key)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(super) fn color(value: &str) -> Result<ColorChoice, String> {
    match value {
        "auto" => Ok(ColorChoice::Auto),
        "always" => Ok(ColorChoice::Always),
        "never" => Ok(ColorChoice::Never),
        _ => Err(String::from("color must be auto, always, or never")),
    }
}

pub(super) fn profile(value: &str) -> Result<AssessmentProfile, String> {
    match value {
        "opportunistic" => Ok(AssessmentProfile::Opportunistic),
        "standard" => Ok(AssessmentProfile::Standard),
        "full" => Ok(AssessmentProfile::Full),
        _ => Err(String::from(
            "profile must be opportunistic, standard, or full",
        )),
    }
}

pub(super) fn packets(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|count| (1..=MAX_LIVE_PACKETS).contains(count))
        .ok_or_else(|| String::from("packet count must be from 1 to 10000"))
}

pub(super) fn duration(value: &str) -> Result<Duration, String> {
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_u64)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60_u64)
    } else {
        return Err(String::from("capture duration must use s or m"));
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(String::from("capture duration must be from 1s to 5m"));
    }
    let seconds = digits
        .parse::<u64>()
        .ok()
        .filter(|amount| *amount > 0)
        .and_then(|amount| amount.checked_mul(multiplier))
        .filter(|seconds| *seconds <= MAX_LIVE_DURATION_SECONDS)
        .ok_or_else(|| String::from("capture duration must be from 1s to 5m"))?;
    Ok(Duration::from_secs(seconds))
}

pub(super) fn source_mapping(value: &str) -> Result<SourceMapping, String> {
    let (capture_source, label) = value
        .split_once('=')
        .ok_or_else(|| String::from("source mapping must use SECTION:INDEX=LABEL"))?;
    let (section, index) = capture_source
        .split_once(':')
        .ok_or_else(|| String::from("source mapping must use SECTION:INDEX=LABEL"))?;
    if !super::model::valid_source_label(label) {
        return Err(String::from(
            "source label must use 1 to 64 ASCII letters, digits, '.', '_', ':', '/', or '-'",
        ));
    }
    Ok(SourceMapping {
        section: section
            .parse()
            .map_err(|_| String::from("source section must be a u32"))?,
        index: index
            .parse()
            .map_err(|_| String::from("source index must be a u32"))?,
        label: label.to_owned(),
    })
}

pub(super) fn source_label(value: &str) -> Result<String, String> {
    if !super::model::valid_source_label(value) {
        return Err(String::from(
            "source label must use 1 to 64 ASCII letters, digits, '.', '_', ':', '/', or '-'",
        ));
    }
    Ok(value.to_owned())
}

pub(super) const fn limit(
    duration: Option<Duration>,
    packets: Option<u32>,
) -> Result<LiveLimit, &'static str> {
    match (duration, packets) {
        (Some(duration), None) => Ok(LiveLimit::Duration(duration)),
        (None, Some(packets)) => Ok(LiveLimit::Packets(packets)),
        (None, None) => Err("live capture requires --duration or --packets"),
        (Some(_), Some(_)) => Err("--duration and --packets are mutually exclusive"),
    }
}
