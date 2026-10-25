use crate::{evidence::SourceRange, sha256};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::HashSet, error::Error, fmt, ops::Range};

/// Maximum normalized endpoint-event document size
pub const MAX_ENDPOINT_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum normalized endpoint events in one document
pub const MAX_ENDPOINT_EVENTS: usize = 256;
const MAX_TEXT_BYTES: usize = 256;
const VALIDATION_STATE: &str = "not_validated_by_workbench";

/// Endpoint event clock definition supplied by the source adapter
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EndpointClock {
    /// Source-provided clock identifier
    pub id: String,
    /// Source-provided epoch label; no conversion is inferred
    pub epoch: String,
    /// Tick radix, either 2 or 10
    pub radix: u8,
    /// Tick resolution exponent
    pub exponent: u8,
    /// Exact caller-provided UTC offset in seconds
    pub offset_seconds: i64,
}

/// Supported file-time events in the normalized import schema
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEventKind {
    /// A reported file creation-time change
    FileCreationTimeChange,
    /// A reported file modification-time change
    FileModifiedTimeChange,
    /// A reported change to one or more file timestamps
    FileTimestampChange,
}

/// Exact comparison of two unsigned ticks in one supplied clock
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampComparison {
    /// Before and after ticks are equal
    Equal,
    /// After ticks are larger
    Increased,
    /// After ticks are smaller
    Decreased,
}

/// One imported file-time event with its exact JSON source range
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EndpointEvent {
    /// Source-provided event identifier
    pub id: String,
    /// Normalized event class
    pub kind: EndpointEventKind,
    /// Exact reported file identity and path label
    pub file: FileIdentity,
    /// Exact reported process identity and image label
    pub process: ProcessIdentity,
    /// Source event correlation fields
    pub source_event: SourceEventReference,
    /// Before and after values in the supplied clock's raw tick units
    pub before_ticks: u64,
    /// After value in raw source tick units
    pub after_ticks: u64,
    /// Exact integer comparison without wall-clock conversion
    pub comparison: TimestampComparison,
    /// Caller-provided provenance claim, retained without elevation
    pub origin_claim: String,
    /// Fixed tool state; caller JSON cannot change this field
    pub validation: &'static str,
    /// Absolute range of this object in the exact imported JSON bytes
    pub source_range: SourceRange,
}

/// File identity carried by one normalized endpoint event
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Provider-supplied stable identity
    pub identity: String,
    /// Provider-supplied path label
    pub path: String,
}

/// Process identity carried by one normalized endpoint event
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Provider-supplied stable identity
    pub identity: String,
    /// Provider-supplied process id
    pub pid: u32,
    /// Provider-supplied image label
    pub image: String,
}

/// Provider and event references supplied with one normalized event
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEventReference {
    /// Provider name or adapter identifier
    pub provider: String,
    /// Provider event name or numeric identifier
    pub event_id: String,
    /// Provider record identifier
    pub record_id: String,
}

/// Bounded import result with full source hash and exact event ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EndpointEventReport {
    /// SHA-256 identity of all exact imported JSON bytes
    pub source_sha256: String,
    /// Exact imported source byte length
    pub source_length: u64,
    /// Clock facts shared by all events in this document
    pub clock: EndpointClock,
    /// Parsed events in source order
    pub events: Vec<EndpointEvent>,
    /// Limits on validating and interpreting imported values
    pub limitations: Vec<String>,
}

/// Failure to parse or validate a bounded normalized endpoint document
#[derive(Debug)]
pub struct EndpointEventError(String);

impl fmt::Display for EndpointEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EndpointEventError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    schema_version: u32,
    clock: ClockWire,
    events: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockWire {
    id: String,
    epoch: String,
    radix: u8,
    exponent: u8,
    offset_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    id: String,
    kind: String,
    file: FileIdentity,
    process: ProcessIdentity,
    source_event: SourceEventReference,
    before_ticks: u64,
    after_ticks: u64,
    origin_claim: String,
}

/// Parse a bounded, source-ranged endpoint event document
///
/// Caller-provided validation claims remain origin text; output validation is
/// always `not_validated_by_workbench`
///
/// # Errors
/// Rejects oversized documents, unknown fields, invalid clocks, or malformed events
pub fn parse_endpoint_events(bytes: &[u8]) -> Result<EndpointEventReport, EndpointEventError> {
    if bytes.len() > MAX_ENDPOINT_EVENT_BYTES {
        return Err(event_error(
            "endpoint event document exceeds its byte limit",
        ));
    }
    let wire: DocumentWire = serde_json::from_slice(bytes).map_err(|error| json_error(&error))?;
    if wire.schema_version != 1 {
        return Err(event_error("unsupported endpoint event schema version"));
    }
    let clock = validate_clock(wire.clock)?;
    let array_range = top_level_value_range(bytes, "events")?;
    let array_bytes = bytes
        .get(array_range.clone())
        .ok_or_else(|| event_error("endpoint event array range is invalid"))?;
    if array_bytes != wire.events.get().as_bytes() {
        return Err(event_error(
            "endpoint event array source range does not match parsed JSON",
        ));
    }
    let mut array_deserializer = serde_json::Deserializer::from_slice(array_bytes);
    let raw_events =
        deserialize_raw_events(&mut array_deserializer).map_err(|error| json_error(&error))?;
    array_deserializer
        .end()
        .map_err(|error| json_error(&error))?;
    let source_sha256 = sha256(bytes);
    let mut cursor = 0_usize;
    let mut event_ids = HashSet::new();
    let mut source_event_ids = HashSet::new();
    let mut events = Vec::with_capacity(raw_events.len());
    for raw in raw_events {
        let raw_bytes = raw.get().as_bytes();
        let relative_offset = find_event_range(array_bytes, raw_bytes, cursor)?;
        cursor = relative_offset
            .checked_add(raw_bytes.len())
            .ok_or_else(|| event_error("endpoint event array offset overflow"))?;
        let offset = array_range
            .start
            .checked_add(relative_offset)
            .ok_or_else(|| event_error("endpoint event source offset overflow"))?;
        let event: EventWire =
            serde_json::from_str(raw.get()).map_err(|error| json_error(&error))?;
        let event = validate_event(
            event,
            &format!("sha256:{source_sha256}"),
            u64::try_from(offset).map_err(|_| event_error("event offset exceeds u64"))?,
            u64::try_from(raw_bytes.len()).map_err(|_| event_error("event length exceeds u64"))?,
        )?;
        if !event_ids.insert(event.id.clone()) {
            return Err(event_error("endpoint event identifier is duplicated"));
        }
        let reference = (
            event.source_event.provider.clone(),
            event.source_event.event_id.clone(),
            event.source_event.record_id.clone(),
        );
        if !source_event_ids.insert(reference) {
            return Err(event_error(
                "endpoint provider record reference is duplicated",
            ));
        }
        events.push(event);
    }
    Ok(EndpointEventReport {
        source_sha256,
        source_length: u64::try_from(bytes.len())
            .map_err(|_| event_error("endpoint source length exceeds u64"))?,
        clock,
        events,
        limitations: vec![
            "Imported endpoint values remain caller-reported; source providers and historical file state are not validated by this parser".to_owned(),
            "legitimate file-time updates remain an alternative explanation".to_owned(),
        ],
    })
}

fn validate_clock(wire: ClockWire) -> Result<EndpointClock, EndpointEventError> {
    validate_named_text(&wire.id, "clock id")?;
    validate_named_text(&wire.epoch, "clock epoch")?;
    if !matches!(wire.radix, 2 | 10) || wire.exponent > 127 {
        return Err(event_error(
            "endpoint clock radix or exponent is unsupported",
        ));
    }
    Ok(EndpointClock {
        id: wire.id,
        epoch: wire.epoch,
        radix: wire.radix,
        exponent: wire.exponent,
        offset_seconds: wire.offset_seconds,
    })
}

fn validate_event(
    wire: EventWire,
    source: &str,
    offset: u64,
    length: u64,
) -> Result<EndpointEvent, EndpointEventError> {
    for (text, field) in [
        (&wire.id, "event id"),
        (&wire.file.identity, "file identity"),
        (&wire.file.path, "file path"),
        (&wire.process.identity, "process identity"),
        (&wire.process.image, "process image"),
        (&wire.source_event.provider, "event provider"),
        (&wire.source_event.event_id, "source event id"),
        (&wire.source_event.record_id, "source record id"),
        (&wire.origin_claim, "origin claim"),
    ] {
        validate_named_text(text, field)?;
    }
    let kind = match wire.kind.as_str() {
        "file_creation_time_change" => EndpointEventKind::FileCreationTimeChange,
        "file_modified_time_change" => EndpointEventKind::FileModifiedTimeChange,
        "file_timestamp_change" => EndpointEventKind::FileTimestampChange,
        _ => return Err(event_error("endpoint event kind is unsupported")),
    };
    let comparison = compare_ticks(wire.before_ticks, wire.after_ticks);
    Ok(EndpointEvent {
        id: wire.id,
        kind,
        file: wire.file,
        process: wire.process,
        source_event: wire.source_event,
        before_ticks: wire.before_ticks,
        after_ticks: wire.after_ticks,
        comparison,
        origin_claim: wire.origin_claim,
        validation: VALIDATION_STATE,
        source_range: SourceRange {
            source: source.to_owned(),
            packet: None,
            offset,
            length,
        },
    })
}

fn compare_ticks(before: u64, after: u64) -> TimestampComparison {
    match after.cmp(&before) {
        std::cmp::Ordering::Less => TimestampComparison::Decreased,
        std::cmp::Ordering::Equal => TimestampComparison::Equal,
        std::cmp::Ordering::Greater => TimestampComparison::Increased,
    }
}

fn find_event_range(
    source: &[u8],
    event: &[u8],
    cursor: usize,
) -> Result<usize, EndpointEventError> {
    source
        .get(cursor..)
        .and_then(|remaining| {
            remaining
                .windows(event.len())
                .position(|window| window == event)
        })
        .and_then(|relative| cursor.checked_add(relative))
        .ok_or_else(|| event_error("endpoint event source range could not be resolved"))
}

fn top_level_value_range(
    source: &[u8],
    wanted_key: &str,
) -> Result<Range<usize>, EndpointEventError> {
    let mut cursor = skip_json_whitespace(source, 0);
    if source.get(cursor) != Some(&b'{') {
        return Err(event_error("endpoint document root is not an object"));
    }
    cursor = cursor
        .checked_add(1)
        .ok_or_else(|| event_error("endpoint object offset overflow"))?;
    loop {
        cursor = skip_json_whitespace(source, cursor);
        if source.get(cursor) == Some(&b'}') {
            return Err(event_error("endpoint event array is missing"));
        }
        let key_end = scan_json_string(source, cursor)?;
        let key: String = serde_json::from_slice(
            source
                .get(cursor..key_end)
                .ok_or_else(|| event_error("endpoint object key range is invalid"))?,
        )
        .map_err(|error| json_error(&error))?;
        cursor = skip_json_whitespace(source, key_end);
        if source.get(cursor) != Some(&b':') {
            return Err(event_error("endpoint object field separator is invalid"));
        }
        cursor = skip_json_whitespace(
            source,
            cursor
                .checked_add(1)
                .ok_or_else(|| event_error("endpoint field offset overflow"))?,
        );
        let value_end = scan_json_value(source, cursor)?;
        if key == wanted_key {
            return Ok(cursor..value_end);
        }
        cursor = skip_json_whitespace(source, value_end);
        match source.get(cursor) {
            Some(b',') => {
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| event_error("endpoint field offset overflow"))?;
            }
            Some(b'}') => return Err(event_error("endpoint event array is missing")),
            _ => return Err(event_error("endpoint object delimiter is invalid")),
        }
    }
}

fn scan_json_value(source: &[u8], start: usize) -> Result<usize, EndpointEventError> {
    match source.get(start) {
        Some(b'"') => scan_json_string(source, start),
        Some(b'{' | b'[') => scan_json_container(source, start),
        Some(_) => {
            let mut cursor = start;
            while source.get(cursor).is_some_and(|byte| {
                !matches!(byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t')
            }) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| event_error("endpoint value offset overflow"))?;
            }
            if cursor == start {
                Err(event_error("endpoint field value is missing"))
            } else {
                Ok(cursor)
            }
        }
        None => Err(event_error("endpoint field value is missing")),
    }
}

fn scan_json_container(source: &[u8], start: usize) -> Result<usize, EndpointEventError> {
    let mut cursor = start;
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&byte) = source.get(cursor) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => depth = depth.saturating_add(1),
                b'}' | b']' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| event_error("endpoint container nesting is invalid"))?;
                    if depth == 0 {
                        return cursor
                            .checked_add(1)
                            .ok_or_else(|| event_error("endpoint value offset overflow"));
                    }
                }
                _ => {}
            }
        }
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| event_error("endpoint value offset overflow"))?;
    }
    Err(event_error("endpoint container is not terminated"))
}

fn scan_json_string(source: &[u8], start: usize) -> Result<usize, EndpointEventError> {
    if source.get(start) != Some(&b'"') {
        return Err(event_error("endpoint object key is not a string"));
    }
    let mut cursor = start
        .checked_add(1)
        .ok_or_else(|| event_error("endpoint string offset overflow"))?;
    let mut escaped = false;
    while let Some(&byte) = source.get(cursor) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return cursor
                .checked_add(1)
                .ok_or_else(|| event_error("endpoint string offset overflow"));
        }
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| event_error("endpoint string offset overflow"))?;
    }
    Err(event_error("endpoint string is not terminated"))
}

fn skip_json_whitespace(source: &[u8], mut cursor: usize) -> usize {
    while source
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        cursor = cursor.saturating_add(1);
    }
    cursor
}

fn validate_named_text(text: &str, field: &str) -> Result<(), EndpointEventError> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(event_error(&format!(
            "endpoint {field} is empty, oversized, or has controls"
        )));
    }
    Ok(())
}

fn deserialize_raw_events<'de, D>(deserializer: D) -> Result<Vec<Box<RawValue>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RawEventsVisitor;
    impl<'de> Visitor<'de> for RawEventsVisitor {
        type Value = Vec<Box<RawValue>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded list of endpoint event objects")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut events = Vec::with_capacity(MAX_ENDPOINT_EVENTS);
            while let Some(event) = sequence.next_element()? {
                if events.len() == MAX_ENDPOINT_EVENTS {
                    return Err(de::Error::custom("endpoint event count exceeds its limit"));
                }
                events.push(event);
            }
            Ok(events)
        }
    }
    deserializer.deserialize_seq(RawEventsVisitor)
}

fn json_error(error: &serde_json::Error) -> EndpointEventError {
    event_error(&format!("invalid endpoint event JSON: {error}"))
}

fn event_error(message: &str) -> EndpointEventError {
    EndpointEventError(message.to_owned())
}
