use l2_workbench::behavior::{EndpointEventKind, TimestampComparison, parse_endpoint_events};
use std::error::Error;

#[test]
fn endpoint_event_identity_ranges_origin() -> Result<(), Box<dyn Error>> {
    let bytes = br#"{
  "schema_version": 1,
  "clock": {"id":"host-clock","epoch":"1601-01-01T00:00:00Z","radix":10,"exponent":7,"offset_seconds":0},
  "\u0065vents": [
    {"id":"evt-1","kind":"file_creation_time_change","file":{"identity":"file-9","path":"sample.bin"},"process":{"identity":"proc-7","pid":7,"image":"worker.exe"},"source_event":{"provider":"generic","event_id":"file-time","record_id":"12"},"before_ticks":100,"after_ticks":200,"origin_claim":"claimed_validated_on_disk"}
  ]
}"#;
    let report = parse_endpoint_events(bytes)?;
    let event = report.events.first().ok_or("event missing")?;
    let raw = std::str::from_utf8(bytes)?;
    let marker = raw.find("\"id\":\"evt-1\"").ok_or("event start missing")?;
    let prefix = raw.get(..marker).ok_or("event prefix is invalid")?;
    let suffix = raw.get(marker..).ok_or("event suffix is invalid")?;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let line_end = suffix
        .find('\n')
        .map_or(raw.len(), |length| marker + length);
    let line = raw
        .get(line_start..line_end)
        .ok_or("event source line is invalid")?;
    let event_start = line_start + line.len() - line.trim_start().len();
    let event_length = line.trim().len();

    assert_eq!(report.source_length, u64::try_from(bytes.len())?);
    assert_eq!(report.source_sha256.len(), 64);
    assert_eq!(event.kind, EndpointEventKind::FileCreationTimeChange);
    assert_eq!(event.comparison, TimestampComparison::Increased);
    assert_eq!(event.origin_claim, "claimed_validated_on_disk");
    assert_eq!(event.validation, "not_validated_by_workbench");
    assert_eq!(event.source_range.offset, u64::try_from(event_start)?);
    assert_eq!(event.source_range.length, u64::try_from(event_length)?);
    let retained = raw
        .get(event_start..event_start + event_length)
        .ok_or("event source range is invalid")?;
    assert_eq!(retained, line.trim());
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("legitimate"))
    );
    let forged_validation = std::str::from_utf8(bytes)?.replace(
        "\"origin_claim\":\"claimed_validated_on_disk\"",
        "\"origin_claim\":\"claimed_validated_on_disk\",\"validation\":\"validated_on_disk\"",
    );
    assert!(parse_endpoint_events(forged_validation.as_bytes()).is_err());
    Ok(())
}

#[test]
fn endpoint_event_clocks_oversized_input() {
    let cases = [
        br#"{"schema_version":1,"clock":{},"events":[],"untrusted":true}"#.as_slice(),
        br#"{"schema_version":2,"clock":{"id":"x","epoch":"y","radix":10,"exponent":7,"offset_seconds":0},"events":[]}"#.as_slice(),
        br#"{"schema_version":1,"clock":{"id":"x","epoch":"y","radix":3,"exponent":7,"offset_seconds":0},"events":[]}"#.as_slice(),
    ];
    for bytes in cases {
        assert!(parse_endpoint_events(bytes).is_err());
    }

    let oversized = vec![b' '; l2_workbench::behavior::MAX_ENDPOINT_EVENT_BYTES + 1];
    assert!(parse_endpoint_events(&oversized).is_err());
}

#[test]
fn endpoint_event_provider_identities() {
    let event = r#"{"id":"evt-a","kind":"file_creation_time_change","file":{"identity":"file-a","path":"sample.bin"},"process":{"identity":"proc-a","pid":7,"image":"worker.exe"},"source_event":{"provider":"generic","event_id":"file-time","record_id":"12"},"before_ticks":1,"after_ticks":2,"origin_claim":"reported"}"#;
    let duplicate_id = format!(
        r#"{{"schema_version":1,"clock":{{"id":"clock","epoch":"epoch","radix":10,"exponent":7,"offset_seconds":0}},"events":[{event},{event}]}}"#
    );
    assert!(parse_endpoint_events(duplicate_id.as_bytes()).is_err());

    let collision = format!(
        r#"{{"schema_version":1,"clock":{{"id":"clock","epoch":"epoch","radix":10,"exponent":7,"offset_seconds":0}},"events":[{event},{{"id":"evt-b","kind":"file_creation_time_change","file":{{"identity":"file-b","path":"other.bin"}},"process":{{"identity":"proc-b","pid":8,"image":"other.exe"}},"source_event":{{"provider":"generic","event_id":"file-time","record_id":"12"}},"before_ticks":2,"after_ticks":3,"origin_claim":"reported"}}]}}"#
    );
    assert!(parse_endpoint_events(collision.as_bytes()).is_err());
}

#[test]
fn endpoint_event_capacity() {
    fn document(event_count: usize) -> String {
        let events = (0..event_count)
            .map(|index| {
                format!(
                    r#"{{"id":"evt-{index}","kind":"file_creation_time_change","file":{{"identity":"file","path":"sample.bin"}},"process":{{"identity":"proc","pid":7,"image":"worker.exe"}},"source_event":{{"provider":"generic","event_id":"file-time","record_id":"{index}"}},"before_ticks":1,"after_ticks":2,"origin_claim":"reported"}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"schema_version":1,"clock":{{"id":"clock","epoch":"epoch","radix":10,"exponent":7,"offset_seconds":0}},"events":[{events}]}}"#
        )
    }

    let at_limit = document(l2_workbench::behavior::MAX_ENDPOINT_EVENTS);
    let over_limit = document(l2_workbench::behavior::MAX_ENDPOINT_EVENTS + 1);

    assert!(parse_endpoint_events(at_limit.as_bytes()).is_ok());
    assert!(parse_endpoint_events(over_limit.as_bytes()).is_err());
}
