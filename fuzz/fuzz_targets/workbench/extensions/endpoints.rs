use l2_workbench::{behavior, sha256};

pub(super) fn exercise(input: &[u8]) {
    let Ok(report) = behavior::parse_endpoint_events(input) else {
        return;
    };
    assert_eq!(report.source_sha256, sha256(input));
    for event in report.events {
        assert_eq!(event.validation, "not_validated_by_workbench");
        let offset = usize::try_from(event.source_range.offset)
            .unwrap_or_else(|_| panic!("event offset is not representable"));
        let length = usize::try_from(event.source_range.length)
            .unwrap_or_else(|_| panic!("event length is not representable"));
        let bytes = input
            .get(offset..offset + length)
            .unwrap_or_else(|| panic!("event range exceeds its source"));
        let raw: serde_json::Value = serde_json::from_slice(bytes)
            .unwrap_or_else(|_| panic!("event range is not a JSON object"));
        assert_eq!(
            raw.get("before_ticks").and_then(serde_json::Value::as_u64),
            Some(event.before_ticks)
        );
        assert_eq!(
            raw.get("after_ticks").and_then(serde_json::Value::as_u64),
            Some(event.after_ticks)
        );
    }
}
