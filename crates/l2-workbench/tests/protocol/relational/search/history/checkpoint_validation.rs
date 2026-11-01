use super::{RelationalReplayHistory, TestResult, checkpoint_history};
use serde_json::json;

#[test]
fn checkpoint_rejects_rejections_without_valid_replay_limits() -> TestResult<()> {
    let (history, _) = checkpoint_history()?;
    let original = serde_json::to_value(&history)?;
    let entries = original
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing entries")?;
    assert!(
        entries
            .iter()
            .any(|entry| entry.get(1).is_some_and(|value| value == "Rejected")),
        "fixture must include a saved rejection"
    );

    for limits in [json!(null), json!([0, 1024]), json!([32, 0])] {
        let mut changed = original.clone();
        *changed.get_mut("limits").ok_or("missing limits")? = limits.clone();
        assert!(
            serde_json::from_value::<RelationalReplayHistory>(changed).is_err(),
            "accepted a rejection with invalid limits {limits}"
        );
    }
    Ok(())
}

#[test]
fn checkpoint_accepts_published_rules_registered_before_a_search() -> TestResult<()> {
    let (_, published) = checkpoint_history()?;
    let mut history = RelationalReplayHistory::new(1024 * 1024);
    assert!(history.register_published_rule(&published));
    let encoded = serde_json::to_vec(&history)?;
    let restored: RelationalReplayHistory = serde_json::from_slice(&encoded)?;
    assert!(restored.is_complete());
    assert_eq!(restored.storage_bytes(), history.storage_bytes());
    Ok(())
}

#[test]
fn checkpoint_rejects_marker_allocation_that_does_not_match_the_saved_history() -> TestResult<()> {
    let (history, _) = checkpoint_history()?;
    let mut saved = serde_json::to_value(&history)?;
    let marker_bytes = saved
        .get_mut("marker_bytes")
        .ok_or("missing marker storage")?;
    let current = marker_bytes.as_u64().ok_or("invalid marker storage")?;
    *marker_bytes = serde_json::json!(current + 1);
    assert!(serde_json::from_value::<RelationalReplayHistory>(saved).is_err());
    Ok(())
}

#[test]
fn history_reader_accepts_prior_checkpoint_versions() -> TestResult<()> {
    let (history, _) = checkpoint_history()?;
    let current = serde_json::to_value(&history)?;
    for version in [1, 2] {
        let mut older = current.clone();
        let fields = older.as_object_mut().ok_or("invalid checkpoint")?;
        fields.remove("marker_bytes");
        if version == 1 {
            fields.remove("sorted_len");
        }
        fields.insert("version".to_owned(), serde_json::json!(version));
        let restored: RelationalReplayHistory = serde_json::from_value(older)?;
        assert_eq!(restored.storage_bytes(), history.storage_bytes());
        assert_eq!(restored.is_complete(), history.is_complete());
    }
    Ok(())
}
