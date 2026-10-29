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
