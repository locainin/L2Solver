use super::super::{RelationalCohortKey, RelationalDiscoveryContext, RelationalLane, StoredSample};
use super::RelationalReplayHistories;
use l2_workbench::protocol::{Direction, MessageContext, RelationalOperationTemplate};

#[test]
fn cohort_histories_share_one_bounded_budget_without_fixed_empty_reservations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut histories = RelationalReplayHistories::default();
    let maximum_bytes = 16 * 1024;
    let first = context("first", 1);
    let second = context("second", 2);
    let mut rule = super::super::search_budget_tests::expected_session_relative_rule();

    let first_history = histories
        .for_context(&first, 128, maximum_bytes)
        .ok_or("one small cohort should use available shared history memory")?;
    for counter in 0..20 {
        let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = rule.operation;
        operation.initial_counter = counter;
        assert!(first_history.register_published_rule(&rule));
    }
    assert!(first_history.storage_bytes() > maximum_bytes / 128);

    let second_history = histories
        .for_context(&second, 128, maximum_bytes)
        .ok_or("another small cohort should use the remaining shared memory")?;
    for counter in 20..30 {
        let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = rule.operation;
        operation.initial_counter = counter;
        assert!(second_history.register_published_rule(&rule));
    }
    assert!(
        histories
            .retained_bytes()
            .is_some_and(|bytes| bytes <= maximum_bytes)
    );
    let mut first_incremental = first;
    first_incremental.lane = RelationalLane::Incremental;
    assert!(
        histories
            .for_context(&first_incremental, 128, maximum_bytes)
            .is_some()
    );
    Ok(())
}

#[test]
fn restored_lane_history_preserves_the_in_progress_lookup_and_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let maximum_bytes = 16 * 1024;
    let normal = context("resume", 1);
    let mut histories = RelationalReplayHistories::default();
    let history = histories
        .for_context(&normal, 128, maximum_bytes)
        .ok_or("missing normal history")?;
    assert!(history.register_published_rule(
        &super::super::search_budget_tests::expected_session_relative_rule()
    ));
    // Restored strings need not keep the original allocator capacity
    histories
        .slots
        .first_mut()
        .ok_or("missing history slot")?
        .key
        .source_id
        .reserve(512);

    for lane in [RelationalLane::Normal, RelationalLane::Incremental] {
        let mut context = normal.clone();
        context.lane = lane;
        let expected = serde_json::to_value(histories.published_history(&context, maximum_bytes))?;
        let bytes = serde_json::to_vec(&histories)?;
        let mut restored: RelationalReplayHistories = serde_json::from_slice(&bytes)?;
        let retained = restored.retained_bytes();
        let saved_limit = restored
            .slots
            .first()
            .map(|slot| slot.history.maximum_bytes());
        let resumed = restored
            .resume_context(&context, maximum_bytes)
            .ok_or_else(|| {
                format!(
                    "saved cohort history was not restored: retained={retained:?}, \
                     saved_limit={saved_limit:?}, shared_limit={maximum_bytes}"
                )
            })?;
        assert_eq!(serde_json::to_value(resumed)?, expected);
        assert!(restored.resume_context(&context, 1).is_none());

        context
            .samples
            .first_mut()
            .ok_or("missing cohort sample")?
            .session_order += 1;
        assert!(restored.resume_context(&context, maximum_bytes).is_none());
    }
    Ok(())
}

#[test]
fn detached_history_restores_its_identity_and_original_storage_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let maximum_bytes = 16 * 1024;
    let context = context("detached", 1);
    let mut histories = RelationalReplayHistories::default();
    let mut active = histories
        .take_for_context(&context, 128, maximum_bytes)
        .ok_or("missing active history")?;
    assert!(active.register_published_rule(
        &super::super::search_budget_tests::expected_session_relative_rule()
    ));
    let expected = serde_json::to_value(&active)?;
    let ceiling = active.maximum_bytes();
    let saved_slots = serde_json::to_vec(&histories)?;
    let saved_history = serde_json::to_vec(&active)?;
    let mut restored: RelationalReplayHistories = serde_json::from_slice(&saved_slots)?;
    let saved = serde_json::from_slice(&saved_history)?;
    let active = restored.take_restored_context(&context, maximum_bytes, saved)?;
    assert_eq!(active.maximum_bytes(), ceiling);
    assert_eq!(serde_json::to_value(&active)?, expected);
    restored.return_context(&context, active)?;
    let returned = restored
        .resume_context(&context, maximum_bytes)
        .ok_or("history was not returned")?;
    assert_eq!(serde_json::to_value(returned)?, expected);

    let mut changed = context.clone();
    changed
        .samples
        .first_mut()
        .ok_or("missing history sample")?
        .session_order += 1;
    let mut restored: RelationalReplayHistories = serde_json::from_slice(&saved_slots)?;
    let saved = serde_json::from_slice(&saved_history)?;
    assert!(
        restored
            .take_restored_context(&changed, maximum_bytes, saved)
            .is_err()
    );
    let mut restored: RelationalReplayHistories = serde_json::from_slice(&saved_slots)?;
    let saved = serde_json::from_slice(&saved_history)?;
    assert!(restored.take_restored_context(&context, 1, saved).is_err());
    Ok(())
}

fn context(source: &str, node_id: u64) -> RelationalDiscoveryContext {
    let key = RelationalCohortKey {
        source_id: source.to_owned(),
        scope_json: "scope".to_owned(),
        endpoints_json: "{}".to_owned(),
        direction: Direction::FirstToSecond,
        framing_rule_json: "framed".to_owned(),
        schema_json: "{}".to_owned(),
    };
    RelationalDiscoveryContext {
        lane: RelationalLane::Normal,
        key,
        sample_node_ids: vec![node_id],
        samples: vec![StoredSample {
            node_id,
            context: MessageContext {
                source: source.to_owned(),
                scope: "scope".to_owned(),
                session: node_id,
                direction: Direction::FirstToSecond,
            },
            session_order: node_id,
            direction_node_id: node_id,
            episode_node_id: node_id,
            stream_offset: 0,
        }],
        sessions_available: 1,
        omitted_sessions: 0,
        omitted_samples: 0,
        source_eligibility_omissions: 0,
        input_coverage_complete: true,
    }
}
