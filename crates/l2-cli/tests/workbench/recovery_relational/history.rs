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
