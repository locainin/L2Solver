use super::{LearnedHeader, PROBE_WORK_LIMIT, TestResult, options};

#[test]
fn gate_checkpoint_rejects_a_cached_plan_without_a_producer_rule() -> TestResult {
    let fixture = LearnedHeader::new()?;
    let limits = options(PROBE_WORK_LIMIT)
        .schema_limits
        .discovery
        .record_limits;

    assert!(
        fixture
            .cache
            .checkpoint_description(limits, 4 * 1024 * 1024)
            .is_err()
    );
    Ok(())
}
