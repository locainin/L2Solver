#[path = "../src/survey_stats.rs"]
mod survey_stats;

#[test]
fn drop_counters_widened_sum() {
    assert_eq!(survey_stats::total_drops(3, 5), 8);
    assert_eq!(
        survey_stats::total_drops(u32::MAX, u32::MAX),
        u64::from(u32::MAX) * 2
    );
}
