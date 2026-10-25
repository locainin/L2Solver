use super::{discovered_record_task_allowed, record_children};
use l2_workbench::evidence::Case;
use l2_workbench::recovery::RecoveryTask;
use serde_json::json;
use std::error::Error;

#[test]
fn record_children_filter_many_groups_and_preserve_input_order() -> Result<(), Box<dyn Error>> {
    const GROUP_COUNT: usize = 4_096;

    let mut case = Case::new();
    let mut group_node_ids = Vec::with_capacity(GROUP_COUNT);
    let mut expected = Vec::with_capacity(GROUP_COUNT / 2);

    for index in 0..GROUP_COUNT {
        let kind = match index % 4 {
            0 => "record_object",
            1 => "record_parse_receipt",
            2 => "record_candidate",
            _ => "record_group_issue",
        };
        let node_id = case.add_node(kind, None, Vec::new(), json!({"index": index}))?;
        group_node_ids.push(node_id);
        if matches!(kind, "record_object" | "record_candidate") {
            expected.push(node_id);
        }
    }

    group_node_ids.reverse();
    expected.reverse();
    group_node_ids.extend([0, u64::MAX]);

    assert_eq!(record_children(&case, &group_node_ids), expected);
    Ok(())
}

#[test]
fn singleton_hypothesis_stays_unpromoted() {
    assert!(!discovered_record_task_allowed(
        "record_candidate",
        &json!({"record_count":1}),
        &RecoveryTask::TransformDiscovery,
    ));
    assert!(discovered_record_task_allowed(
        "record_candidate",
        &json!({"record_count":2}),
        &RecoveryTask::TransformDiscovery,
    ));
    assert!(discovered_record_task_allowed(
        "record_object",
        &json!({"record_count":1}),
        &RecoveryTask::TransformDiscovery,
    ));
    assert!(discovered_record_task_allowed(
        "record_candidate",
        &json!({"record_count":1}),
        &RecoveryTask::StructuralValidation,
    ));
}
