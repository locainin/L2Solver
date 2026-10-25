use l2_workbench::{
    behavior::{BehaviorConfig, visit_case},
    evidence::Case,
};
use serde_json::json;
use std::error::Error;

#[test]
fn finding_visitor_without_retention_limit() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for _ in 0..4097 {
        case.add_node("arp_claim_sequence", None, Vec::new(), json!({}))?;
    }
    let mut visited = 0;
    let mut final_node = None;
    let limitations = visit_case(&case, &BehaviorConfig::default(), |finding| {
        visited += 1;
        final_node = finding.node_ids.first().copied();
        Ok(())
    })?;
    assert_eq!(visited, 4097);
    assert_eq!(final_node, Some(4097));
    assert!(
        !limitations
            .iter()
            .any(|limitation| limitation.contains("omitted"))
    );
    Ok(())
}

#[test]
fn finding_visitor_without_later_findings() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for _ in 0..3 {
        case.add_node("arp_claim_sequence", None, Vec::new(), json!({}))?;
    }
    let mut visited = 0;
    let result = visit_case(&case, &BehaviorConfig::default(), |_| {
        visited += 1;
        Err("finding consumer failed".into())
    });
    let error = result.err().ok_or("consumer failure was lost")?;
    assert_eq!(error.to_string(), "finding consumer failed");
    assert_eq!(visited, 1);
    Ok(())
}

#[test]
fn finding_visitor_source_collection_limitations() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.mark_incomplete("Source records were omitted")?;
    let limitations = visit_case(&case, &BehaviorConfig::default(), |_| Ok(()))?;
    assert!(
        limitations
            .iter()
            .any(|text| text == "Source records were omitted")
    );
    assert!(!case.collection_complete());
    Ok(())
}
