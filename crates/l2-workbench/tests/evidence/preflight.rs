use l2_workbench::evidence::{
    Case, EvidenceError, MAX_NODE_DETAILS_BYTES, MAX_TOTAL_DETAILS_BYTES,
};
use serde_json::json;
use std::error::Error;

#[test]
fn raw_node_materializing_json_values() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_node("observation", None, Vec::new(), json!({}))?;
    let document = String::from_utf8(case.to_json()?)?;
    let oversized = format!("{{{}}}", " ".repeat(MAX_NODE_DETAILS_BYTES));
    let document = document.replace("\"details\":{}", &format!("\"details\":{oversized}"));
    assert!(matches!(
        Case::from_json(document.as_bytes()),
        Err(EvidenceError::NodeDetailsTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn aggregate_raw_details_budget_graph() -> Result<(), Box<dyn Error>> {
    let count = MAX_TOTAL_DETAILS_BYTES / MAX_NODE_DETAILS_BYTES + 1;
    let mut case = Case::new();
    for _ in 0..count {
        case.add_node("observation", None, Vec::new(), json!({}))?;
    }
    let document = String::from_utf8(case.to_json()?)?;
    let bounded = format!("{{{}}}", " ".repeat(MAX_NODE_DETAILS_BYTES - 2));
    let document = document.replace("\"details\":{}", &format!("\"details\":{bounded}"));
    assert!(matches!(
        Case::from_json(document.as_bytes()),
        Err(EvidenceError::TotalDetailsTooLarge { .. })
    ));
    Ok(())
}
