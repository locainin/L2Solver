use std::{collections::HashMap, error::Error};

use l2_workbench::evidence::Case;
use serde_json::json;

#[test]
fn archive_parent_path_follows_input_nodes_to_the_retained_member() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let member = case.add_node("archive_member", None, Vec::new(), json!({}))?;
    let structure = case.add_node(
        "archive_structure",
        None,
        Vec::new(),
        json!({"input_node": member}),
    )?;
    let detached = case.add_node("archive_structure", None, Vec::new(), json!({}))?;
    let paths = HashMap::from([(member, "nested/inside.zip")]);

    assert_eq!(
        super::archive_member_ancestor_path(member, &case, &paths),
        Some("nested/inside.zip")
    );
    assert_eq!(
        super::archive_member_ancestor_path(structure, &case, &paths),
        Some("nested/inside.zip")
    );
    assert!(super::archive_member_ancestor_path(detached, &case, &paths).is_none());
    assert!(super::archive_member_ancestor_path(0, &case, &paths).is_none());
    Ok(())
}
