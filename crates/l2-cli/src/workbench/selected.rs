use l2_workbench::evidence::{Case, Node};
use std::error::Error;

pub(super) fn bytes(case: &Case, id: u64) -> Result<(&Node, &[u8]), Box<dyn Error>> {
    let node = case.node(id).ok_or("selected node does not exist")?;
    let blob_id = node
        .blob
        .as_deref()
        .ok_or("selected node has no retained bytes")?;
    let blob = case
        .blob(blob_id)
        .ok_or("selected node bytes are missing")?;
    Ok((node, &blob.bytes))
}
