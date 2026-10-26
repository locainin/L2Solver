use super::*;
use serde_json::json;
use std::error::Error;

#[test]
fn relational_lineage_index_updates_only_for_committed_decoded_frames() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    case.add_bytes_node(
        "record_candidate",
        b"ordinary",
        Vec::new(),
        json!({"relational_decoded_frame":true}),
    )?;
    let mut index = CaseIndex::new(&case)?;
    assert!(!index.has_relational_frames);

    // A failed evidence transaction must not affect the incremental lineage index
    let rolled_back: Result<(), Box<dyn Error>> = case.transaction(|transaction| {
        transaction.add_bytes_node(
            "relational_decoded_frame",
            b"not committed",
            Vec::new(),
            json!({"relational_decoded_frame":true}),
        )?;
        Err(std::io::Error::other("injected evidence rollback").into())
    });
    assert!(rolled_back.is_err());
    index.refresh(&case)?;
    assert!(!index.has_relational_frames);

    case.add_bytes_node(
        "relational_decoded_frame",
        b"committed",
        Vec::new(),
        json!({"relational_decoded_frame":true}),
    )?;
    index.refresh(&case)?;
    assert!(index.has_relational_frames);
    assert!(CaseIndex::new(&case)?.has_relational_frames);
    Ok(())
}
