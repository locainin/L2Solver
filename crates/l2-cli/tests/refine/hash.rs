use std::error::Error;

#[test]
fn streaming_json_hash_matches_the_canonical_serialized_bytes() -> Result<(), Box<dyn Error>> {
    let value = ("source", ["line\nnext", "quote\"", "λ"]);
    let expected = l2_workbench::sha256(&serde_json::to_vec(&value)?);
    assert_eq!(super::hash_json(&value)?, expected);
    Ok(())
}

#[test]
fn streaming_source_identity_matches_the_existing_ordered_representation()
-> Result<(), Box<dyn Error>> {
    let sources = [(1_u64, "abc"), (42_u64, "d\"ef")];
    let entries = sources
        .iter()
        .map(|(length, digest)| serde_json::json!({ "byte_length": length, "sha256": digest }))
        .collect::<Vec<_>>();
    let expected = l2_workbench::sha256(&serde_json::to_vec(&(
        "l2solver-refine-input-set-v1",
        entries,
    ))?);
    assert_eq!(
        crate::refine::output::refine_source_identity_sha256(sources)?,
        expected
    );
    let empty: [(u64, &str); 0] = [];
    let expected_empty = l2_workbench::sha256(&serde_json::to_vec(&(
        "l2solver-refine-input-set-v1",
        Vec::<serde_json::Value>::new(),
    ))?);
    assert_eq!(
        crate::refine::output::refine_source_identity_sha256(empty)?,
        expected_empty
    );
    Ok(())
}
