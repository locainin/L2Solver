use l2_workbench::protocol::{
    ByteRange, RelationalAppliedOutput, RelationalOutputMapping, RelationalSessionId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SavedOutput {
    #[serde(with = "l2_workbench::job::checkpoint_relational_output")]
    output: RelationalAppliedOutput,
}

fn output_fixture() -> SavedOutput {
    SavedOutput {
        output: RelationalAppliedOutput {
            session: RelationalSessionId {
                source: "source".into(),
                scope: "scope".into(),
                session: 9,
            },
            session_order: 7,
            seed_sample: 4,
            payload_mappings: vec![RelationalOutputMapping {
                sample: 5,
                source_range: ByteRange { start: 1, end: 4 },
                output_range: ByteRange { start: 0, end: 3 },
            }],
            bytes: vec![0, 1, 255],
            parser_validation_deferred: true,
            work_bytes: 88,
        },
    }
}

#[test]
fn checkpoint_output_compacts_bytes_and_preserves_public_output_json() -> Result<(), Box<dyn Error>>
{
    let saved = output_fixture();
    let document = serde_json::to_value(&saved)?;
    assert_eq!(
        document
            .pointer("/output/bytes")
            .and_then(serde_json::Value::as_str),
        Some("AAH/")
    );
    assert_eq!(serde_json::from_value::<SavedOutput>(document)?, saved);
    assert_eq!(
        serde_json::to_value(&saved.output)?.get("bytes"),
        Some(&serde_json::json!([0, 1, 255]))
    );
    Ok(())
}

#[test]
fn checkpoint_output_rejects_noncanonical_and_numeric_byte_fields() -> Result<(), Box<dyn Error>> {
    for invalid in [serde_json::json!("AB=="), serde_json::json!([0, 1, 255])] {
        let mut document = serde_json::to_value(output_fixture())?;
        *document
            .pointer_mut("/output/bytes")
            .ok_or("fixture output bytes are missing")? = invalid;
        assert!(serde_json::from_value::<SavedOutput>(document).is_err());
    }
    Ok(())
}
