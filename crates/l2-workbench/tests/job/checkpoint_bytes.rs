use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SavedBytes {
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    bytes: Vec<u8>,
}

#[test]
fn checkpoint_bytes_serialize_canonical_padding_and_restore_exact_bytes()
-> Result<(), Box<dyn Error>> {
    for (bytes, encoded) in [
        (vec![], ""),
        (vec![0], "AA=="),
        (vec![0, 1], "AAE="),
        (vec![0, 1, 255], "AAH/"),
    ] {
        let value = SavedBytes { bytes };
        let document = serde_json::to_value(&value)?;
        assert_eq!(document["bytes"], encoded);
        assert_eq!(serde_json::from_value::<SavedBytes>(document)?, value);
    }
    Ok(())
}

#[test]
fn checkpoint_bytes_reject_noncanonical_text_and_numeric_arrays() {
    for document in [
        r#"{"bytes":"AA="}"#,
        r#"{"bytes":"AB=="}"#,
        r#"{"bytes":"AA==="}"#,
        r#"{"bytes":[0,1]}"#,
    ] {
        assert!(
            serde_json::from_str::<SavedBytes>(document).is_err(),
            "unexpectedly accepted {document}"
        );
    }
}
