use l2_workbench::{
    derivation::{Constraint, Operation, Recipe, SecretBytes, run},
    validation::Validator,
};
use serde_json::json;
use std::error::Error;

#[test]
fn authenticated_decryption_key_identity_retained() -> Result<(), Box<dyn Error>> {
    let key = vec![0xa5; 16];
    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![Constraint::AesGcm {
            key: key.clone().into(),
            nonce: vec![0; 12].into(),
            associated_data: Vec::new().into(),
        }],
    };

    let serialized_recipe = serde_json::to_value(&recipe)?;
    assert_eq!(
        serialized_recipe.pointer("/constraints/0/key/byte_length"),
        Some(&json!(16))
    );
    assert_eq!(
        serialized_recipe.pointer("/constraints/0/key/sha256"),
        Some(&json!(l2_workbench::sha256(&key)))
    );
    assert!(!format!("{recipe:?}").contains(&format!("{key:?}")));

    let input_recipe = json!({
        "steps": [],
        "constraints": [{
            "kind": "aes_gcm",
            "key": key,
            "nonce": vec![0; 12],
            "associated_data": []
        }]
    });
    let decoded_recipe: Recipe = serde_json::from_value(input_recipe)?;
    assert_eq!(decoded_recipe, recipe);

    let report = run(b"not authenticated data", &recipe)?;
    let serialized_report = serde_json::to_value(&report)?;
    assert_eq!(
        serialized_report.pointer("/constraints/0/constraint/key/sha256"),
        Some(&json!(l2_workbench::sha256(&key)))
    );
    assert!(!format!("{report:?}").contains(&format!("{key:?}")));

    let validator = Validator::AesGcm {
        key: &key,
        nonce: &[0; 12],
        associated_data: &[],
    };
    assert!(!format!("{validator:?}").contains(&format!("{key:?}")));
    Ok(())
}

#[test]
fn scrypt_password_identity_used_receipts() -> Result<(), Box<dyn Error>> {
    let password = b"private password";
    let salt = b"private salt".to_vec();
    let recipe = Recipe {
        steps: vec![Operation::ScryptDerive {
            salt: SecretBytes::new(salt.clone()).into(),
            log_n: 4,
            r: 1,
            p: 1,
            output_length: 32,
        }],
        constraints: Vec::new(),
    };

    let serialized_recipe = serde_json::to_value(&recipe)?;
    assert_eq!(
        serialized_recipe.pointer("/steps/0/salt/byte_length"),
        Some(&json!(salt.len()))
    );
    assert_eq!(
        serialized_recipe.pointer("/steps/0/salt/sha256"),
        Some(&json!(l2_workbench::sha256(&salt)))
    );
    assert!(!serialized_recipe.to_string().contains("private salt"));
    assert!(!format!("{recipe:?}").contains("private salt"));

    let report = run(password, &recipe)?;
    let serialized_report = serde_json::to_value(&report)?;
    assert_eq!(
        serialized_report.pointer("/steps/0/operation/salt/sha256"),
        Some(&json!(l2_workbench::sha256(&salt)))
    );
    assert!(!serialized_report.to_string().contains("private password"));
    assert!(!serialized_report.to_string().contains("private salt"));
    assert!(!format!("{report:?}").contains("private password"));
    assert!(!format!("{report:?}").contains("private salt"));
    Ok(())
}
