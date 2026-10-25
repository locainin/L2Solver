use l2_workbench::derivation::{DerivationStatus, Operation, Recipe, run};
use std::error::Error;

#[test]
fn recipe_deserialization_operation_parameters_typed() -> Result<(), Box<dyn Error>> {
    let recipe: Recipe = serde_json::from_str(
        r#"{"steps":[{"kind":"xor_repeat","key":[1,2],"offset":1}],"constraints":[]}"#,
    )?;

    assert!(matches!(
        recipe.steps.first(),
        Some(Operation::XorRepeat { key, offset }) if key == &[1, 2] && *offset == 1
    ));
    let report = run(&[0x10], &recipe)?;
    assert_eq!(report.output, [0x12]);
    Ok(())
}

#[test]
fn explicit_slice_recipe_wire_shape() -> Result<(), Box<dyn Error>> {
    let recipe: Recipe = serde_json::from_str(
        r#"{"steps":[{"kind":"slice","start":1,"length":2}],"constraints":[]}"#,
    )?;
    let report = run(b"abcd", &recipe)?;
    assert_eq!(report.output, b"bc");
    let encoded = serde_json::to_value(&recipe)?;
    assert_eq!(
        encoded.pointer("/steps/0/length"),
        Some(&serde_json::json!(2))
    );
    Ok(())
}

#[test]
fn scrypt_recipe_deserializes_parameters_output() -> Result<(), Box<dyn Error>> {
    let recipe: Recipe = serde_json::from_str(
        r#"{"steps":[{"kind":"scrypt_derive","salt":[],"log_n":4,"r":1,"p":1,"output_length":64}],"constraints":[]}"#,
    )?;

    let report = run(b"", &recipe)?;
    assert_eq!(report.output.len(), 64);
    assert_eq!(report.status, DerivationStatus::Completed);
    Ok(())
}

#[test]
fn bit_selection_recipe_round_trips() -> Result<(), Box<dyn Error>> {
    let source = r#"{"steps":[{"kind":"select_bits","indices":[0,7,8],"bits_per_byte":3}],"constraints":[]}"#;
    let recipe: Recipe = serde_json::from_str(source)?;
    let encoded = serde_json::to_string(&recipe)?;
    let round_tripped: Recipe = serde_json::from_str(&encoded)?;

    assert_eq!(round_tripped, recipe);
    let report = run(&[0b1000_0001, 0b0000_0000], &round_tripped)?;
    assert_eq!(report.output, [0b110]);
    Ok(())
}

#[test]
fn operations_reject_unapplied_fields() {
    for input in [
        r#"{"steps":[{"kind":"reverse","guess_key":true}],"constraints":[]}"#,
        r#"{"steps":[{"kind":"xor_repeat","key":[1],"offset":0,"guess_key":true}],"constraints":[]}"#,
    ] {
        assert!(serde_json::from_str::<Recipe>(input).is_err());
    }
}

#[test]
fn recipe_deserialization_top_level_fields() {
    let result =
        serde_json::from_str::<Recipe>(r#"{"steps":[],"constraints":[],"unexpected":true}"#);
    assert!(result.is_err());
}

#[test]
fn constraints_reject_unapplied_fields() {
    for input in [
        r#"{"kind":"utf8","guess_encoding":true}"#,
        r#"{"kind":"json","repair":true}"#,
    ] {
        assert!(serde_json::from_str::<l2_workbench::derivation::Constraint>(input).is_err());
    }
}
