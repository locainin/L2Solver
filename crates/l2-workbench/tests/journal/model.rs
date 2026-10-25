use l2_workbench::journal::ChainPlan;
use serde_json::json;
use std::error::Error;

#[test]
fn defaults_chain_deadline() -> Result<(), Box<dyn Error>> {
    let plan: ChainPlan = serde_json::from_value(json!({"steps": []}))?;

    assert_eq!(plan.max_elapsed_ms.milliseconds(), Some(120_000));
    let serialized = serde_json::to_value(&plan)?;
    assert_eq!(serialized.get("max_elapsed_ms"), Some(&json!(120_000)));
    Ok(())
}

#[test]
fn null_disables_deadline() -> Result<(), Box<dyn Error>> {
    let plan: ChainPlan = serde_json::from_value(json!({
        "steps": [],
        "max_elapsed_ms": null
    }))?;

    assert_eq!(plan.max_elapsed_ms.milliseconds(), None);
    let serialized = serde_json::to_value(&plan)?;
    assert_eq!(serialized.get("max_elapsed_ms"), Some(&json!(null)));
    Ok(())
}

#[test]
fn preserves_explicit_deadline() -> Result<(), Box<dyn Error>> {
    for milliseconds in [0, 42, u64::MAX] {
        let plan: ChainPlan = serde_json::from_value(json!({
            "steps": [],
            "max_elapsed_ms": milliseconds
        }))?;

        assert_eq!(plan.max_elapsed_ms.milliseconds(), Some(milliseconds));
        let serialized = serde_json::to_value(&plan)?;
        assert_eq!(serialized.get("max_elapsed_ms"), Some(&json!(milliseconds)));
    }
    Ok(())
}

#[test]
fn rejects_missing_steps() -> Result<(), Box<dyn Error>> {
    let error = serde_json::from_value::<ChainPlan>(json!({}))
        .err()
        .ok_or("a chain plan must include steps")?;

    assert!(error.to_string().contains("missing field `steps`"));
    Ok(())
}

#[test]
fn rejects_unknown_fields() -> Result<(), Box<dyn Error>> {
    let error = serde_json::from_value::<ChainPlan>(json!({
        "steps": [],
        "unexpected": true
    }))
    .err()
    .ok_or("a chain plan must reject unknown fields")?;

    assert!(error.to_string().contains("unknown field `unexpected`"));
    Ok(())
}
