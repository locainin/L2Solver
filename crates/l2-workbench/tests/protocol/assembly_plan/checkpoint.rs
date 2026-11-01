use super::{
    RecordAssemblyPlan, RecordInput, RecordLimits, assert_compiled_layout_plan,
    assert_current_payloads_reuse_layout, frame, header_model, schema,
};
use l2_workbench::protocol::{RecordAssemblyPlanDescription, RecordError};
use serde_json::json;
use std::error::Error;

const CHECKPOINT_LIMIT: usize = 1024 * 1024;

fn compiled_plan() -> Result<RecordAssemblyPlan, Box<dyn Error>> {
    let limits = RecordLimits::default();
    let frames = vec![frame(0, 0, b'x'), frame(1, 0, b'y')];
    let models = vec![
        header_model(&frames, schema(0, 1), limits)?,
        header_model(&frames, schema(4, 2), limits)?,
    ];
    Ok(RecordAssemblyPlan::compile_header_models(
        models,
        CHECKPOINT_LIMIT,
    )?)
}

#[test]
fn checkpoint_rebuilds_shared_layouts_and_preserves_model_receipts() -> Result<(), Box<dyn Error>> {
    let plan = compiled_plan()?;
    let limits = RecordLimits::default();
    let descriptor = plan.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
    let encoded = serde_json::to_value(&descriptor)?;
    assert_eq!(
        encoded
            .get("inputs")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing inputs")?
            .len(),
        2
    );
    let bytes = serde_json::to_vec(&descriptor)?;
    let saved: RecordAssemblyPlanDescription = serde_json::from_slice(&bytes)?;
    let restored = saved.restore(limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)?;

    assert_compiled_layout_plan(&restored);
    assert_eq!(restored.stats(), plan.stats());
    assert_current_payloads_reuse_layout(&restored)?;
    let changed = [frame(3, 0, b'n'), frame(1, 0, b'w')];
    let inputs = changed
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let bound = restored.bind(&inputs)?;
    assert_ne!(
        bound.model_status(0),
        Some(l2_workbench::protocol::RecordAssemblyModelStatus::Ready)
    );
    Ok(())
}

#[test]
fn checkpoint_rejects_incompatible_limits_versions_and_invalid_header_lengths()
-> Result<(), Box<dyn Error>> {
    let plan = compiled_plan()?;
    let limits = RecordLimits::default();
    let descriptor = plan.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
    let original = serde_json::to_value(&descriptor)?;
    let mut wrong_version = original.clone();
    set_field(&mut wrong_version, "/version", json!(99))?;
    let saved: RecordAssemblyPlanDescription = serde_json::from_value(wrong_version)?;
    assert!(
        saved
            .restore(limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)
            .is_err()
    );

    let saved: RecordAssemblyPlanDescription = serde_json::from_value(original.clone())?;
    let mut changed_limits = limits;
    changed_limits.max_records -= 1;
    assert!(
        saved
            .restore(changed_limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)
            .is_err()
    );

    let mut invalid_header = original;
    set_field(&mut invalid_header, "/inputs/0/header/3", json!(255))?;
    let saved: RecordAssemblyPlanDescription = serde_json::from_value(invalid_header)?;
    assert!(
        saved
            .restore(limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)
            .is_err()
    );
    assert!(plan.checkpoint_description(limits, 0).is_err());
    let descriptor = plan.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
    let bytes = serde_json::to_vec(&descriptor)?;
    let descriptor: RecordAssemblyPlanDescription = serde_json::from_slice(&bytes)?;
    assert!(descriptor.restore(limits, 1, CHECKPOINT_LIMIT).is_err());
    assert!(descriptor.restore(limits, CHECKPOINT_LIMIT, 1).is_err());
    Ok(())
}

#[test]
fn checkpoint_reconstructs_a_large_logical_record_without_materializing_its_body()
-> Result<(), Box<dyn Error>> {
    let plan = compiled_plan()?;
    let original_limits = RecordLimits::default();
    let descriptor = plan.checkpoint_description(original_limits, CHECKPOINT_LIMIT)?;
    let mut encoded = serde_json::to_value(descriptor)?;
    let logical_length = 1024_usize * 1024 * 1024;
    let mut limits = original_limits;
    limits.max_input_bytes = logical_length;
    limits.max_output_bytes = logical_length;
    set_field(&mut encoded, "/limits", serde_json::to_value(limits)?)?;
    {
        let models = encoded
            .get_mut("models")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing models")?;
        models.truncate(1);
        let model = models.first_mut().ok_or("missing model")?;
        set_field(model, "/limits", serde_json::to_value(limits)?)?;
        set_field(model, "/schema/length/offset", json!(2))?;
        set_field(model, "/schema/length/width", json!(8))?;
        set_field(model, "/schema/data_offset", json!(10))?;
        let inputs = model
            .get_mut("inputs")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing inputs")?;
        inputs.truncate(1);
        set_field(model, "/inputs/0/header_length", json!(10))?;
    }
    let inputs = encoded
        .get_mut("inputs")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing inputs")?;
    inputs.truncate(1);
    let input = inputs.first_mut().ok_or("missing input")?;
    set_field(input, "/input_length", json!(logical_length))?;
    let payload_length = u64::try_from(logical_length - 10)?;
    let mut header = vec![b'A', 0];
    header.extend_from_slice(&payload_length.to_be_bytes());
    set_field(input, "/header", json!(header))?;

    let saved: RecordAssemblyPlanDescription = serde_json::from_value(encoded)?;
    let restored = saved.restore(limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)?;
    assert_eq!(restored.model_count(), 1);
    assert_eq!(restored.layout_count(), 1);
    assert!(restored.retained_bytes() < 64 * 1024);
    Ok(())
}

#[test]
fn checkpoint_headers_must_match_their_frozen_source_inputs() -> Result<(), Box<dyn Error>> {
    let plan = compiled_plan()?;
    let descriptor = plan.checkpoint_description(RecordLimits::default(), CHECKPOINT_LIMIT)?;
    let bytes = serde_json::to_vec(&descriptor)?;
    let descriptor: RecordAssemblyPlanDescription = serde_json::from_slice(&bytes)?;
    let frames = [frame(0, 0, b'x'), frame(1, 0, b'y')];
    let inputs = frames.iter().map(Vec::as_slice).collect::<Vec<_>>();
    descriptor.validate_inputs(&inputs)?;
    let changed_header = [frame(7, 0, b'x'), frame(1, 0, b'y')];
    let changed = changed_header.iter().map(Vec::as_slice).collect::<Vec<_>>();
    assert!(descriptor.validate_inputs(&changed).is_err());
    assert!(
        descriptor
            .validate_inputs(inputs.get(..1).ok_or("missing first input")?)
            .is_err()
    );
    let changed_length = [frame(0, 0, b'x'), vec![b'A']];
    let changed = changed_length.iter().map(Vec::as_slice).collect::<Vec<_>>();
    assert!(descriptor.validate_inputs(&changed).is_err());
    Ok(())
}

#[test]
fn checkpoint_compilation_and_reconstruction_share_one_workspace_limit()
-> Result<(), Box<dyn Error>> {
    let plan = compiled_plan()?;
    let limits = RecordLimits::default();
    let descriptor = plan.checkpoint_description(limits, CHECKPOINT_LIMIT)?;
    let bytes = serde_json::to_vec(&descriptor)?;
    let descriptor: RecordAssemblyPlanDescription = serde_json::from_slice(&bytes)?;
    let frames = vec![frame(0, 0, b'x'), frame(1, 0, b'y')];
    let mut lower = 0;
    let mut upper = CHECKPOINT_LIMIT;
    while upper - lower > 1 {
        let middle = lower + (upper - lower) / 2;
        let models = vec![
            header_model(&frames, schema(0, 1), limits)?,
            header_model(&frames, schema(4, 2), limits)?,
        ];
        if RecordAssemblyPlan::compile_header_models(models, middle).is_ok() {
            upper = middle;
        } else {
            lower = middle;
        }
    }
    match descriptor.restore(limits, CHECKPOINT_LIMIT, upper) {
        Err(RecordError::PlanTooLarge { bytes, maximum }) => {
            assert_eq!(maximum, upper);
            assert!(bytes > maximum);
        }
        result => {
            return Err(format!(
                "expected the combined workspace limit to reject restoration: {result:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn checkpoint_restores_each_models_original_limits_and_exact_receipts() -> Result<(), Box<dyn Error>>
{
    let policy_limits = RecordLimits::default();
    let mut limited = policy_limits;
    limited.max_issue_examples = 1;
    let mut layout = schema(0, 1);
    layout.terminal_sequence = Some(5);
    let frames = [0, 0, 2, 2, 4]
        .into_iter()
        .map(|sequence| frame(sequence, 0, b'x'))
        .collect::<Vec<_>>();
    let models = vec![
        header_model(&frames, layout.clone(), limited)?,
        header_model(&frames, layout, policy_limits)?,
    ];
    let plan = RecordAssemblyPlan::compile_header_models(models, CHECKPOINT_LIMIT)?;

    assert!(
        plan.checkpoint_description(limited, CHECKPOINT_LIMIT)
            .is_err()
    );
    // A saved description should not compile the already validated plan again
    let description = plan.checkpoint_description(policy_limits, CHECKPOINT_LIMIT)?;
    let mut beyond_policy = serde_json::to_value(&description)?;
    set_field(
        &mut beyond_policy,
        "/models/0/limits/max_issue_examples",
        json!(policy_limits.max_issue_examples + 1),
    )?;
    let invalid: RecordAssemblyPlanDescription = serde_json::from_value(beyond_policy)?;
    assert!(
        invalid
            .restore(policy_limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)
            .is_err()
    );
    let saved = serde_json::to_vec(&description)?;
    let saved: RecordAssemblyPlanDescription = serde_json::from_slice(&saved)?;
    let restored = saved.restore(policy_limits, CHECKPOINT_LIMIT, CHECKPOINT_LIMIT)?;
    assert_eq!(plan.stats(), restored.stats());
    let inputs = frames
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let mut original = plan.bind(&inputs)?;
    let mut resumed = restored.bind(&inputs)?;
    let original_layout = original.layout_id(0, 0).ok_or("missing original layout")?;
    let restored_layout = resumed.layout_id(0, 0).ok_or("missing restored layout")?;
    assert_eq!(
        original.materialize(original_layout)?.bytes(),
        resumed.materialize(restored_layout)?.bytes()
    );
    for model in 0..2 {
        assert_eq!(
            original.group_receipt(model, 0)?,
            resumed.group_receipt(model, 0)?
        );
    }
    let limited_receipt = resumed.group_receipt(0, 0)?;
    let full_receipt = resumed.group_receipt(1, 0)?;
    assert_eq!(limited_receipt.duplicate_sequences, vec![0]);
    assert_eq!(limited_receipt.omitted_duplicate_sequences, 1);
    assert_eq!(full_receipt.duplicate_sequences, vec![0, 2]);
    assert_eq!(full_receipt.omitted_duplicate_sequences, 0);
    Ok(())
}

// Change one existing fixture field without silently creating a different description
fn set_field(
    value: &mut serde_json::Value,
    pointer: &str,
    replacement: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    *value
        .pointer_mut(pointer)
        .ok_or_else(|| format!("checkpoint fixture field {pointer} is missing"))? = replacement;
    Ok(())
}
