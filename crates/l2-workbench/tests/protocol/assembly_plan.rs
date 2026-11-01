use l2_workbench::protocol::{
    ByteField, ByteOrder, HeaderParseTemplate, IntegerField, RecordAssemblyHeaderModel,
    RecordAssemblyModelStatus, RecordAssemblyPlan, RecordCount, RecordInput, RecordLengthMeaning,
    RecordLimits, RecordSchema,
};
use std::error::Error;

#[path = "assembly_plan_fuzz.rs"]
mod bounded_fuzz;

#[path = "assembly_plan/checkpoint.rs"]
mod checkpoint;

const fn schema(identifier_offset: usize, sequence_offset: usize) -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::Exact { records: 1 },
        identifier: ByteField {
            offset: identifier_offset,
            width: 1,
        },
        sequence: IntegerField {
            offset: sequence_offset,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 3,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 5,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: Some(1),
    }
}

fn frame(sequence_a: u8, sequence_b: u8, payload: u8) -> Vec<u8> {
    frame_with_identifier(b'A', sequence_a, sequence_b, payload)
}

fn frame_with_identifier(identifier: u8, sequence_a: u8, sequence_b: u8, payload: u8) -> Vec<u8> {
    vec![identifier, sequence_a, sequence_b, 1, b'B', payload]
}

fn header_templates(
    frames: &[Vec<u8>],
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<Vec<(usize, HeaderParseTemplate)>, Box<dyn Error>> {
    let input_indices = (0..frames.len()).collect::<Vec<_>>();
    header_templates_for_indices(frames, &input_indices, schema, limits, 5)
}

fn header_templates_for_indices(
    frames: &[Vec<u8>],
    input_indices: &[usize],
    schema: &RecordSchema,
    limits: RecordLimits,
    preserved_header_end: usize,
) -> Result<Vec<(usize, HeaderParseTemplate)>, Box<dyn Error>> {
    if frames.len() != input_indices.len() {
        return Err("test frame and cohort index counts differ".into());
    }
    let mut templates = Vec::<(usize, HeaderParseTemplate)>::new();
    templates.try_reserve_exact(frames.len())?;
    for (input_index, bytes) in input_indices.iter().zip(frames) {
        let input = RecordInput::new(bytes);
        let report = input.parse(schema, limits)?;
        let template = report
            .header_only_template(&input, preserved_header_end, limits)?
            .ok_or("record report did not produce a header template")?;
        templates.push((*input_index, template));
    }
    Ok(templates)
}

fn header_model(
    frames: &[Vec<u8>],
    schema: RecordSchema,
    limits: RecordLimits,
) -> Result<RecordAssemblyHeaderModel, Box<dyn Error>> {
    let templates = header_templates(frames, &schema, limits)?;
    Ok(RecordAssemblyHeaderModel::new(schema, limits, templates))
}

fn header_model_for_indices(
    frames: &[Vec<u8>],
    input_indices: &[usize],
    schema: RecordSchema,
    limits: RecordLimits,
) -> Result<RecordAssemblyHeaderModel, Box<dyn Error>> {
    let templates = header_templates_for_indices(frames, input_indices, &schema, limits, 5)?;
    Ok(RecordAssemblyHeaderModel::new(schema, limits, templates))
}

fn two_identifier_frames() -> [Vec<u8>; 2] {
    let first = frame(0, 0, b'x');
    let second = frame_with_identifier(b'B', 1, 0, b'y');
    [first, second]
}

fn repeated_models(
    frames: &[Vec<u8>],
    model_count: usize,
    maximum_retained_bytes: usize,
) -> Result<RecordAssemblyPlan, Box<dyn Error>> {
    let limits = RecordLimits::default();
    let mut models = Vec::new();
    models.try_reserve_exact(model_count)?;
    for _ in 0..model_count {
        models.push(header_model(frames, schema(0, 1), limits)?);
    }
    Ok(RecordAssemblyPlan::compile_header_models(
        models,
        maximum_retained_bytes,
    )?)
}

fn record_sequences(receipt: &l2_workbench::protocol::RecordGroupReceipt) -> Vec<u64> {
    receipt.parts.iter().map(|part| part.sequence).collect()
}

#[test]
fn compiled_layout_reuses_bytes_but_preserves_each_models_sequence_evidence()
-> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_frames = vec![frame(0, 0, b'x'), frame(1, 0, b'y')];
    let first_model = header_model(&original_frames, schema(0, 1), limits)?;
    let second_model = header_model(&original_frames, schema(4, 2), limits)?;
    let plan =
        RecordAssemblyPlan::compile_header_models(vec![first_model, second_model], usize::MAX)?;

    assert_compiled_layout_plan(&plan);
    assert_current_payloads_reuse_layout(&plan)?;
    Ok(())
}

fn assert_compiled_layout_plan(plan: &RecordAssemblyPlan) {
    assert_eq!(plan.model_count(), 2);
    assert_eq!(plan.layout_count(), 1);
    assert_eq!(plan.stats().layout_reuses, 1);
    assert_eq!(plan.model_schema(0), Some(&schema(0, 1)));
    assert_eq!(plan.model_schema(1), Some(&schema(4, 2)));
    assert!(plan.retained_bytes() > 0);
}

fn assert_current_payloads_reuse_layout(plan: &RecordAssemblyPlan) -> Result<(), Box<dyn Error>> {
    let current_frames = [frame(0, 0, b'n'), frame(1, 0, b'w')];
    let inputs = current_frames
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let mut bound = plan.bind(&inputs)?;
    assert_eq!(
        bound.model_status(0),
        Some(RecordAssemblyModelStatus::Ready)
    );
    assert_eq!(
        bound.model_status(1),
        Some(RecordAssemblyModelStatus::Ready)
    );
    assert_eq!(bound.model_group_count(0), Some(1));
    assert_eq!(bound.model_group_count(1), Some(1));

    let first_layout = bound
        .layout_id(0, 0)
        .ok_or("first model layout is missing")?;
    let second_layout = bound
        .layout_id(1, 0)
        .ok_or("second model layout is missing")?;
    assert_eq!(first_layout, second_layout);
    assert_eq!(bound.layout_output_length(first_layout), Some(2));
    assert!(bound.group_receipt(0, 0).is_err());

    let materialized = bound.materialize(first_layout)?;
    assert_eq!(materialized.bytes(), b"nw");
    assert_eq!(materialized.sha256(), l2_workbench::sha256(b"nw"));
    assert_eq!(bound.stats().materialized_layouts, 1);
    assert_eq!(bound.stats().materialized_bytes, 2);
    assert_eq!(bound.stats().hashed_bytes, 2);
    assert_eq!(bound.stats().shared_input_checks, 2);
    assert_eq!(bound.stats().model_input_checks, 0);
    assert_eq!(bound.stats().layout_membership_checks, 0);
    assert_eq!(bound.stats().prefix_bytes_checked, 10);

    drop(materialized);
    assert_distinct_model_receipts(&bound)?;
    Ok(())
}

fn assert_distinct_model_receipts(
    bound: &l2_workbench::protocol::BoundRecordAssemblyPlan<'_, '_>,
) -> Result<(), Box<dyn Error>> {
    let first_receipt = bound.group_receipt(0, 0)?;
    let second_receipt = bound.group_receipt(1, 0)?;
    assert_eq!(first_receipt.identifier, b"A");
    assert_eq!(second_receipt.identifier, b"B");
    assert_eq!(record_sequences(&first_receipt), vec![0, 1]);
    assert_eq!(record_sequences(&second_receipt), vec![0, 0]);
    assert!(first_receipt.complete);
    assert!(!second_receipt.complete);
    assert_eq!(second_receipt.duplicate_sequences, vec![0]);
    assert_eq!(second_receipt.missing_sequence_count, 1);
    assert_eq!(second_receipt.missing_sequences, vec![1]);
    assert_eq!(first_receipt.output_sha256, second_receipt.output_sha256);
    assert_eq!(first_receipt.output_length, second_receipt.output_length);
    Ok(())
}

#[test]
fn compiled_header_plan_rejects_changed_header_and_input_length() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_frames = vec![frame(0, 0, b'x')];
    let model = header_model(&original_frames, schema(0, 1), limits)?;
    let plan = RecordAssemblyPlan::compile_header_models(vec![model], usize::MAX)?;

    let mut changed_header = frame(0, 0, b'n');
    *changed_header
        .first_mut()
        .ok_or("test frame does not contain a header byte")? = b'Z';
    let header_inputs = vec![RecordInput::new(&changed_header)];
    let bound_header = plan.bind(&header_inputs)?;
    assert!(matches!(
        bound_header.model_status(0),
        Some(RecordAssemblyModelStatus::PreservedHeaderMismatch { input_index: 0, .. })
    ));

    let mut changed_length = frame(0, 0, b'n');
    changed_length.push(b'!');
    let length_inputs = vec![RecordInput::new(&changed_length)];
    let bound_length = plan.bind(&length_inputs)?;
    assert!(matches!(
        bound_length.model_status(0),
        Some(RecordAssemblyModelStatus::InputLengthMismatch { input_index: 0, .. })
    ));
    Ok(())
}

#[test]
fn a_changed_byte_only_rejects_models_that_preserved_that_byte() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_frames = [frame(0, 0, b'x'), frame(0, 0, b'y')];
    let short_model = header_model(&original_frames, schema(0, 1), limits)?;
    let reversed_frames = [original_frames[1].clone(), original_frames[0].clone()];
    let reversed_input_indices = [1, 0];
    let long_model = RecordAssemblyHeaderModel::new(
        schema(0, 1),
        limits,
        header_templates_for_indices(
            &reversed_frames,
            &reversed_input_indices,
            &schema(0, 1),
            limits,
            6,
        )?,
    );
    let plan =
        RecordAssemblyPlan::compile_header_models(vec![short_model, long_model], usize::MAX)?;
    assert_eq!(plan.layout_count(), 2);

    let changed_frames = [frame(0, 0, b'n'), frame(0, 0, b'w')];
    let inputs = changed_frames
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let mut bound = plan.bind(&inputs)?;

    assert_eq!(
        bound.model_status(0),
        Some(RecordAssemblyModelStatus::Ready)
    );
    assert_eq!(
        bound.model_status(1),
        Some(RecordAssemblyModelStatus::PreservedHeaderMismatch { input_index: 1 })
    );
    assert_eq!(bound.model_group_count(0), Some(1));
    assert_eq!(bound.model_group_count(1), None);
    assert_eq!(bound.layout_id(1, 0), None);
    assert_eq!(bound.stats().shared_input_checks, 2);
    assert_eq!(bound.stats().model_input_checks, 3);
    assert_eq!(bound.stats().layout_membership_checks, 1);
    let ready_layout = bound
        .layout_id(0, 0)
        .ok_or("ready model layout is missing while another model is rejected")?;
    assert_eq!(bound.layout_output_length(ready_layout), Some(2));
    assert_eq!(bound.materialize(ready_layout)?.bytes(), b"nw");
    Ok(())
}

#[test]
fn compiled_header_plan_rejects_limits_that_differ_from_the_prepared_template()
-> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original_frames = vec![frame(0, 0, b'x')];
    let templates = header_templates(&original_frames, &schema(0, 1), limits)?;
    let changed_limits = RecordLimits {
        max_issue_examples: limits.max_issue_examples.saturating_sub(1),
        ..limits
    };
    let invalid_model = RecordAssemblyHeaderModel::new(schema(0, 1), changed_limits, templates);

    assert!(RecordAssemblyPlan::compile_header_models(vec![invalid_model], usize::MAX).is_err());
    Ok(())
}

#[test]
fn compiled_header_plan_enforces_aggregate_output_limit() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits {
        max_output_bytes: 1,
        ..RecordLimits::default()
    };
    let original_frames = vec![frame(0, 0, b'x'), frame(1, 0, b'y')];
    let model = header_model(&original_frames, schema(0, 1), limits)?;

    assert!(RecordAssemblyPlan::compile_header_models(vec![model], usize::MAX).is_err());
    Ok(())
}

#[test]
fn per_model_input_limit_excludes_unselected_global_control_inputs() -> Result<(), Box<dyn Error>> {
    let limits = RecordLimits {
        max_input_bytes: 12,
        ..RecordLimits::default()
    };
    let selected_frames = [frame(0, 0, b'x'), frame(1, 0, b'y')];
    let model = header_model_for_indices(&selected_frames, &[1, 3], schema(0, 1), limits)?;
    let plan = RecordAssemblyPlan::compile_header_models(vec![model], usize::MAX)?;

    let control_a = [0; 20];
    let control_b = [0; 21];
    let trailing_control = [0; 22];
    let cohort = [
        control_a.as_slice(),
        selected_frames[0].as_slice(),
        control_b.as_slice(),
        selected_frames[1].as_slice(),
        trailing_control.as_slice(),
    ];
    let inputs = cohort
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let mut bound = plan.bind(&inputs)?;

    assert_eq!(
        bound.model_status(0),
        Some(RecordAssemblyModelStatus::Ready)
    );
    assert_eq!(bound.stats().prefix_bytes_checked, 10);
    assert_eq!(bound.stats().shared_input_checks, 2);
    assert_eq!(bound.stats().model_input_checks, 0);
    let layout = bound.layout_id(0, 0).ok_or("model layout is missing")?;
    let materialized = bound.materialize(layout)?;
    assert_eq!(materialized.bytes(), b"xy");
    let receipt = bound.group_receipt(0, 0)?;
    assert_eq!(
        receipt
            .parts
            .iter()
            .map(|part| part.input_index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    Ok(())
}

#[test]
fn physical_layout_uses_global_inputs_while_receipts_keep_local_order() -> Result<(), Box<dyn Error>>
{
    let limits = RecordLimits::default();
    let selected_frames = [frame(0, 0, b'x'), frame(0, 0, b'y')];
    let first_model = header_model_for_indices(&selected_frames, &[1, 3], schema(0, 1), limits)?;
    let second_model = header_model_for_indices(&selected_frames, &[3, 1], schema(0, 1), limits)?;
    let plan =
        RecordAssemblyPlan::compile_header_models(vec![first_model, second_model], usize::MAX)?;
    assert_eq!(plan.model_input_global_index(0, 0), Some(1));
    assert_eq!(plan.model_input_global_index(0, 1), Some(3));
    assert_eq!(plan.model_input_global_index(1, 0), Some(3));
    assert_eq!(plan.model_input_global_index(1, 1), Some(1));
    let control_a = [0; 2];
    let control_b = [0; 3];
    let cohort = [
        control_a.as_slice(),
        selected_frames[0].as_slice(),
        control_b.as_slice(),
        selected_frames[1].as_slice(),
    ];
    let inputs = cohort
        .iter()
        .map(|bytes| RecordInput::new(bytes))
        .collect::<Vec<_>>();
    let mut bound = plan.bind(&inputs)?;
    let first_layout = bound.layout_id(0, 0).ok_or("first layout is missing")?;
    let second_layout = bound.layout_id(1, 0).ok_or("second layout is missing")?;

    assert_ne!(first_layout, second_layout);
    assert_eq!(bound.materialize(first_layout)?.bytes(), b"xy");
    assert_eq!(bound.materialize(second_layout)?.bytes(), b"yx");
    for model_index in [0, 1] {
        let receipt = bound.group_receipt(model_index, 0)?;
        assert_eq!(
            receipt
                .parts
                .iter()
                .map(|part| part.input_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }
    Ok(())
}

#[test]
fn prior_shared_input_lookup_workspace_is_included_for_the_next_model() -> Result<(), Box<dyn Error>>
{
    let frames = two_identifier_frames();
    let one_model = repeated_models(&frames, 1, usize::MAX)?;
    let one_model_retained_bytes = one_model.retained_bytes();
    drop(one_model);
    let two_models = repeated_models(&frames, 2, usize::MAX)?;
    let two_models_retained_bytes = two_models.retained_bytes();
    drop(two_models);

    let mut lower_bound = 0_usize;
    let mut upper_bound = one_model_retained_bytes.saturating_add(64 * 1024);
    while lower_bound < upper_bound {
        let candidate_bound = lower_bound + (upper_bound - lower_bound) / 2;
        if repeated_models(&frames, 1, candidate_bound).is_ok() {
            upper_bound = candidate_bound;
        } else {
            lower_bound = candidate_bound.saturating_add(1);
        }
    }
    let additional_retained_bytes =
        two_models_retained_bytes.saturating_sub(one_model_retained_bytes);
    let maximum_bytes = lower_bound.saturating_add(additional_retained_bytes);
    let error = repeated_models(&frames, 2, maximum_bytes)
        .err()
        .ok_or("second model fit without room for the retained compiler lookup")?;
    assert!(
        matches!(error.downcast_ref::<l2_workbench::protocol::RecordError>(),
        Some(l2_workbench::protocol::RecordError::PlanTooLarge { maximum, .. })
            if *maximum == maximum_bytes)
    );
    Ok(())
}

#[test]
fn conflicting_template_expectations_for_one_global_input_are_rejected()
-> Result<(), Box<dyn Error>> {
    let limits = RecordLimits::default();
    let original = [frame(0, 0, b'x')];
    let mut changed_prefix = frame(0, 0, b'y');
    *changed_prefix
        .first_mut()
        .ok_or("test frame has no identifier byte")? = b'Z';
    let changed_prefix = [changed_prefix];
    let first_model = header_model_for_indices(&original, &[0], schema(0, 1), limits)?;
    let second_model = header_model_for_indices(&changed_prefix, &[0], schema(0, 1), limits)?;
    assert!(
        RecordAssemblyPlan::compile_header_models(vec![first_model, second_model], usize::MAX)
            .is_err()
    );

    let mut changed_length = frame(0, 0, b'x');
    *changed_length
        .get_mut(3)
        .ok_or("test record has no length field")? = 2;
    changed_length.push(b'y');
    let changed_length = [changed_length];
    let different_length_model =
        header_model_for_indices(&changed_length, &[0], schema(0, 1), limits)?;
    let same_length_model = header_model_for_indices(&original, &[0], schema(0, 1), limits)?;
    assert!(
        RecordAssemblyPlan::compile_header_models(
            vec![same_length_model, different_length_model],
            usize::MAX
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn compiled_plan_respects_exact_and_exhausted_aggregate_retention_bounds()
-> Result<(), Box<dyn Error>> {
    let frames = two_identifier_frames();
    let unbounded = repeated_models(&frames, 1, usize::MAX)?;
    let exact_retained_bytes = unbounded.retained_bytes();
    drop(unbounded);

    let mut lower_bound = 0_usize;
    let mut upper_bound = exact_retained_bytes.saturating_add(64 * 1024);
    while lower_bound < upper_bound {
        let candidate_bound = lower_bound + (upper_bound - lower_bound) / 2;
        if repeated_models(&frames, 1, candidate_bound).is_ok() {
            upper_bound = candidate_bound;
        } else {
            lower_bound = candidate_bound.saturating_add(1);
        }
    }
    let exact_bound = repeated_models(&frames, 1, lower_bound)?;
    assert_eq!(exact_bound.retained_bytes(), exact_retained_bytes);
    drop(exact_bound);

    assert!(matches!(
        repeated_models(&frames, 1, lower_bound.saturating_sub(1)),
        Err(error) if matches!(
            error.downcast_ref::<l2_workbench::protocol::RecordError>(),
            Some(l2_workbench::protocol::RecordError::PlanTooLarge { maximum, .. })
                if *maximum == lower_bound.saturating_sub(1)
        )
    ));
    assert!(matches!(
        repeated_models(&frames, 2, lower_bound),
        Err(error) if matches!(
            error.downcast_ref::<l2_workbench::protocol::RecordError>(),
            Some(l2_workbench::protocol::RecordError::PlanTooLarge { maximum, .. })
                if *maximum == lower_bound
        )
    ));
    Ok(())
}

#[test]
fn plan_construction_stops_before_large_diagnostics_exceeding_remaining_allowance()
-> Result<(), Box<dyn Error>> {
    let limits = RecordLimits {
        max_issue_examples: 4_096,
        max_report_bytes: 1_000_000,
        ..RecordLimits::default()
    };
    let frames = (0..120)
        .map(|sequence| frame(sequence, 0, b'x'))
        .collect::<Vec<_>>();
    let schema = RecordSchema {
        terminal_sequence: Some(5_000),
        ..schema(0, 1)
    };
    let unbounded = RecordAssemblyPlan::compile_header_models(
        vec![header_model(&frames, schema.clone(), limits)?],
        usize::MAX,
    )?;
    let final_plan_bytes = unbounded.retained_bytes();
    let templates = header_templates(&frames, &schema, limits)?;
    let model = RecordAssemblyHeaderModel::new(schema, limits, templates);

    let maximum_bytes = final_plan_bytes.saturating_sub(10_000);
    let error = RecordAssemblyPlan::compile_header_models(vec![model], maximum_bytes)
        .err()
        .ok_or("large diagnostic plan unexpectedly fit a small construction allowance")?;
    let l2_workbench::protocol::RecordError::PlanTooLarge { bytes, maximum } = error else {
        return Err("plan construction failed for a reason other than its allowance".into());
    };
    assert_eq!(maximum, maximum_bytes);
    assert!(
        bytes > final_plan_bytes,
        "failure occurred after final plan accounting"
    );
    Ok(())
}

#[test]
fn bounded_generated_inputs_preserve_compiled_plan_semantics() {
    let empty: [u8; 0] = [];
    let zeros = [0; 64];
    let high_bytes = [u8::MAX; 64];
    let ascending = (0_u8..64).collect::<Vec<_>>();

    for input in [
        empty.as_slice(),
        zeros.as_slice(),
        high_bytes.as_slice(),
        ascending.as_slice(),
    ] {
        assert_eq!(
            bounded_fuzz::exercise(input),
            Ok(()),
            "bounded property failed for input {input:?}"
        );
    }
}
