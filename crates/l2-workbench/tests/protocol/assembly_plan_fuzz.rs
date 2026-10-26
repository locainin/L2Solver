use l2_workbench::protocol::{
    BoundRecordAssemblyPlan, ByteField, ByteOrder, HeaderParseTemplate, RecordAssemblyHeaderModel,
    RecordAssemblyInput, RecordAssemblyModelStatus, RecordAssemblyOutcome, RecordAssemblyPart,
    RecordAssemblyPlan, RecordCount, RecordError, RecordInput, RecordLengthMeaning, RecordLimits,
    RecordParseReport, RecordSchema, assemble_record_groups_from_inputs,
};

const INPUT_LIMIT: usize = 64;
const HEADER_LENGTH: usize = 5;
const MAX_PAYLOAD_LENGTH: u8 = 8;
const MAX_PLAN_BYTES: usize = 1024 * 1024;

type ModelOrders = [Vec<usize>; 2];

pub fn exercise(data: &[u8]) -> Result<(), String> {
    let bounded = data.get(..data.len().min(INPUT_LIMIT)).unwrap_or_default();
    let (frames, count_byte) = make_frames(bounded);
    let orders = model_orders(frames.len());
    let schema = record_schema(count_byte);
    let limits = RecordLimits::default();
    let models = make_models(&frames, &orders, &schema, limits)?;
    let plan = RecordAssemblyPlan::compile_header_models(models, MAX_PLAN_BYTES)
        .map_err(|error| format!("generated plan did not compile: {error}"))?;
    ensure(plan.model_count() == orders.len(), "model count changed")?;

    let inputs = record_inputs(&frames);
    let mut bound = plan
        .bind(&inputs)
        .map_err(|error| format!("generated inputs did not bind: {error}"))?;
    compare_with_reference(&plan, &mut bound, &frames, &orders, &schema, limits)?;

    // Payload changes stay eligible and must produce newly projected bytes
    let mut changed_payloads = frames.clone();
    let payload_byte = changed_payloads
        .get_mut(0)
        .and_then(|frame| frame.get_mut(HEADER_LENGTH))
        .ok_or_else(|| "generated frame has no payload byte".to_owned())?;
    *payload_byte ^= 0x80;
    let changed_inputs = record_inputs(&changed_payloads);
    let mut changed_bound = plan
        .bind(&changed_inputs)
        .map_err(|error| format!("changed payload inputs did not bind: {error}"))?;
    compare_with_reference(
        &plan,
        &mut changed_bound,
        &changed_payloads,
        &orders,
        &schema,
        limits,
    )?;

    check_changed_header_and_length(&plan, &frames, orders.len())?;

    // An empty retained-byte budget must reject the same valid model set
    let models = make_models(&frames, &orders, &schema, limits)?;
    match RecordAssemblyPlan::compile_header_models(models, 0) {
        Err(RecordError::PlanTooLarge { maximum: 0, .. }) => {}
        Err(error) => return Err(format!("zero budget returned the wrong error: {error}")),
        Ok(_) => return Err("zero budget accepted a nonempty plan".to_owned()),
    }
    Ok(())
}

fn check_changed_header_and_length(
    plan: &RecordAssemblyPlan,
    frames: &[Vec<u8>],
    model_count: usize,
) -> Result<(), String> {
    // A changed preserved header must disable every layout using that input
    let mut changed_header = frames.to_vec();
    let identifier = changed_header
        .get_mut(0)
        .and_then(|frame| frame.first_mut())
        .ok_or_else(|| "generated frame has no identifier byte".to_owned())?;
    *identifier ^= u8::MAX;
    let header_inputs = record_inputs(&changed_header);
    let header_bound = plan
        .bind(&header_inputs)
        .map_err(|error| format!("changed header inputs did not bind: {error}"))?;
    for model_index in 0..model_count {
        ensure(
            header_bound.model_status(model_index)
                == Some(RecordAssemblyModelStatus::PreservedHeaderMismatch { input_index: 0 }),
            "changed header was not reported for every model",
        )?;
        ensure(
            header_bound.layout_id(model_index, 0).is_none(),
            "changed header retained an output layout",
        )?;
    }

    // A changed source length must be reported before materialization
    let mut changed_length = frames.to_vec();
    let frame = changed_length
        .get_mut(0)
        .ok_or_else(|| "generated first frame is missing".to_owned())?;
    ensure(
        frame.pop().is_some(),
        "generated frame was unexpectedly empty",
    )?;
    let length_inputs = record_inputs(&changed_length);
    let length_bound = plan
        .bind(&length_inputs)
        .map_err(|error| format!("changed length inputs did not bind: {error}"))?;
    for model_index in 0..model_count {
        ensure(
            length_bound.model_status(model_index)
                == Some(RecordAssemblyModelStatus::InputLengthMismatch { input_index: 0 }),
            "changed source length was not reported for every model",
        )?;
        ensure(
            length_bound.layout_id(model_index, 0).is_none(),
            "changed source length retained an output layout",
        )?;
    }
    Ok(())
}

fn make_frames(input: &[u8]) -> (Vec<Vec<u8>>, u8) {
    let count_byte = byte_at(input, 0) % 4 + 2;
    let count = usize::from(count_byte);
    let mut frames = Vec::with_capacity(count);
    for index in 0..count {
        let base = 1 + index * 16;
        let payload_length_byte = byte_at(input, base + 4) % MAX_PAYLOAD_LENGTH + 1;
        let payload_length = usize::from(payload_length_byte);
        let mut frame = Vec::with_capacity(HEADER_LENGTH + payload_length);
        frame.push(byte_at(input, base + 1) % 3);
        frame.push(byte_at(input, base + 2) % count_byte);
        frame.push(byte_at(input, base + 3));
        frame.push(payload_length_byte);
        frame.push(0x42);
        for offset in 0..payload_length {
            frame.push(byte_at(input, base + 5 + offset));
        }
        frames.push(frame);
    }
    (frames, count_byte)
}

fn model_orders(input_count: usize) -> ModelOrders {
    let forward = (0..input_count).collect::<Vec<_>>();
    let mut reverse = forward.clone();
    reverse.reverse();
    [forward, reverse]
}

fn record_schema(input_count: u8) -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::Exact { records: 1 },
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: l2_workbench::protocol::IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: l2_workbench::protocol::IntegerField {
            offset: 3,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: HEADER_LENGTH,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: Some(u64::from(input_count - 1)),
    }
}

fn make_models(
    frames: &[Vec<u8>],
    orders: &ModelOrders,
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<Vec<RecordAssemblyHeaderModel>, String> {
    let mut models = Vec::with_capacity(orders.len());
    for order in orders {
        let mut templates = Vec::<(usize, HeaderParseTemplate)>::with_capacity(order.len());
        for global_index in order {
            let input_bytes = frames
                .get(*global_index)
                .ok_or_else(|| "model references a missing generated frame".to_owned())?;
            let input = RecordInput::new(input_bytes);
            let report = input
                .parse(schema, limits)
                .map_err(|error| format!("generated frame did not parse: {error}"))?;
            let template = report
                .header_only_template(&input, HEADER_LENGTH, limits)
                .map_err(|error| format!("generated header template failed: {error}"))?
                .ok_or_else(|| "generated record did not produce a header template".to_owned())?;
            templates.push((*global_index, template));
        }
        models.push(RecordAssemblyHeaderModel::new(
            schema.clone(),
            limits,
            templates,
        ));
    }
    Ok(models)
}

fn record_inputs(frames: &[Vec<u8>]) -> Vec<RecordInput<'_>> {
    frames.iter().map(|frame| RecordInput::new(frame)).collect()
}

fn baseline(
    frames: &[Vec<u8>],
    order: &[usize],
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<RecordAssemblyOutcome, String> {
    let inputs = record_inputs(frames);
    let mut reports = Vec::<RecordParseReport>::with_capacity(inputs.len());
    for input in &inputs {
        reports.push(
            input
                .parse(schema, limits)
                .map_err(|error| format!("reference frame did not parse: {error}"))?,
        );
    }
    let mut assembly_inputs = Vec::<RecordAssemblyInput<'_>>::with_capacity(order.len());
    for global_index in order {
        let input = inputs
            .get(*global_index)
            .ok_or_else(|| "reference order points to a missing input".to_owned())?;
        let report = reports
            .get(*global_index)
            .ok_or_else(|| "reference order points to a missing parse report".to_owned())?;
        assembly_inputs.push(
            RecordAssemblyInput::from_input(input, report)
                .map_err(|error| format!("reference input construction failed: {error}"))?,
        );
    }
    assemble_record_groups_from_inputs(&assembly_inputs, limits)
        .map_err(|error| format!("reference assembly failed: {error}"))
}

fn compare_with_reference(
    plan: &RecordAssemblyPlan,
    bound: &mut BoundRecordAssemblyPlan<'_, '_>,
    frames: &[Vec<u8>],
    orders: &ModelOrders,
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<(), String> {
    for (model_index, order) in orders.iter().enumerate() {
        ensure(
            bound.model_status(model_index) == Some(RecordAssemblyModelStatus::Ready),
            "valid generated model did not bind as ready",
        )?;
        let expected = baseline(frames, order, schema, limits)?;
        let expected_groups = expected.report().groups;
        ensure(
            bound.model_group_count(model_index) == Some(expected_groups.len()),
            "compiled and reference group counts differ",
        )?;
        for (group_index, expected_group) in expected_groups.iter().enumerate() {
            let layout_id = bound
                .layout_id(model_index, group_index)
                .ok_or_else(|| "ready model is missing a group layout".to_owned())?;
            ensure(
                bound.layout_output_length(layout_id)
                    == Some(expected_group.candidate_bytes().len()),
                "compiled output length differs from the reference",
            )?;
            let materialized = bound
                .materialize(layout_id)
                .map_err(|error| format!("compiled layout failed to materialize: {error}"))?;
            let expected_payloads =
                project_source_payloads(frames, order, &expected_group.receipt().parts)?;
            ensure(
                expected_group.candidate_bytes() == expected_payloads,
                "reference candidate differs from direct source payload projection",
            )?;
            ensure(
                materialized.bytes() == expected_payloads,
                "compiled candidate differs from direct source payload projection",
            )?;
            ensure(
                materialized.sha256() == l2_workbench::sha256(&expected_payloads).as_str(),
                "compiled candidate digest differs from direct source payload projection",
            )?;
            let receipt = bound
                .group_receipt(model_index, group_index)
                .map_err(|error| format!("compiled receipt could not be produced: {error}"))?;
            ensure(
                &receipt == expected_group.receipt(),
                "compiled receipt differs from the reference receipt",
            )?;
            for part in &receipt.parts {
                let global_index = plan
                    .model_input_global_index(model_index, part.input_index)
                    .ok_or_else(|| "model input index has no global mapping".to_owned())?;
                ensure(
                    order.get(part.input_index).copied() == Some(global_index),
                    "model input global mapping differs from the declared order",
                )?;
            }
        }
    }
    Ok(())
}

fn project_source_payloads(
    frames: &[Vec<u8>],
    order: &[usize],
    parts: &[RecordAssemblyPart],
) -> Result<Vec<u8>, String> {
    let mut expected = Vec::new();
    for part in parts {
        let global_index = order
            .get(part.input_index)
            .ok_or_else(|| "receipt input index is outside the generated model order".to_owned())?;
        let frame = frames
            .get(*global_index)
            .ok_or_else(|| "receipt input index maps to a missing generated frame".to_owned())?;
        let payload = frame
            .get(HEADER_LENGTH..)
            .ok_or_else(|| "generated frame is shorter than its fixed header".to_owned())?;
        expected.extend_from_slice(payload);
    }
    Ok(expected)
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn byte_at(input: &[u8], offset: usize) -> u8 {
    input.get(offset).copied().unwrap_or_default()
}
