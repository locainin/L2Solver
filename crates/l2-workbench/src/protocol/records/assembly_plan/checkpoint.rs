//! Rebuild compiled assembly layouts from bounded preserved-header descriptions

use super::{
    CompiledInput, CompiledModel, HeaderParseTemplate, RecordAssemblyHeaderModel,
    RecordAssemblyPlan, RecordError, SharedInputExpectation,
};
use crate::protocol::{ParsedRecord, RecordLimits, RecordSchema};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeSeq};
use std::mem;

const VERSION: u32 = 2;

/// Canonical preserved headers used to reconstruct a compiled record assembly plan
///
/// The description does not contain decoded payloads or live indexes. Bound serialized input
/// and admit its decoded memory before deserializing an untrusted checkpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordAssemblyPlanDescription {
    version: u32,
    limits: RecordLimits,
    inputs: Vec<InputDescription>,
    models: Vec<ModelDescription>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDescription {
    index: usize,
    input_length: usize,
    header: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelDescription {
    schema: RecordSchema,
    limits: RecordLimits,
    inputs: Vec<ModelInputDescription>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelInputDescription {
    shared_index: usize,
    header_length: usize,
}

#[derive(Serialize)]
struct DescriptionRef<'a> {
    version: u32,
    limits: RecordLimits,
    inputs: InputRefs<'a>,
    models: ModelRefs<'a>,
}

struct InputRefs<'a>(&'a [SharedInputExpectation]);

impl Serialize for InputRefs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct InputRef<'a> {
            index: usize,
            input_length: usize,
            header: &'a [u8],
        }

        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for input in self.0 {
            sequence.serialize_element(&InputRef {
                index: input.global_input_index,
                input_length: input.length,
                header: &input.preserved_prefix,
            })?;
        }
        sequence.end()
    }
}

struct ModelRefs<'a>(&'a [CompiledModel]);

impl Serialize for ModelRefs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct ModelRef<'a> {
            schema: &'a RecordSchema,
            limits: RecordLimits,
            inputs: ModelInputRefs<'a>,
        }

        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for model in self.0 {
            sequence.serialize_element(&ModelRef {
                schema: &model.schema,
                limits: model.limits,
                inputs: ModelInputRefs(&model.inputs),
            })?;
        }
        sequence.end()
    }
}

struct ModelInputRefs<'a>(&'a [CompiledInput]);

impl Serialize for ModelInputRefs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct ModelInputRef {
            shared_index: usize,
            header_length: usize,
        }

        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for input in self.0 {
            sequence.serialize_element(&ModelInputRef {
                shared_index: input.shared_input_index,
                header_length: input.expected_prefix_length,
            })?;
        }
        sequence.end()
    }
}

impl RecordAssemblyPlan {
    /// Describe the canonical headers needed to rebuild this plan under the supplied limits
    ///
    /// `maximum_description_bytes` rejects descriptions whose minimum decoded size exceeds the
    /// bound. Restoration also checks actual decoded capacities. The limits supplied here are
    /// the policy ceiling for every model. The returned view borrows the compiled plan without
    /// rebuilding or copying its preserved headers
    ///
    /// # Errors
    /// Returns an error if limits, retained metadata, or allocation bounds are invalid
    pub fn checkpoint_description(
        &self,
        limits: RecordLimits,
        maximum_description_bytes: usize,
    ) -> Result<impl Serialize + '_, RecordError> {
        super::validate_assembly_limits(limits)?;
        let needed = description_minimum_size(self)?;
        check_size(needed, maximum_description_bytes)?;
        for model in &self.models {
            // Preserve the exact limits that shaped each compiled model's receipts
            if !within_ceiling(model.limits, limits) {
                return Err(RecordError::InvalidReport);
            }
            for input in &model.inputs {
                let shared = self
                    .inputs
                    .get(input.shared_input_index)
                    .filter(|shared| shared.global_input_index == input.global_input_index)
                    .ok_or(RecordError::InvalidReport)?;
                if input.expected_prefix_length > shared.preserved_prefix.len() {
                    return Err(RecordError::InvalidReport);
                }
            }
        }
        Ok(DescriptionRef {
            version: VERSION,
            limits,
            inputs: InputRefs(&self.inputs),
            models: ModelRefs(&self.models),
        })
    }
}

impl RecordAssemblyPlanDescription {
    /// Check that every saved input length and preserved header matches the frozen source
    ///
    /// Input order uses the global indices supplied to the original assembly models.
    /// Payload bytes after each saved header are not compared.
    /// The control checks cancellation and reserves work before each bounded operation
    ///
    /// # Errors
    /// Returns an error when a referenced input changed or the control rejects further work
    pub fn validate_inputs(
        &self,
        inputs: &[&[u8]],
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<(), RecordError> {
        if self.version != VERSION {
            return Err(RecordError::InvalidReport);
        }
        for saved in &self.inputs {
            control(mem::size_of::<InputDescription>())?;
            let bytes = inputs.get(saved.index).ok_or(RecordError::InvalidReport)?;
            if bytes.len() != saved.input_length {
                return Err(RecordError::InvalidReport);
            }
            compare_header(bytes, &saved.header, control)?;
        }
        Ok(())
    }

    /// Rebuild the compiled plan after validating the saved headers and current limits
    ///
    /// `maximum_description_bytes` bounds retained descriptor allocations, and
    /// `maximum_plan_bytes` bounds reconstruction and compilation workspace.
    /// The workspace uses the compiler's logical accounting, which excludes allocator metadata
    /// and allocation capacity beyond requested entries.
    /// The control checks cancellation and reserves work before each bounded operation
    ///
    /// # Errors
    /// Returns an error for an incompatible description, invalid header, or exceeded bound.
    pub fn restore(
        &self,
        expected_limits: RecordLimits,
        maximum_description_bytes: usize,
        maximum_plan_bytes: usize,
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<RecordAssemblyPlan, RecordError> {
        if self.version != VERSION || self.limits != expected_limits {
            return Err(RecordError::InvalidReport);
        }
        super::validate_assembly_limits(expected_limits)?;
        self.check_size(maximum_description_bytes, control)?;
        for model in &self.models {
            control(mem::size_of::<ModelDescription>())?;
            if !within_ceiling(model.limits, expected_limits) {
                return Err(RecordError::InvalidReport);
            }
        }
        let reconstruction_bytes = self.reconstruction_size(control)?;
        if reconstruction_bytes > maximum_plan_bytes {
            return Err(RecordError::PlanTooLarge {
                bytes: reconstruction_bytes,
                maximum: maximum_plan_bytes,
            });
        }
        let models = self.rebuild_models(control)?;
        // The remaining models stay live while the compiler builds shared layouts
        let compilation_budget = maximum_plan_bytes - reconstruction_bytes;
        let plan = RecordAssemblyPlan::compile_header_models_controlled(
            models,
            compilation_budget,
            Some(control),
        )
        .map_err(|error| match error {
            RecordError::PlanTooLarge { bytes, .. } => RecordError::PlanTooLarge {
                bytes: bytes.saturating_add(reconstruction_bytes),
                maximum: maximum_plan_bytes,
            },
            other => other,
        })?;
        if plan.inputs.len() != self.inputs.len() {
            return Err(RecordError::InvalidReport);
        }
        for (actual, saved) in plan.inputs.iter().zip(&self.inputs) {
            control(mem::size_of::<InputDescription>())?;
            if actual.global_input_index != saved.index || actual.length != saved.input_length {
                return Err(RecordError::InvalidReport);
            }
            if actual.preserved_prefix.len() != saved.header.len() {
                return Err(RecordError::InvalidReport);
            }
            compare_header(&actual.preserved_prefix, &saved.header, control)?;
        }
        Ok(plan)
    }

    fn rebuild_models(
        &self,
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<Vec<RecordAssemblyHeaderModel>, RecordError> {
        let mut models = Vec::new();
        models
            .try_reserve_exact(self.models.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        for model in &self.models {
            control(mem::size_of::<ModelDescription>())?;
            let mut templates = Vec::new();
            templates
                .try_reserve_exact(model.inputs.len())
                .map_err(|_| RecordError::AllocationFailed)?;
            for input in &model.inputs {
                control(mem::size_of::<ModelInputDescription>())?;
                let saved = self
                    .inputs
                    .get(input.shared_index)
                    .ok_or(RecordError::InvalidReport)?;
                let prefix = saved
                    .header
                    .get(..input.header_length)
                    .ok_or(RecordError::InvalidReport)?;
                let mut header = Vec::new();
                header
                    .try_reserve_exact(prefix.len())
                    .map_err(|_| RecordError::AllocationFailed)?;
                for chunk in prefix.chunks(64 * 1024) {
                    control(chunk.len())?;
                    header.extend_from_slice(chunk);
                }
                let template = HeaderParseTemplate::from_header_checkpoint(
                    model.schema.clone(),
                    model.limits,
                    saved.input_length,
                    header,
                )?;
                templates.push((saved.index, template));
            }
            models.push(RecordAssemblyHeaderModel::new(
                model.schema.clone(),
                model.limits,
                templates,
            ));
        }
        Ok(models)
    }

    fn check_size(
        &self,
        maximum: usize,
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<(), RecordError> {
        check_size(self.logical_size(control)?, maximum)
    }

    fn logical_size(
        &self,
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<usize, RecordError> {
        let mut total = mem::size_of::<Self>();
        total = add_array(
            total,
            self.inputs.capacity(),
            mem::size_of::<InputDescription>(),
        )?;
        total = add_array(
            total,
            self.models.capacity(),
            mem::size_of::<ModelDescription>(),
        )?;
        for input in &self.inputs {
            control(mem::size_of::<InputDescription>())?;
            total = total
                .checked_add(input.header.capacity())
                .ok_or(RecordError::InvalidReport)?;
        }
        for model in &self.models {
            control(mem::size_of::<ModelDescription>())?;
            total = add_array(
                total,
                model.inputs.capacity(),
                mem::size_of::<ModelInputDescription>(),
            )?;
        }
        Ok(total)
    }

    fn reconstruction_size(
        &self,
        control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
    ) -> Result<usize, RecordError> {
        let mut total = add_array(
            0,
            self.models.len(),
            mem::size_of::<RecordAssemblyHeaderModel>(),
        )?;
        for model in &self.models {
            control(mem::size_of::<ModelDescription>())?;
            let per_input = mem::size_of::<(usize, HeaderParseTemplate)>()
                .checked_add(mem::size_of::<ParsedRecord>())
                .and_then(|bytes| bytes.checked_add(model.schema.identifier.width))
                .ok_or(RecordError::InvalidReport)?;
            total = add_array(total, model.inputs.len(), per_input)?;
            for input in &model.inputs {
                control(mem::size_of::<ModelInputDescription>())?;
                let shared = self
                    .inputs
                    .get(input.shared_index)
                    .ok_or(RecordError::InvalidReport)?;
                if input.header_length > shared.header.len() {
                    return Err(RecordError::InvalidReport);
                }
                total = total
                    .checked_add(input.header_length)
                    .ok_or(RecordError::InvalidReport)?;
            }
        }
        Ok(total)
    }
}

fn compare_header(
    input: &[u8],
    header: &[u8],
    control: &mut dyn FnMut(usize) -> Result<(), RecordError>,
) -> Result<(), RecordError> {
    let prefix = input
        .get(..header.len())
        .ok_or(RecordError::InvalidReport)?;
    for (actual, expected) in prefix.chunks(64 * 1024).zip(header.chunks(64 * 1024)) {
        control(expected.len())?;
        if actual != expected {
            return Err(RecordError::InvalidReport);
        }
    }
    Ok(())
}

const fn within_ceiling(limits: RecordLimits, ceiling: RecordLimits) -> bool {
    limits.max_input_bytes <= ceiling.max_input_bytes
        && limits.max_records <= ceiling.max_records
        && limits.max_identifier_bytes <= ceiling.max_identifier_bytes
        && limits.max_report_bytes <= ceiling.max_report_bytes
        && limits.max_groups <= ceiling.max_groups
        && limits.max_output_bytes <= ceiling.max_output_bytes
        && limits.max_issue_examples <= ceiling.max_issue_examples
}

fn description_minimum_size(plan: &RecordAssemblyPlan) -> Result<usize, RecordError> {
    let mut total = mem::size_of::<RecordAssemblyPlanDescription>();
    total = add_array(total, plan.inputs.len(), mem::size_of::<InputDescription>())?;
    total = add_array(total, plan.models.len(), mem::size_of::<ModelDescription>())?;
    for input in &plan.inputs {
        total = total
            .checked_add(input.preserved_prefix.len())
            .ok_or(RecordError::InvalidReport)?;
    }
    for model in &plan.models {
        total = add_array(
            total,
            model.inputs.len(),
            mem::size_of::<ModelInputDescription>(),
        )?;
    }
    Ok(total)
}

fn add_array(total: usize, count: usize, item_bytes: usize) -> Result<usize, RecordError> {
    count
        .checked_mul(item_bytes)
        .and_then(|bytes| total.checked_add(bytes))
        .ok_or(RecordError::InvalidReport)
}

const fn check_size(bytes: usize, maximum: usize) -> Result<(), RecordError> {
    if bytes > maximum {
        Err(RecordError::ReportTooLarge { bytes, maximum })
    } else {
        Ok(())
    }
}
