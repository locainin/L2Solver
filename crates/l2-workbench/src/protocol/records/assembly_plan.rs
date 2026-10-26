use super::{
    HeaderParseTemplate, RecordError, RecordGroupReceipt, RecordInput, RecordLimits, RecordSchema,
    assemble::{
        AssemblyPlanBudget, PhysicalPart, PreparedGroup, RecordMetadataInput,
        finish_receipt_identity, materialize_layout, prepare_record_groups,
    },
    parse::{validate_assembly_limits, validate_schema},
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
};

/// Header-derived parse templates for one semantic record interpretation
pub struct RecordAssemblyHeaderModel {
    schema: RecordSchema,
    limits: RecordLimits,
    templates: Vec<(usize, HeaderParseTemplate)>,
}

impl RecordAssemblyHeaderModel {
    /// Create a model from canonical header templates keyed by global cohort input index
    ///
    /// Template order defines this model's local input order and sequence tie order
    #[must_use]
    pub const fn new(
        schema: RecordSchema,
        limits: RecordLimits,
        templates: Vec<(usize, HeaderParseTemplate)>,
    ) -> Self {
        Self {
            schema,
            limits,
            templates,
        }
    }
}

impl fmt::Debug for RecordAssemblyHeaderModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordAssemblyHeaderModel")
            .field("schema", &self.schema)
            .field("limits", &self.limits)
            .field("template_count", &self.templates.len())
            .finish()
    }
}

/// Status of one model after candidate headers and lengths are checked
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecordAssemblyModelStatus {
    /// Every source frame matches the model's prepared input boundary
    Ready,
    /// A source frame length differs from the immutable prepared length
    InputLengthMismatch {
        /// Global cohort input index with the changed length
        input_index: usize,
    },
    /// A source frame differs inside bytes used by the model's parsed header
    PreservedHeaderMismatch {
        /// Global cohort input index with the changed header
        input_index: usize,
    },
}

/// Bounded work performed while compiling a shared physical assembly plan
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordAssemblyPlanStats {
    /// Semantic record interpretations compiled
    pub models: usize,
    /// Semantic groups across all interpretations
    pub groups: usize,
    /// Distinct ordered payload-range recipes
    pub layouts: usize,
    /// Groups that reuse a layout already compiled for an earlier interpretation
    pub layout_reuses: usize,
    /// Conservative logical memory retained by the compiled plan
    pub retained_bytes: usize,
}

/// Work performed while binding and lazily materializing one candidate
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordAssemblyBindStats {
    /// Preserved header bytes compared once for each referenced global cohort input
    pub prefix_bytes_checked: usize,
    /// Unique global input length and prefix checks performed
    pub shared_input_checks: usize,
    /// Per-model input checks needed after a shared input mismatch
    pub model_input_checks: usize,
    /// Model group references checked while exposing ready physical layouts
    pub layout_membership_checks: usize,
    /// Distinct physical layouts materialized so far
    pub materialized_layouts: usize,
    /// Payload bytes copied by materialization calls
    pub materialized_bytes: usize,
    /// Payload bytes hashed by materialization calls
    pub hashed_bytes: usize,
}

/// Immutable semantic models and their deduplicated physical payload layouts
pub struct RecordAssemblyPlan {
    input_count: usize,
    inputs: Vec<SharedInputExpectation>,
    models: Vec<CompiledModel>,
    layouts: Vec<PhysicalLayout>,
    stats: RecordAssemblyPlanStats,
}

impl fmt::Debug for RecordAssemblyPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordAssemblyPlan")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SharedInputExpectation {
    global_input_index: usize,
    length: usize,
    preserved_prefix: Vec<u8>,
}

#[derive(Debug)]
struct CompiledInput {
    global_input_index: usize,
    shared_input_index: usize,
    expected_prefix_length: usize,
}

#[derive(Clone, Copy)]
enum SharedInputMismatch {
    Length,
    Prefix { offset: usize },
}

#[derive(Debug)]
struct CompiledModel {
    schema: RecordSchema,
    inputs: Vec<CompiledInput>,
    groups: Vec<CompiledGroup>,
}

#[derive(Debug)]
struct CompiledGroup {
    receipt: RecordGroupReceipt,
    layout_id: usize,
}

#[derive(Debug)]
struct PhysicalLayout {
    parts: Vec<PhysicalPart>,
    output_length: usize,
}

impl RecordAssemblyPlan {
    /// Compile header-derived models once and share equal byte layouts across them
    ///
    /// Models may use different ordered subsets of the cohort inputs. Each template index is
    /// global, while its order in the model defines local sequence tie order
    ///
    /// `maximum_retained_bytes` bounds both the compiled plan and temporary compilation
    /// workspace, so a model is rejected before its preparation allocations exceed the cap
    /// Workspace accounting estimates logical entries and buffers, excluding allocator metadata
    /// and capacity slack
    ///
    /// # Errors
    /// Rejects inconsistent input membership, templates, schemas, limits, or resource bounds
    pub fn compile_header_models(
        models: Vec<RecordAssemblyHeaderModel>,
        maximum_retained_bytes: usize,
    ) -> Result<Self, RecordError> {
        let input_count = cohort_input_count(&models)?;
        let mut compiler = PlanCompiler::new(models.len(), maximum_retained_bytes);
        for model in models {
            compiler.add_model(model)?;
        }
        Ok(compiler.finish(input_count))
    }

    /// Return the number of semantic interpretations in the plan
    #[must_use]
    pub const fn model_count(&self) -> usize {
        self.models.len()
    }

    /// Return the number of distinct physical payload layouts
    #[must_use]
    pub const fn layout_count(&self) -> usize {
        self.layouts.len()
    }

    /// Return plan compilation and retained-memory counters
    #[must_use]
    pub const fn stats(&self) -> &RecordAssemblyPlanStats {
        &self.stats
    }

    /// Return the schema associated with one semantic model
    #[must_use]
    pub fn model_schema(&self, model_index: usize) -> Option<&RecordSchema> {
        self.models.get(model_index).map(|model| &model.schema)
    }

    /// Return a model-local input's global cohort index
    ///
    /// The local index follows the template order used to prepare receipt parts and sequence
    /// ties; it may differ from global cohort order
    #[must_use]
    pub fn model_input_global_index(
        &self,
        model_index: usize,
        local_input_index: usize,
    ) -> Option<usize> {
        self.models
            .get(model_index)?
            .inputs
            .get(local_input_index)
            .map(|input| input.global_input_index)
    }

    /// Return a conservative logical size for bounded cache accounting
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.stats.retained_bytes
    }

    /// Check candidate input lengths and frozen header bytes once before any layout is copied
    ///
    /// # Errors
    /// Rejects a cohort too short to contain a referenced global index or allocation failure;
    /// model-specific mismatches are returned as status and do not invalidate other models
    pub fn bind<'plan, 'input>(
        &'plan self,
        inputs: &'plan [RecordInput<'input>],
    ) -> Result<BoundRecordAssemblyPlan<'plan, 'input>, RecordError> {
        if inputs.len() < self.input_count {
            return Err(RecordError::InvalidReport);
        }
        let mut stats = RecordAssemblyBindStats::default();
        let input_checks = check_shared_inputs(&self.inputs, inputs)?;
        stats.shared_input_checks = input_checks.checks;
        stats.prefix_bytes_checked = input_checks.prefix_bytes_checked;
        let (model_statuses, model_input_checks) = resolve_model_statuses(
            &self.models,
            &self.inputs,
            &input_checks.mismatches,
            input_checks.all_match,
        )?;
        stats.model_input_checks = model_input_checks;
        let (available_layouts, layout_membership_checks) = ready_layouts(
            &self.models,
            &model_statuses,
            self.layouts.len(),
            input_checks.all_match,
        )?;
        stats.layout_membership_checks = layout_membership_checks;
        let mut layout_digests = Vec::new();
        layout_digests
            .try_reserve_exact(self.layouts.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        layout_digests.resize_with(self.layouts.len(), || None);
        Ok(BoundRecordAssemblyPlan {
            plan: self,
            inputs,
            model_statuses,
            available_layouts,
            layout_digests,
            stats,
        })
    }
}

fn cohort_input_count(models: &[RecordAssemblyHeaderModel]) -> Result<usize, RecordError> {
    models
        .iter()
        .flat_map(|model| model.templates.iter().map(|(index, _)| *index))
        .max()
        .and_then(|index| index.checked_add(1))
        .ok_or(RecordError::InvalidReport)
}

struct SharedInputChecks {
    mismatches: Vec<Option<SharedInputMismatch>>,
    prefix_bytes_checked: usize,
    checks: usize,
    all_match: bool,
}

fn check_shared_inputs(
    expectations: &[SharedInputExpectation],
    inputs: &[RecordInput<'_>],
) -> Result<SharedInputChecks, RecordError> {
    let mut mismatches = Vec::new();
    mismatches
        .try_reserve_exact(expectations.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut prefix_bytes_checked = 0_usize;
    let mut all_match = true;
    for expected in expectations {
        let input = inputs
            .get(expected.global_input_index)
            .ok_or(RecordError::InvalidReport)?;
        let mismatch = if input.bytes.len() == expected.length {
            let actual_prefix = input
                .bytes
                .get(..expected.preserved_prefix.len())
                .ok_or(RecordError::InvalidReport)?;
            let mismatch = expected
                .preserved_prefix
                .iter()
                .zip(actual_prefix)
                .position(|(expected_byte, actual_byte)| expected_byte != actual_byte);
            let checked_bytes = mismatch.map_or(expected.preserved_prefix.len(), |offset| {
                offset.saturating_add(1)
            });
            prefix_bytes_checked = prefix_bytes_checked.saturating_add(checked_bytes);
            mismatch.map(|offset| SharedInputMismatch::Prefix { offset })
        } else {
            Some(SharedInputMismatch::Length)
        };
        all_match &= mismatch.is_none();
        mismatches.push(mismatch);
    }
    Ok(SharedInputChecks {
        mismatches,
        prefix_bytes_checked,
        checks: expectations.len(),
        all_match,
    })
}

fn resolve_model_statuses(
    models: &[CompiledModel],
    shared_inputs: &[SharedInputExpectation],
    mismatches: &[Option<SharedInputMismatch>],
    all_inputs_match: bool,
) -> Result<(Vec<RecordAssemblyModelStatus>, usize), RecordError> {
    let mut statuses = Vec::new();
    statuses
        .try_reserve_exact(models.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut input_checks = 0_usize;
    for model in models {
        let (status, checks) = if all_inputs_match {
            (RecordAssemblyModelStatus::Ready, 0)
        } else {
            model_status(model, shared_inputs, mismatches)?
        };
        input_checks = input_checks.saturating_add(checks);
        statuses.push(status);
    }
    Ok((statuses, input_checks))
}

fn ready_layouts(
    models: &[CompiledModel],
    statuses: &[RecordAssemblyModelStatus],
    layout_count: usize,
    all_inputs_match: bool,
) -> Result<(Vec<bool>, usize), RecordError> {
    let mut available = Vec::new();
    available
        .try_reserve_exact(layout_count)
        .map_err(|_| RecordError::AllocationFailed)?;
    available.resize(layout_count, all_inputs_match);
    if all_inputs_match {
        return Ok((available, 0));
    }

    let mut membership_checks = 0_usize;
    for (model, status) in models.iter().zip(statuses) {
        if *status != RecordAssemblyModelStatus::Ready {
            continue;
        }
        for group in &model.groups {
            membership_checks = membership_checks.saturating_add(1);
            let Some(is_available) = available.get_mut(group.layout_id) else {
                return Err(RecordError::InvalidReport);
            };
            *is_available = true;
        }
    }
    Ok((available, membership_checks))
}

const fn minimum_model_bytes(input_count: usize) -> usize {
    std::mem::size_of::<CompiledModel>()
        .saturating_add(input_count.saturating_mul(std::mem::size_of::<CompiledInput>()))
}

struct PlanCompiler {
    maximum_retained_bytes: usize,
    compiler_workspace_bytes: usize,
    shared_inputs: Vec<SharedInputExpectation>,
    compiled_models: Vec<CompiledModel>,
    layouts: Vec<PhysicalLayout>,
    layout_buckets: HashMap<u64, Vec<usize>>,
    shared_input_lookup: HashMap<usize, usize>,
    stats: RecordAssemblyPlanStats,
}

impl PlanCompiler {
    fn new(model_count: usize, maximum_retained_bytes: usize) -> Self {
        Self {
            maximum_retained_bytes,
            compiler_workspace_bytes: 0,
            shared_inputs: Vec::new(),
            compiled_models: Vec::new(),
            layouts: Vec::new(),
            layout_buckets: HashMap::new(),
            shared_input_lookup: HashMap::new(),
            stats: RecordAssemblyPlanStats {
                models: model_count,
                ..RecordAssemblyPlanStats::default()
            },
        }
    }

    fn add_model(&mut self, model: RecordAssemblyHeaderModel) -> Result<(), RecordError> {
        let RecordAssemblyHeaderModel {
            schema,
            limits,
            templates,
        } = model;
        validate_assembly_limits(limits)?;
        validate_schema(&schema, limits)?;
        let base_bytes = self
            .current_retained_bytes()
            .saturating_add(self.compiler_workspace_bytes)
            .saturating_add(minimum_model_bytes(templates.len()));
        let mut budget = AssemblyPlanBudget::new(base_bytes, self.maximum_retained_bytes)?;
        let frames = indexed_templates(&schema, limits, templates, &mut budget)?;
        update_shared_expectations(
            &mut self.shared_inputs,
            &mut self.shared_input_lookup,
            &frames,
            &mut budget,
            &mut self.compiler_workspace_bytes,
        )?;

        let prepared = prepare_model_groups(
            &frames,
            schema.sequence_base,
            schema.terminal_sequence,
            limits,
            &mut budget,
        )?;
        let compiled_inputs = compile_inputs(&frames, &self.shared_input_lookup)?;
        let compiled_groups = self.compile_groups(prepared.groups, &frames, &mut budget)?;
        self.compiled_models
            .try_reserve(1)
            .map_err(|_| RecordError::AllocationFailed)?;
        self.compiled_models.push(CompiledModel {
            schema,
            inputs: compiled_inputs,
            groups: compiled_groups,
        });
        Ok(())
    }

    fn compile_groups(
        &mut self,
        groups: Vec<PreparedGroup>,
        frames: &[IndexedTemplate],
        budget: &mut AssemblyPlanBudget,
    ) -> Result<Vec<CompiledGroup>, RecordError> {
        let compiled_group_bytes = std::mem::size_of::<CompiledGroup>()
            .checked_mul(groups.len())
            .ok_or_else(|| budget.overflow_error())?;
        budget.charge_workspace(compiled_group_bytes)?;
        let mut compiled = Vec::new();
        compiled
            .try_reserve_exact(groups.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        for group in groups {
            let PreparedGroup {
                receipt,
                layout,
                output_length,
            } = group;
            let layout = globalize_layout(layout, frames)?;
            let layout_id = intern_layout(
                layout,
                output_length,
                &mut self.layouts,
                &mut self.layout_buckets,
                &mut self.stats.layout_reuses,
                budget,
                &mut self.compiler_workspace_bytes,
            )?;
            compiled.push(CompiledGroup { receipt, layout_id });
            self.stats.groups = self.stats.groups.saturating_add(1);
        }
        Ok(compiled)
    }

    fn current_retained_bytes(&self) -> usize {
        retained_plan_bytes(&self.shared_inputs, &self.compiled_models, &self.layouts)
    }

    fn finish(mut self, input_count: usize) -> RecordAssemblyPlan {
        self.stats.layouts = self.layouts.len();
        self.stats.retained_bytes = self.current_retained_bytes();
        RecordAssemblyPlan {
            input_count,
            inputs: self.shared_inputs,
            models: self.compiled_models,
            layouts: self.layouts,
            stats: self.stats,
        }
    }
}

fn compile_inputs(
    frames: &[IndexedTemplate],
    shared_input_lookup: &HashMap<usize, usize>,
) -> Result<Vec<CompiledInput>, RecordError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(frames.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for frame in frames {
        let shared_input_index = shared_input_lookup
            .get(&frame.global_input_index)
            .copied()
            .ok_or(RecordError::InvalidReport)?;
        inputs.push(CompiledInput {
            global_input_index: frame.global_input_index,
            shared_input_index,
            expected_prefix_length: frame.preserved_header.len(),
        });
    }
    Ok(inputs)
}

struct IndexedTemplate {
    global_input_index: usize,
    input_length: usize,
    preserved_header: Vec<u8>,
    records: Vec<super::ParsedRecord>,
}

fn prepare_model_groups(
    frames: &[IndexedTemplate],
    sequence_base: u64,
    terminal_sequence: Option<u64>,
    limits: RecordLimits,
    budget: &mut AssemblyPlanBudget,
) -> Result<super::assemble::PreparedRecordGroups, RecordError> {
    let metadata_workspace = std::mem::size_of::<RecordMetadataInput<'_>>()
        .checked_mul(frames.len())
        .ok_or_else(|| budget.overflow_error())?;
    budget.charge_workspace(metadata_workspace)?;
    let mut metadata_inputs = Vec::new();
    metadata_inputs
        .try_reserve_exact(frames.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    metadata_inputs.extend(frames.iter().enumerate().map(|(input_index, frame)| {
        RecordMetadataInput {
            input_index,
            input_length: frame.input_length,
            records: &frame.records,
        }
    }));
    let prepared = prepare_record_groups(
        &metadata_inputs,
        sequence_base,
        terminal_sequence,
        limits,
        budget,
    );
    drop(metadata_inputs);
    budget.release_workspace(metadata_workspace);
    prepared
}

fn indexed_templates(
    schema: &RecordSchema,
    limits: RecordLimits,
    templates: Vec<(usize, HeaderParseTemplate)>,
    budget: &mut AssemblyPlanBudget,
) -> Result<Vec<IndexedTemplate>, RecordError> {
    if templates.is_empty() {
        return Err(RecordError::InvalidReport);
    }
    let frame_storage = std::mem::size_of::<IndexedTemplate>()
        .checked_mul(templates.len())
        .ok_or_else(|| budget.overflow_error())?;
    let seen_input_storage = std::mem::size_of::<usize>()
        .checked_mul(templates.len())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| budget.overflow_error())?;
    let indexed_workspace = frame_storage
        .checked_add(seen_input_storage)
        .ok_or_else(|| budget.overflow_error())?;
    budget.charge_workspace(indexed_workspace)?;
    let mut seen_inputs = HashSet::new();
    seen_inputs
        .try_reserve(templates.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(templates.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for (input_index, template) in templates {
        if !seen_inputs.insert(input_index) {
            return Err(RecordError::InvalidReport);
        }
        let parts = template.into_parts();
        if parts.schema != *schema || parts.limits != limits {
            return Err(RecordError::InvalidReport);
        }
        frames.push(IndexedTemplate {
            global_input_index: input_index,
            input_length: parts.input_length,
            preserved_header: parts.preserved_header,
            records: parts.records,
        });
    }
    budget.release_workspace(seen_input_storage);
    Ok(frames)
}

fn update_shared_expectations(
    shared: &mut Vec<SharedInputExpectation>,
    shared_lookup: &mut HashMap<usize, usize>,
    frames: &[IndexedTemplate],
    budget: &mut AssemblyPlanBudget,
    compiler_workspace_bytes: &mut usize,
) -> Result<(), RecordError> {
    for frame in frames {
        let global_index = frame.global_input_index;
        if let Some(shared_index) = shared_lookup.get(&global_index).copied() {
            let expected = shared
                .get_mut(shared_index)
                .ok_or(RecordError::InvalidReport)?;
            if expected.length != frame.input_length {
                return Err(RecordError::InvalidReport);
            }
            let common_length = expected
                .preserved_prefix
                .len()
                .min(frame.preserved_header.len());
            if expected.preserved_prefix.get(..common_length)
                != frame.preserved_header.get(..common_length)
            {
                return Err(RecordError::InvalidReport);
            }
            if frame.preserved_header.len() > expected.preserved_prefix.len() {
                let additional = frame
                    .preserved_header
                    .len()
                    .saturating_sub(expected.preserved_prefix.len());
                budget.charge_workspace(frame.preserved_header.len())?;
                expected.preserved_prefix = try_clone_bytes(&frame.preserved_header)?;
                budget.release_workspace(frame.preserved_header.len());
                budget.retain(additional)?;
            }
        } else {
            let additional = std::mem::size_of::<SharedInputExpectation>()
                .saturating_add(frame.preserved_header.len());
            // The map remains live across models, so charge it before reserving an entry
            let lookup_workspace = std::mem::size_of::<(usize, usize)>()
                .saturating_add(4_usize.saturating_mul(std::mem::size_of::<usize>()));
            budget.retain(additional)?;
            budget.charge_workspace(lookup_workspace)?;
            shared
                .try_reserve(1)
                .map_err(|_| RecordError::AllocationFailed)?;
            shared_lookup
                .try_reserve(1)
                .map_err(|_| RecordError::AllocationFailed)?;
            *compiler_workspace_bytes =
                (*compiler_workspace_bytes).saturating_add(lookup_workspace);
            let shared_index = shared.len();
            shared.push(SharedInputExpectation {
                global_input_index: global_index,
                length: frame.input_length,
                preserved_prefix: try_clone_bytes(&frame.preserved_header)?,
            });
            if shared_lookup.insert(global_index, shared_index).is_some() {
                return Err(RecordError::InvalidReport);
            }
        }
    }
    Ok(())
}

fn globalize_layout(
    mut layout: Vec<PhysicalPart>,
    frames: &[IndexedTemplate],
) -> Result<Vec<PhysicalPart>, RecordError> {
    for part in &mut layout {
        part.input_index = frames
            .get(part.input_index)
            .ok_or(RecordError::InvalidReport)?
            .global_input_index;
    }
    Ok(layout)
}

fn intern_layout(
    parts: Vec<PhysicalPart>,
    output_length: usize,
    layouts: &mut Vec<PhysicalLayout>,
    buckets: &mut HashMap<u64, Vec<usize>>,
    layout_reuses: &mut usize,
    budget: &mut AssemblyPlanBudget,
    compiler_workspace_bytes: &mut usize,
) -> Result<usize, RecordError> {
    let hash = layout_hash(&parts);
    if let Some(layout_ids) = buckets.get(&hash)
        && let Some(layout_id) = layout_ids.iter().copied().find(|layout_id| {
            layouts
                .get(*layout_id)
                .is_some_and(|layout| layout.parts == parts)
        })
    {
        *layout_reuses = layout_reuses.saturating_add(1);
        return Ok(layout_id);
    }
    let layout_id = layouts.len();
    let new_bucket = !buckets.contains_key(&hash);
    let bucket_workspace_bytes = std::mem::size_of::<usize>().saturating_add(if new_bucket {
        std::mem::size_of::<(u64, Vec<usize>)>()
            .saturating_add(4_usize.saturating_mul(std::mem::size_of::<usize>()))
    } else {
        0
    });
    // The layout enters the final plan; the bucket storage stays in the compiler
    let bucket_bytes = std::mem::size_of::<PhysicalLayout>().saturating_add(bucket_workspace_bytes);
    budget.charge_workspace(bucket_bytes)?;
    if new_bucket {
        buckets
            .try_reserve(1)
            .map_err(|_| RecordError::AllocationFailed)?;
    }
    let bucket = buckets.entry(hash).or_default();
    bucket
        .try_reserve(1)
        .map_err(|_| RecordError::AllocationFailed)?;
    layouts
        .try_reserve(1)
        .map_err(|_| RecordError::AllocationFailed)?;
    bucket.push(layout_id);
    layouts.push(PhysicalLayout {
        parts,
        output_length,
    });
    *compiler_workspace_bytes = (*compiler_workspace_bytes).saturating_add(bucket_workspace_bytes);
    Ok(layout_id)
}

fn layout_hash(layout: &[PhysicalPart]) -> u64 {
    let mut hasher = DefaultHasher::new();
    layout.hash(&mut hasher);
    hasher.finish()
}

fn try_clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, RecordError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn model_status(
    model: &CompiledModel,
    shared_inputs: &[SharedInputExpectation],
    input_mismatches: &[Option<SharedInputMismatch>],
) -> Result<(RecordAssemblyModelStatus, usize), RecordError> {
    let mut checks = 0_usize;
    for compiled in &model.inputs {
        checks = checks.saturating_add(1);
        shared_inputs
            .get(compiled.shared_input_index)
            .ok_or(RecordError::InvalidReport)?;
        let mismatch = input_mismatches
            .get(compiled.shared_input_index)
            .ok_or(RecordError::InvalidReport)?;
        match mismatch {
            Some(SharedInputMismatch::Length) => {
                return Ok((
                    RecordAssemblyModelStatus::InputLengthMismatch {
                        input_index: compiled.global_input_index,
                    },
                    checks,
                ));
            }
            Some(SharedInputMismatch::Prefix { offset })
                if *offset < compiled.expected_prefix_length =>
            {
                return Ok((
                    RecordAssemblyModelStatus::PreservedHeaderMismatch {
                        input_index: compiled.global_input_index,
                    },
                    checks,
                ));
            }
            None | Some(SharedInputMismatch::Prefix { .. }) => {}
        }
    }
    Ok((RecordAssemblyModelStatus::Ready, checks))
}

fn retained_plan_bytes(
    inputs: &[SharedInputExpectation],
    models: &[CompiledModel],
    layouts: &[PhysicalLayout],
) -> usize {
    let input_bytes = inputs.iter().fold(0_usize, |total, input| {
        total
            .saturating_add(std::mem::size_of::<SharedInputExpectation>())
            .saturating_add(input.preserved_prefix.len())
    });
    let model_bytes = models.iter().fold(0_usize, |total, model| {
        let groups = model.groups.iter().fold(0_usize, |groups, group| {
            groups
                .saturating_add(std::mem::size_of::<CompiledGroup>())
                .saturating_add(receipt_retained_bytes(&group.receipt))
        });
        total
            .saturating_add(std::mem::size_of::<CompiledModel>())
            .saturating_add(
                model
                    .inputs
                    .len()
                    .saturating_mul(std::mem::size_of::<CompiledInput>()),
            )
            .saturating_add(groups)
    });
    let layout_bytes = layouts.iter().fold(0_usize, |total, layout| {
        total
            .saturating_add(std::mem::size_of::<PhysicalLayout>())
            .saturating_add(
                layout
                    .parts
                    .len()
                    .saturating_mul(std::mem::size_of::<PhysicalPart>()),
            )
    });
    std::mem::size_of::<RecordAssemblyPlan>()
        .saturating_add(input_bytes)
        .saturating_add(model_bytes)
        .saturating_add(layout_bytes)
}

const fn receipt_retained_bytes(receipt: &RecordGroupReceipt) -> usize {
    receipt
        .identifier
        .len()
        .saturating_add(
            receipt
                .parts
                .len()
                .saturating_mul(std::mem::size_of::<super::RecordAssemblyPart>()),
        )
        .saturating_add(
            receipt
                .missing_sequences
                .len()
                .saturating_mul(std::mem::size_of::<u64>()),
        )
        .saturating_add(
            receipt
                .duplicate_sequences
                .len()
                .saturating_mul(std::mem::size_of::<u64>()),
        )
        .saturating_add(
            receipt
                .sequences_before_base
                .len()
                .saturating_mul(std::mem::size_of::<u64>()),
        )
        .saturating_add(
            receipt
                .sequences_after_terminal
                .len()
                .saturating_mul(std::mem::size_of::<u64>()),
        )
}

/// Candidate-bound view of a compiled plan
pub struct BoundRecordAssemblyPlan<'plan, 'input> {
    plan: &'plan RecordAssemblyPlan,
    inputs: &'plan [RecordInput<'input>],
    model_statuses: Vec<RecordAssemblyModelStatus>,
    available_layouts: Vec<bool>,
    layout_digests: Vec<Option<String>>,
    stats: RecordAssemblyBindStats,
}

impl fmt::Debug for BoundRecordAssemblyPlan<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundRecordAssemblyPlan")
            .field("input_count", &self.inputs.len())
            .field("model_statuses", &self.model_statuses)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl BoundRecordAssemblyPlan<'_, '_> {
    /// Return the status for one frozen semantic model
    #[must_use]
    pub fn model_status(&self, model_index: usize) -> Option<RecordAssemblyModelStatus> {
        self.model_statuses.get(model_index).copied()
    }

    /// Return the number of semantic groups if the model's headers and lengths match
    #[must_use]
    pub fn model_group_count(&self, model_index: usize) -> Option<usize> {
        self.model_status(model_index)
            .filter(|status| *status == RecordAssemblyModelStatus::Ready)?;
        self.plan
            .models
            .get(model_index)
            .map(|model| model.groups.len())
    }

    /// Return one physical layout ID for a ready model group
    #[must_use]
    pub fn layout_id(&self, model_index: usize, group_index: usize) -> Option<usize> {
        self.model_status(model_index)
            .filter(|status| *status == RecordAssemblyModelStatus::Ready)?;
        self.plan
            .models
            .get(model_index)?
            .groups
            .get(group_index)
            .map(|group| group.layout_id)
    }

    /// Return a referenced layout's output length before copying its payload bytes
    #[must_use]
    pub fn layout_output_length(&self, layout_id: usize) -> Option<usize> {
        self.available_layouts
            .get(layout_id)
            .copied()
            .filter(|available| *available)?;
        self.plan
            .layouts
            .get(layout_id)
            .map(|layout| layout.output_length)
    }

    /// Materialize one current-candidate layout and compute its fresh digest
    ///
    /// The returned buffer is owned by the caller so rejected alternatives need not accumulate
    /// in the bound plan
    ///
    /// # Errors
    /// Rejects unknown layouts, layouts with no ready model, invalid source ranges, and allocation
    /// failure
    pub fn materialize(
        &mut self,
        layout_id: usize,
    ) -> Result<RecordAssemblyMaterializedLayout, RecordError> {
        let layout = self
            .plan
            .layouts
            .get(layout_id)
            .ok_or(RecordError::InvalidReport)?;
        if !self
            .available_layouts
            .get(layout_id)
            .copied()
            .unwrap_or(false)
        {
            return Err(RecordError::InvalidReport);
        }
        let bytes = materialize_layout(self.inputs, &layout.parts, layout.output_length)?;
        let sha256 = crate::sha256(&bytes);
        let Some(digest) = self.layout_digests.get_mut(layout_id) else {
            return Err(RecordError::InvalidReport);
        };
        if digest.is_none() {
            self.stats.materialized_layouts = self.stats.materialized_layouts.saturating_add(1);
        }
        *digest = Some(sha256.clone());
        self.stats.materialized_bytes = self.stats.materialized_bytes.saturating_add(bytes.len());
        self.stats.hashed_bytes = self.stats.hashed_bytes.saturating_add(bytes.len());
        Ok(RecordAssemblyMaterializedLayout { bytes, sha256 })
    }

    /// Return one model-specific receipt carrying a shared layout's fresh output identity
    ///
    /// # Errors
    /// Rejects a non-ready model, unknown group, or output from another physical layout
    pub fn group_receipt(
        &self,
        model_index: usize,
        group_index: usize,
    ) -> Result<RecordGroupReceipt, RecordError> {
        if self.model_status(model_index) != Some(RecordAssemblyModelStatus::Ready) {
            return Err(RecordError::InvalidReport);
        }
        let group = self
            .plan
            .models
            .get(model_index)
            .and_then(|model| model.groups.get(group_index))
            .ok_or(RecordError::InvalidReport)?;
        let output_sha256 = self
            .layout_digests
            .get(group.layout_id)
            .and_then(Option::as_deref)
            .ok_or(RecordError::InvalidReport)?;
        let output_length = self
            .plan
            .layouts
            .get(group.layout_id)
            .ok_or(RecordError::InvalidReport)?
            .output_length;
        let mut receipt = group.receipt.clone();
        finish_receipt_identity(&mut receipt, output_length, output_sha256);
        Ok(receipt)
    }

    /// Return work counters accumulated by this candidate binding
    #[must_use]
    pub const fn stats(&self) -> &RecordAssemblyBindStats {
        &self.stats
    }
}

/// Fresh bytes and digest for one physical layout in a bound candidate
pub struct RecordAssemblyMaterializedLayout {
    bytes: Vec<u8>,
    sha256: String,
}

impl fmt::Debug for RecordAssemblyMaterializedLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordAssemblyMaterializedLayout")
            .field("byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl RecordAssemblyMaterializedLayout {
    /// Return the exact assembled payload bytes
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the SHA-256 computed from these exact assembled bytes
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}
