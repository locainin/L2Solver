use super::super::super::RecoveryExecutionError;
use super::super::invalid_policy;
use l2_workbench::protocol::{HeaderParseTemplate, RecordLimits, RecordSchema};

#[derive(Clone)]
pub(super) struct HeaderSchemaModel {
    pub(super) schema: RecordSchema,
    pub(super) limits: RecordLimits,
    pub(super) templates: Vec<(usize, HeaderParseTemplate)>,
    pub(super) retained_bytes: usize,
}

#[derive(Default)]
pub(super) struct HeaderSchemaPlan {
    pub(super) models: Vec<HeaderSchemaModel>,
    pub(super) retained_bytes: usize,
    pub(super) omitted_models: usize,
}

impl HeaderSchemaModel {
    pub(super) fn with_templates(
        schema: RecordSchema,
        limits: RecordLimits,
        templates: Vec<(usize, HeaderParseTemplate)>,
    ) -> Result<Self, RecoveryExecutionError> {
        let template_bytes = templates.iter().fold(0_usize, |total, (index, template)| {
            total
                .saturating_add(std::mem::size_of_val(index))
                .saturating_add(template.retained_bytes())
        });
        let retained_bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of_val(templates.as_slice()))
            .and_then(|total| total.checked_add(template_bytes))
            .ok_or_else(|| invalid_policy("header schema model size overflowed"))?;
        Ok(Self {
            schema,
            limits,
            templates,
            retained_bytes,
        })
    }
}
