use super::RecordWorkBudget;
use super::model::{
    IntegerField, ParsedRecord, RecordAssemblyInput, RecordCount, RecordError, RecordLimits,
    RecordParseReport, RecordSchema, parsed_record_metadata_bytes,
};
use std::{cell::OnceCell, fmt};

#[cfg(test)]
#[path = "../../../tests/protocol/record_input_internal.rs"]
mod tests;

/// Complete input bytes paired with a lazily computed full-byte SHA-256 identity
pub struct RecordInput<'a> {
    pub(super) bytes: &'a [u8],
    input_sha256: OnceCell<String>,
}

impl<'a> RecordInput<'a> {
    /// Bind an immutable input slice to the canonical record APIs
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            input_sha256: OnceCell::new(),
        }
    }

    /// Parse records while computing the full-byte identity only after a successful parse
    ///
    /// # Errors
    /// Rejects invalid layouts, truncated inputs, trailing bytes, overflow, and limit violations
    pub fn parse(
        &self,
        schema: &RecordSchema,
        limits: RecordLimits,
    ) -> Result<RecordParseReport, RecordError> {
        super::parse::parse_with_input(self, schema, limits)
    }

    /// Parse records while charging field reads, metadata, and first-time identity work
    ///
    /// The input identity is hashed only after a successful parse and is reused by later parses
    /// and assembly operations on this input
    ///
    /// # Errors
    /// Rejects invalid layouts, truncated inputs, trailing bytes, limit violations, and exhausted work budgets
    pub fn parse_with_work(
        &self,
        schema: &RecordSchema,
        limits: RecordLimits,
        work: &mut RecordWorkBudget,
    ) -> Result<RecordParseReport, RecordError> {
        super::parse::parse_with_input_metered(self, schema, limits, work)
    }

    /// Return the immutable bytes paired with this input identity
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(super) fn input_sha256(&self) -> &str {
        self.input_sha256.get_or_init(|| crate::sha256(self.bytes))
    }

    pub(super) fn identity_is_computed(&self) -> bool {
        self.input_sha256.get().is_some()
    }
}

impl fmt::Debug for RecordInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordInput")
            .field("length", &self.bytes.len())
            .field("identity_computed", &self.input_sha256.get().is_some())
            .finish()
    }
}

/// Parsed header metadata that can be rebound only across an identical header and input length
#[derive(Clone, Eq, PartialEq)]
pub struct HeaderParseTemplate {
    schema: RecordSchema,
    input_length: usize,
    preserved_header: Vec<u8>,
    limits: RecordLimits,
    declared_count: Option<u64>,
    records: Vec<ParsedRecord>,
}

impl HeaderParseTemplate {
    /// Bind cached record metadata to a new full-byte input with the same preserved header
    ///
    /// The full-byte identity is always computed from the current immutable input bytes
    ///
    /// # Errors
    /// Rejects changed headers, input lengths, record limits, and invalid template metadata
    pub fn rebind(
        &self,
        input: &RecordInput<'_>,
        limits: RecordLimits,
    ) -> Result<RecordParseReport, RecordError> {
        if limits != self.limits {
            return Err(RecordError::InvalidReport);
        }
        super::parse::validate_limits(limits)?;
        super::parse::validate_schema(&self.schema, limits)?;
        let current_header = input
            .bytes
            .get(..self.preserved_header.len())
            .ok_or(RecordError::InvalidReport)?;
        if input.bytes.len() != self.input_length
            || current_header != self.preserved_header
            || !single_record_fills_input(
                &self.schema,
                self.declared_count,
                &self.records,
                input.bytes.len(),
                self.preserved_header.len(),
            )
            || parsed_record_metadata_bytes(&self.records) > limits.max_report_bytes
        {
            return Err(RecordError::InvalidReport);
        }
        Ok(RecordParseReport {
            schema: self.schema.clone(),
            input_length: input.bytes.len(),
            input_sha256: input.input_sha256().to_owned(),
            declared_count: self.declared_count,
            records: self.records.clone(),
        })
    }

    /// Return a conservative logical size for bounded cache accounting
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.preserved_header.len())
            .saturating_add(parsed_record_metadata_bytes(&self.records))
    }

    pub(super) fn into_parts(self) -> HeaderParseTemplateParts {
        HeaderParseTemplateParts {
            schema: self.schema,
            input_length: self.input_length,
            preserved_header: self.preserved_header,
            limits: self.limits,
            records: self.records,
        }
    }
}

pub(super) struct HeaderParseTemplateParts {
    pub(super) schema: RecordSchema,
    pub(super) input_length: usize,
    pub(super) preserved_header: Vec<u8>,
    pub(super) limits: RecordLimits,
    pub(super) records: Vec<ParsedRecord>,
}

impl fmt::Debug for HeaderParseTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderParseTemplate")
            .field("schema", &self.schema)
            .field("input_length", &self.input_length)
            .field("preserved_header_end", &self.preserved_header.len())
            .field("record_count", &self.records.len())
            .field("limits", &self.limits)
            .field("declared_count", &self.declared_count)
            .finish_non_exhaustive()
    }
}

impl RecordParseReport {
    /// Cache one complete record whose schema fields all read preserved prefix bytes
    ///
    /// The report and input must share the same canonical full-byte identity. Templates are
    /// unavailable for multiple records, body-dependent fields, or oversized preserved headers
    ///
    /// # Errors
    /// Rejects a report that is not bound to the supplied input or limits
    pub fn header_only_template(
        &self,
        input: &RecordInput<'_>,
        preserved_header_end: usize,
        limits: RecordLimits,
    ) -> Result<Option<HeaderParseTemplate>, RecordError> {
        if self.input_length != input.bytes.len() || self.input_sha256 != input.input_sha256() {
            return Err(RecordError::InvalidReport);
        }
        super::parse::validate_limits(limits)?;
        super::parse::validate_schema(&self.schema, limits)?;
        if self.input_length > limits.max_input_bytes {
            return Err(RecordError::InputTooLarge {
                length: self.input_length,
                maximum: limits.max_input_bytes,
            });
        }
        let metadata_bytes = self.metadata_bytes();
        if metadata_bytes > limits.max_report_bytes {
            return Err(RecordError::ReportTooLarge {
                bytes: metadata_bytes,
                maximum: limits.max_report_bytes,
            });
        }
        let Some(prefix) = input.bytes.get(..preserved_header_end) else {
            return Ok(None);
        };
        if preserved_header_end > limits.max_report_bytes
            || !single_record_fills_input(
                &self.schema,
                self.declared_count,
                &self.records,
                input.bytes.len(),
                preserved_header_end,
            )
        {
            return Ok(None);
        }
        // Reserve both copies before retaining a template so allocation failure stays recoverable
        let mut preserved_header = Vec::new();
        preserved_header
            .try_reserve_exact(preserved_header_end)
            .map_err(|_| RecordError::AllocationFailed)?;
        preserved_header.extend_from_slice(prefix);
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.records.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        for record in &self.records {
            let mut identifier = Vec::new();
            identifier
                .try_reserve_exact(record.identifier.len())
                .map_err(|_| RecordError::AllocationFailed)?;
            identifier.extend_from_slice(&record.identifier);
            records.push(ParsedRecord {
                index: record.index,
                record: record.record,
                identifier,
                sequence: record.sequence,
                payload: record.payload,
            });
        }
        Ok(Some(HeaderParseTemplate {
            schema: self.schema.clone(),
            input_length: self.input_length,
            preserved_header,
            limits,
            declared_count: self.declared_count,
            records,
        }))
    }
}

impl<'a> RecordAssemblyInput<'a> {
    /// Bind a report to a record input whose digest came from the same immutable bytes
    ///
    /// # Errors
    /// Rejects reports tied to another identity or input length
    pub fn from_input(
        input: &'a RecordInput<'_>,
        report: &'a RecordParseReport,
    ) -> Result<Self, RecordError> {
        if input.bytes.len() != report.input_length || input.input_sha256() != report.input_sha256 {
            return Err(RecordError::InvalidReport);
        }
        Ok(Self {
            bytes: input.bytes,
            report,
            input_sha256: Some(input.input_sha256()),
        })
    }
}

fn single_record_fills_input(
    schema: &RecordSchema,
    declared_count: Option<u64>,
    records: &[ParsedRecord],
    input_length: usize,
    preserved_header_end: usize,
) -> bool {
    let Some(record) = records.first() else {
        return false;
    };
    let record_start = schema.records_offset;
    let Some(record_data_end) = record_start.checked_add(schema.data_offset) else {
        return false;
    };
    let Some(identifier_end) = byte_field_end(
        record_start,
        schema.identifier.offset,
        schema.identifier.width,
    ) else {
        return false;
    };
    let Some(sequence_end) = integer_field_end(record_start, schema.sequence) else {
        return false;
    };
    let Some(length_end) = integer_field_end(record_start, schema.length) else {
        return false;
    };
    let count_valid = match schema.count {
        RecordCount::UntilEnd => declared_count.is_none(),
        RecordCount::Exact { records: 1 } => declared_count == Some(1),
        RecordCount::Exact { .. } => false,
        RecordCount::Field { field } => integer_field_end(0, field).is_some_and(|count_end| {
            count_end <= schema.records_offset
                && count_end <= preserved_header_end
                && declared_count == Some(1)
        }),
    };
    let payload_start = record_start.checked_add(schema.data_offset);
    records.len() == 1
        && preserved_header_end <= input_length
        && schema.records_offset <= preserved_header_end
        && record_data_end <= preserved_header_end
        && identifier_end <= preserved_header_end
        && sequence_end <= preserved_header_end
        && length_end <= preserved_header_end
        && record.index == 0
        && record.record.start == record_start
        && record.record.end == input_length
        && Some(record.payload.start) == payload_start
        && record.payload.end == input_length
        && count_valid
}

fn byte_field_end(start: usize, offset: usize, width: usize) -> Option<usize> {
    start.checked_add(offset)?.checked_add(width)
}

const fn integer_field_end(start: usize, field: IntegerField) -> Option<usize> {
    match start.checked_add(field.offset) {
        Some(field_start) => field_start.checked_add(field.width),
        None => None,
    }
}
