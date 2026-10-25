use super::model::{
    Ambiguity, CarrierError, FieldWidth, MAX_INPUT_BYTES, Observation, OmissionReason, Report,
    Rule, TimingStatus, Value,
};
use crate::{derivation, evidence::SourceRange, hypothesis};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Maximum number of caller-selected observations in one composition
pub const MAX_COMPOSITION_PARTS: usize = 4096;

/// Explicit byte, numeric, or bit representation for one projected value
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompositionEncoding {
    /// Copy the selected byte value as-is
    Bytes,
    /// Encode a complete unsigned number at an exact width and byte order
    Unsigned {
        width: FieldWidth,
        byte_order: super::NumericByteOrder,
    },
    /// Apply checked integer arithmetic to an explicit length value before encoding it
    LengthArithmetic {
        operation: LengthArithmetic,
        operand: u64,
        width: FieldWidth,
        byte_order: super::NumericByteOrder,
    },
    /// Pack a logical bit sequence in an explicit output order
    Bits {
        order: super::BitOrder,
        padding: PartialBytePadding,
    },
}

/// Checked integer operation for a whole-message or explicit length-field value
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthArithmetic {
    Add,
    Subtract,
    Multiply,
    Divide,
}

/// Explicit handling for a final partial output byte
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialBytePadding {
    /// Reject a bit sequence whose length is not divisible by eight
    Reject,
    /// Set every unused output bit to zero
    ZeroFill,
    /// Set every unused output bit to one
    OneFill,
}

/// One exact value selected from an extraction observation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionField {
    /// Exact projected sample bytes
    Bytes,
    /// Full unsigned length, order, or numeric value
    Unsigned,
    /// Logical source bits in their extracted order
    Bits,
    /// Original bytes of one DNS label
    DnsRaw,
    /// Caller-selected DNS label comparison bytes
    DnsComparison,
    /// One zero-or-one byte for each ASCII letter's case
    Capitalization,
    /// Exact tick delta from an adjacent measured interval
    TimingDeltaTicks,
    /// Caller-provided sequence value for the earlier event
    TimingFromSequence,
    /// Caller-provided sequence value for the later event
    TimingToSequence,
    /// Exact source ticks for the earlier event
    TimingFromTicks,
    /// Exact source ticks for the later event
    TimingToTicks,
}

/// One caller-selected observation and its complete output encoding
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionPart {
    /// Exact caller sample identifiers in observation order
    pub sample_ids: Vec<u64>,
    /// Extraction rule, including its offsets and source bit order
    pub rule: Rule,
    /// Component selector for repeated values such as DNS labels
    pub component_index: Option<usize>,
    /// Value within the matching observation
    pub field: CompositionField,
    /// Explicit conversion from the selected value to output bytes
    pub encoding: CompositionEncoding,
}

/// Ordered, replayable recipe for assembling selected carrier values
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionRecipe {
    /// Caller-selected projected values in output order
    pub parts: Vec<CompositionPart>,
}

/// Result for one selected part, including exact source provenance
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompositionPartStatus {
    /// One exact observation was encoded
    Encoded,
    /// No matching observation was retained
    Missing { omission: Option<OmissionReason> },
    /// The observation exists but its selected field has no exact value
    Unresolved { omission: Option<OmissionReason> },
    /// Source or event attribution has multiple caller-retained candidates
    Ambiguous,
}

/// Provenance and output position for one recipe part
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionPartReceipt {
    /// Zero-based recipe part position
    pub part_index: usize,
    /// Exact extraction observation, if one was retained
    pub observation_id: Option<u64>,
    /// Source ranges that support the selected value
    pub ranges: Vec<SourceRange>,
    /// Identity uncertainty retained from extraction
    pub ambiguity: Option<Ambiguity>,
    /// Whether a value was selected, omitted, or unresolved
    pub status: CompositionPartStatus,
    /// Logical bit count before explicit final-byte padding
    pub logical_bit_length: Option<usize>,
    /// Encoded byte count, even when another part prevents composition
    pub encoded_length: Option<usize>,
    /// Output offset, present only when the whole recipe is complete
    pub composed_offset: Option<usize>,
}

/// Replay recipe, per-part provenance, and digest for composed bytes
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionReceipt {
    /// Exact caller composition recipe
    pub recipe: CompositionRecipe,
    /// Whether the source extraction report was complete
    pub extraction_complete: bool,
    /// True only when extraction and every selected part are complete
    pub complete: bool,
    /// Per-part source provenance and encoded output spans
    pub parts: Vec<CompositionPartReceipt>,
    /// Encoded output size, absent when composition is incomplete
    pub output_length: Option<usize>,
    /// Content digest for the fully composed byte stream
    pub output_sha256: Option<String>,
}

/// In-memory composed bytes with a serializable provenance receipt
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionOutcome {
    /// Audit record for the selected and encoded observations
    receipt: CompositionReceipt,
    bytes: Option<Vec<u8>>,
}

impl CompositionOutcome {
    /// Return the immutable receipt bound to these composed bytes
    #[must_use]
    pub const fn receipt(&self) -> &CompositionReceipt {
        &self.receipt
    }

    /// Return composed bytes only when every selected part resolved
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

impl CompositionRecipe {
    /// Validate selector bounds and every explicit field-to-encoding pair
    ///
    /// # Errors
    /// Rejects empty selectors, too many parts, or incompatible rule and encoding choices
    pub fn validate(&self) -> Result<(), CarrierError> {
        validate_recipe(self)
    }
}

/// Search result bound to the exact composition recipe and source ranges
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedSearchOutcome {
    /// Composition input and exact source provenance
    pub composition: CompositionReceipt,
    /// Candidate recipes and independent checks run on composed bytes
    pub search: hypothesis::SearchReport,
}

/// Derivation result bound to the exact composition recipe and source ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedDerivationOutcome {
    /// Composition input and exact source provenance
    pub composition: CompositionReceipt,
    /// Complete caller-specified operation sequence and constraints
    pub recipe: derivation::Recipe,
    /// Exact result of applying the recipe to composed bytes
    pub derivation: derivation::DerivationReport,
}

/// Encode selected, retained observations without inferring missing values
///
/// A partial extraction or unresolved selected part never produces bytes
///
/// # Errors
/// Rejects malformed recipes, ambiguous selectors, incompatible encodings, or overflow
pub fn compose(
    report: &Report,
    recipe: &CompositionRecipe,
) -> Result<CompositionOutcome, CarrierError> {
    validate_recipe(recipe)?;
    let observations = observation_index(report);
    let mut encoded_parts = Vec::with_capacity(recipe.parts.len());
    let mut receipts = Vec::with_capacity(recipe.parts.len());
    let mut encoded_length = 0_usize;
    for (part_index, part) in recipe.parts.iter().enumerate() {
        let (encoded, receipt) = compose_part(report, &observations, part_index, part)?;
        if let Some(bytes) = &encoded {
            encoded_length = encoded_length
                .checked_add(bytes.len())
                .filter(|length| *length <= MAX_INPUT_BYTES)
                .ok_or(CarrierError::RequestLimit)?;
        }
        encoded_parts.push(encoded);
        receipts.push(receipt);
    }
    assemble(report.complete, recipe, receipts, encoded_parts)
}

#[derive(Eq, Hash, PartialEq)]
struct ObservationKey<'a> {
    sample_ids: &'a [u64],
    rule: &'a Rule,
    component_index: Option<usize>,
}

type ObservationIndex<'a> = HashMap<ObservationKey<'a>, Option<&'a Observation>>;

fn observation_index(report: &Report) -> ObservationIndex<'_> {
    let mut index = HashMap::with_capacity(report.observations.len());
    for observation in &report.observations {
        let key = ObservationKey {
            sample_ids: &observation.sample_ids,
            rule: &observation.rule,
            component_index: observation.component_index,
        };
        index
            .entry(key)
            .and_modify(|entry| *entry = None)
            .or_insert(Some(observation));
    }
    index
}

fn validate_recipe(recipe: &CompositionRecipe) -> Result<(), CarrierError> {
    if recipe.parts.is_empty() || recipe.parts.len() > MAX_COMPOSITION_PARTS {
        return Err(CarrierError::InvalidCompositionRecipe);
    }
    for part in &recipe.parts {
        let mut sample_ids = HashSet::with_capacity(part.sample_ids.len());
        if part.sample_ids.is_empty()
            || part
                .sample_ids
                .iter()
                .any(|sample_id| *sample_id == 0 || !sample_ids.insert(*sample_id))
        {
            return Err(CarrierError::InvalidCompositionRecipe);
        }
        validate_part(part)?;
    }
    Ok(())
}

const fn validate_part(part: &CompositionPart) -> Result<(), CarrierError> {
    let rule_matches = matches!(
        (&part.rule, part.field),
        (Rule::Bytes, CompositionField::Bytes)
            | (Rule::Bits { .. }, CompositionField::Bits)
            | (
                Rule::MessageLength
                    | Rule::LengthField { .. }
                    | Rule::Sequence
                    | Rule::OrderField { .. },
                CompositionField::Unsigned,
            )
            | (Rule::Capitalization, CompositionField::Capitalization)
            | (
                Rule::DnsLabels { .. },
                CompositionField::DnsRaw | CompositionField::DnsComparison,
            )
            | (
                Rule::Timing,
                CompositionField::TimingDeltaTicks
                    | CompositionField::TimingFromSequence
                    | CompositionField::TimingToSequence
                    | CompositionField::TimingFromTicks
                    | CompositionField::TimingToTicks,
            )
    );
    let encoding_matches = match part.field {
        CompositionField::Bytes | CompositionField::DnsRaw | CompositionField::DnsComparison => {
            matches!(part.encoding, CompositionEncoding::Bytes)
        }
        CompositionField::Unsigned
        | CompositionField::TimingDeltaTicks
        | CompositionField::TimingFromSequence
        | CompositionField::TimingToSequence
        | CompositionField::TimingFromTicks
        | CompositionField::TimingToTicks => match part.encoding {
            CompositionEncoding::Unsigned { .. } => true,
            CompositionEncoding::LengthArithmetic { .. } => {
                matches!(part.rule, Rule::MessageLength | Rule::LengthField { .. })
            }
            CompositionEncoding::Bytes | CompositionEncoding::Bits { .. } => false,
        },
        CompositionField::Bits | CompositionField::Capitalization => {
            matches!(part.encoding, CompositionEncoding::Bits { .. })
        }
    };
    if !rule_matches || !encoding_matches {
        return Err(CarrierError::InvalidCompositionEncoding);
    }
    Ok(())
}

fn compose_part(
    report: &Report,
    observations: &ObservationIndex<'_>,
    part_index: usize,
    part: &CompositionPart,
) -> Result<(Option<Vec<u8>>, CompositionPartReceipt), CarrierError> {
    let observation = find_observation(observations, part)?;
    let Some(observation) = observation else {
        return Ok(missing_part(report, part_index, part));
    };
    if observation.ambiguity == Ambiguity::MultipleCandidates {
        return Ok(ambiguous_part(part_index, observation));
    }
    let Some(value) = observation.value.as_ref() else {
        return Ok(unresolved_part(report, part_index, part, observation));
    };
    let Some((selected, bit_length)) = select_field(value, part.field)? else {
        return Ok(unresolved_part(report, part_index, part, observation));
    };
    let encoded = encode_value(selected, part.encoding)?;
    let receipt = CompositionPartReceipt {
        part_index,
        observation_id: Some(observation.id),
        ranges: observation.ranges.clone(),
        ambiguity: Some(observation.ambiguity),
        status: CompositionPartStatus::Encoded,
        logical_bit_length: bit_length,
        encoded_length: Some(encoded.len()),
        composed_offset: None,
    };
    Ok((Some(encoded), receipt))
}

fn ambiguous_part(
    part_index: usize,
    observation: &Observation,
) -> (Option<Vec<u8>>, CompositionPartReceipt) {
    (
        None,
        CompositionPartReceipt {
            part_index,
            observation_id: Some(observation.id),
            ranges: observation.ranges.clone(),
            ambiguity: Some(observation.ambiguity),
            status: CompositionPartStatus::Ambiguous,
            logical_bit_length: None,
            encoded_length: None,
            composed_offset: None,
        },
    )
}

fn find_observation<'a>(
    observations: &ObservationIndex<'a>,
    part: &CompositionPart,
) -> Result<Option<&'a Observation>, CarrierError> {
    let key = ObservationKey {
        sample_ids: &part.sample_ids,
        rule: &part.rule,
        component_index: part.component_index,
    };
    match observations.get(&key) {
        Some(Some(observation)) => Ok(Some(*observation)),
        Some(None) => Err(CarrierError::AmbiguousCompositionPart),
        None => Ok(None),
    }
}

fn missing_part(
    report: &Report,
    part_index: usize,
    part: &CompositionPart,
) -> (Option<Vec<u8>>, CompositionPartReceipt) {
    let omission = find_omission(report, part);
    (
        None,
        CompositionPartReceipt {
            part_index,
            observation_id: None,
            ranges: Vec::new(),
            ambiguity: None,
            status: CompositionPartStatus::Missing { omission },
            logical_bit_length: None,
            encoded_length: None,
            composed_offset: None,
        },
    )
}

fn unresolved_part(
    report: &Report,
    part_index: usize,
    part: &CompositionPart,
    observation: &Observation,
) -> (Option<Vec<u8>>, CompositionPartReceipt) {
    (
        None,
        CompositionPartReceipt {
            part_index,
            observation_id: Some(observation.id),
            ranges: observation.ranges.clone(),
            ambiguity: Some(observation.ambiguity),
            status: CompositionPartStatus::Unresolved {
                omission: find_omission(report, part),
            },
            logical_bit_length: None,
            encoded_length: None,
            composed_offset: None,
        },
    )
}

fn find_omission(report: &Report, part: &CompositionPart) -> Option<OmissionReason> {
    report
        .omissions
        .iter()
        .find(|omission| {
            omission.rule == part.rule && omission.sample_id == part.sample_ids.first().copied()
        })
        .map(|omission| omission.reason)
}

enum SelectedValue<'a> {
    Bytes(&'a [u8]),
    Unsigned(u64),
    Bits(Vec<u8>),
}

fn select_field(
    value: &Value,
    field: CompositionField,
) -> Result<Option<(SelectedValue<'_>, Option<usize>)>, CarrierError> {
    let selected = match (value, field) {
        (Value::Bytes { bytes }, CompositionField::Bytes) => (SelectedValue::Bytes(bytes), None),
        (Value::Unsigned { value }, CompositionField::Unsigned) => {
            (SelectedValue::Unsigned(*value), None)
        }
        (
            Value::Bits {
                bit_length, packed, ..
            },
            CompositionField::Bits,
        ) => {
            let Some(length) = usize::try_from(*bit_length).ok() else {
                return Ok(None);
            };
            let Some(bits) = unpack_bits(packed, length) else {
                return Ok(None);
            };
            (SelectedValue::Bits(bits), Some(length))
        }
        (Value::DnsLabel { raw, .. }, CompositionField::DnsRaw) => {
            (SelectedValue::Bytes(raw), None)
        }
        (Value::DnsLabel { comparison, .. }, CompositionField::DnsComparison) => {
            (SelectedValue::Bytes(comparison), None)
        }
        (Value::Capitalization { pattern }, CompositionField::Capitalization) => {
            (SelectedValue::Bits(pattern.clone()), Some(pattern.len()))
        }
        (
            Value::Timing {
                delta_ticks: Some(value),
                status: TimingStatus::Measured,
                ..
            },
            CompositionField::TimingDeltaTicks,
        )
        | (
            Value::Timing {
                from_sequence: Some(value),
                ..
            },
            CompositionField::TimingFromSequence,
        )
        | (
            Value::Timing {
                to_sequence: Some(value),
                ..
            },
            CompositionField::TimingToSequence,
        )
        | (
            Value::Timing {
                from_ticks: Some(value),
                ..
            },
            CompositionField::TimingFromTicks,
        )
        | (
            Value::Timing {
                to_ticks: Some(value),
                ..
            },
            CompositionField::TimingToTicks,
        ) => (SelectedValue::Unsigned(*value), None),
        (
            Value::Timing { .. },
            CompositionField::TimingDeltaTicks
            | CompositionField::TimingFromSequence
            | CompositionField::TimingToSequence
            | CompositionField::TimingFromTicks
            | CompositionField::TimingToTicks,
        ) => return Ok(None),
        _ => return Err(CarrierError::InvalidCompositionEncoding),
    };
    Ok(Some(selected))
}

fn unpack_bits(packed: &[u8], bit_length: usize) -> Option<Vec<u8>> {
    let expected_length = bit_length.checked_add(7)?.checked_div(8)?;
    if packed.len() != expected_length {
        return None;
    }
    let mut bits = Vec::with_capacity(bit_length);
    for index in 0..bit_length {
        let byte = packed.get(index / 8).copied()?;
        bits.push((byte >> (7 - index % 8)) & 1);
    }
    Some(bits)
}

fn encode_value(
    value: SelectedValue<'_>,
    encoding: CompositionEncoding,
) -> Result<Vec<u8>, CarrierError> {
    match (value, encoding) {
        (SelectedValue::Bytes(bytes), CompositionEncoding::Bytes) => Ok(bytes.to_vec()),
        (SelectedValue::Unsigned(value), CompositionEncoding::Unsigned { width, byte_order }) => {
            encode_unsigned(value, width, byte_order)
        }
        (
            SelectedValue::Unsigned(value),
            CompositionEncoding::LengthArithmetic {
                operation,
                operand,
                width,
                byte_order,
            },
        ) => encode_unsigned(
            apply_length_arithmetic(value, operation, operand)?,
            width,
            byte_order,
        ),
        (SelectedValue::Bits(bits), CompositionEncoding::Bits { order, padding }) => {
            encode_bits(&bits, order, padding)
        }
        _ => Err(CarrierError::InvalidCompositionEncoding),
    }
}

fn apply_length_arithmetic(
    value: u64,
    operation: LengthArithmetic,
    operand: u64,
) -> Result<u64, CarrierError> {
    match operation {
        LengthArithmetic::Add => value
            .checked_add(operand)
            .ok_or(CarrierError::CompositionOverflow),
        LengthArithmetic::Subtract => value
            .checked_sub(operand)
            .ok_or(CarrierError::CompositionOverflow),
        LengthArithmetic::Multiply => value
            .checked_mul(operand)
            .ok_or(CarrierError::CompositionOverflow),
        LengthArithmetic::Divide => value
            .checked_div(operand)
            .ok_or(CarrierError::CompositionArithmetic),
    }
}

fn encode_unsigned(
    value: u64,
    width: FieldWidth,
    byte_order: super::NumericByteOrder,
) -> Result<Vec<u8>, CarrierError> {
    let byte_count = width.bytes();
    let bit_count = byte_count
        .checked_mul(8)
        .ok_or(CarrierError::CompositionOverflow)?;
    if bit_count < 64 && value >= (1_u64 << bit_count) {
        return Err(CarrierError::CompositionOverflow);
    }
    let bytes = match byte_order {
        super::NumericByteOrder::BigEndian => value.to_be_bytes(),
        super::NumericByteOrder::LittleEndian => value.to_le_bytes(),
    };
    let range = match byte_order {
        super::NumericByteOrder::BigEndian => (8 - byte_count)..8,
        super::NumericByteOrder::LittleEndian => 0..byte_count,
    };
    Ok(bytes
        .get(range)
        .ok_or(CarrierError::InvalidCompositionEncoding)?
        .to_vec())
}

fn encode_bits(
    bits: &[u8],
    order: super::BitOrder,
    padding: PartialBytePadding,
) -> Result<Vec<u8>, CarrierError> {
    if bits.iter().any(|bit| *bit > 1) {
        return Err(CarrierError::InvalidCompositionEncoding);
    }
    let remainder = bits.len() % 8;
    if remainder != 0 && padding == PartialBytePadding::Reject {
        return Err(CarrierError::InvalidCompositionEncoding);
    }
    let output_len = bits
        .len()
        .checked_add(7)
        .and_then(|length| length.checked_div(8))
        .ok_or(CarrierError::CompositionOverflow)?;
    let mut output = vec![0_u8; output_len];
    for (index, bit) in bits.iter().copied().enumerate() {
        let byte = output
            .get_mut(index / 8)
            .ok_or(CarrierError::CompositionOverflow)?;
        let shift = bit_shift(index % 8, order)?;
        *byte |= bit << shift;
    }
    if remainder != 0 && padding == PartialBytePadding::OneFill {
        fill_padding(output.last_mut(), remainder, order)?;
    }
    Ok(output)
}

fn bit_shift(position: usize, order: super::BitOrder) -> Result<u32, CarrierError> {
    let position = u32::try_from(position).map_err(|_| CarrierError::CompositionOverflow)?;
    match order {
        super::BitOrder::MostSignificantFirst => Ok(7 - position),
        super::BitOrder::LeastSignificantFirst => Ok(position),
    }
}

fn fill_padding(
    byte: Option<&mut u8>,
    used_bits: usize,
    order: super::BitOrder,
) -> Result<(), CarrierError> {
    let byte = byte.ok_or(CarrierError::CompositionOverflow)?;
    for position in used_bits..8 {
        let shift = bit_shift(position, order)?;
        *byte |= 1 << shift;
    }
    Ok(())
}

fn assemble(
    extraction_complete: bool,
    recipe: &CompositionRecipe,
    mut parts: Vec<CompositionPartReceipt>,
    encoded_parts: Vec<Option<Vec<u8>>>,
) -> Result<CompositionOutcome, CarrierError> {
    if parts.len() != encoded_parts.len() {
        return Err(CarrierError::InvalidCompositionRecipe);
    }
    let complete = extraction_complete && encoded_parts.iter().all(Option::is_some);
    let bytes = if complete {
        Some(assemble_bytes(&mut parts, encoded_parts)?)
    } else {
        None
    };
    let output_length = bytes.as_ref().map(Vec::len);
    let output_sha256 = bytes.as_ref().map(|bytes| crate::sha256(bytes));
    Ok(CompositionOutcome {
        receipt: CompositionReceipt {
            recipe: recipe.clone(),
            extraction_complete,
            complete,
            parts,
            output_length,
            output_sha256,
        },
        bytes,
    })
}

fn assemble_bytes(
    receipts: &mut [CompositionPartReceipt],
    parts: Vec<Option<Vec<u8>>>,
) -> Result<Vec<u8>, CarrierError> {
    let mut output = Vec::new();
    for (receipt, part) in receipts.iter_mut().zip(parts) {
        let part = part.ok_or(CarrierError::IncompleteComposition)?;
        if output
            .len()
            .checked_add(part.len())
            .is_none_or(|length| length > MAX_INPUT_BYTES)
        {
            return Err(CarrierError::RequestLimit);
        }
        receipt.composed_offset = Some(output.len());
        output.extend_from_slice(&part);
    }
    Ok(output)
}

/// Search transformation families on a complete composed byte stream
///
/// # Errors
/// Rejects incomplete composition or a search plan rejected by the bounded hypothesis engine
pub fn search_composed(
    composition: &CompositionOutcome,
    plan: &hypothesis::SearchPlan,
) -> Result<ComposedSearchOutcome, CarrierError> {
    let bytes = complete_bytes(composition)?;
    if bytes.len() > hypothesis::MAX_INPUT_BYTES {
        return Err(CarrierError::SearchInputLimit);
    }
    let search = hypothesis::search(bytes, plan).map_err(|_| CarrierError::SearchPlan)?;
    Ok(ComposedSearchOutcome {
        composition: composition.receipt().clone(),
        search,
    })
}

/// Apply a complete caller recipe to a composed byte stream
///
/// # Errors
/// Rejects incomplete composition or a recipe rejected by bounded derivation
pub fn derive_composed(
    composition: &CompositionOutcome,
    recipe: &derivation::Recipe,
) -> Result<ComposedDerivationOutcome, CarrierError> {
    let bytes = complete_bytes(composition)?;
    let derivation = derivation::run(bytes, recipe).map_err(|_| CarrierError::DerivationRecipe)?;
    Ok(ComposedDerivationOutcome {
        composition: composition.receipt().clone(),
        recipe: recipe.clone(),
        derivation,
    })
}

fn complete_bytes(composition: &CompositionOutcome) -> Result<&[u8], CarrierError> {
    if !composition.receipt().complete {
        return Err(CarrierError::IncompleteComposition);
    }
    composition
        .bytes()
        .ok_or(CarrierError::IncompleteComposition)
}
