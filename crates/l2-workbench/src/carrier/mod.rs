//! Explicit, source-backed projections for byte, bit, length, order, timing, DNS, and case carriers

mod builder;
mod composition;
pub mod discovery;
mod extract;
mod fingerprint;
mod model;
mod projection;
mod relationships;
mod resolve;
mod source;
mod timing;

pub use composition::{
    ComposedDerivationOutcome, ComposedSearchOutcome, CompositionEncoding, CompositionField,
    CompositionOutcome, CompositionPart, CompositionPartReceipt, CompositionPartStatus,
    CompositionReceipt, CompositionRecipe, LengthArithmetic, MAX_COMPOSITION_PARTS,
    PartialBytePadding, compose, derive_composed, search_composed,
};
pub use extract::extract;
pub use model::{
    Ambiguity, BitOrder, CarrierError, ClockSample, Field, FieldWidth, LengthMeaning,
    MAX_INPUT_BYTES, MAX_OBSERVATIONS, MAX_REPORT_RANGES, MAX_REPORT_VALUE_BYTES, MAX_RULES,
    MAX_SAMPLE_BYTES, MAX_SAMPLE_RANGES, MAX_SAMPLES, MAX_SOURCES, MAX_TOTAL_RANGES,
    NumericByteOrder, Observation, Omission, OmissionReason, Relationship, RelationshipMember,
    Report, Rule, Sample, TimingStatus, Value,
};
pub use source::SourceReader;

/// Verify that exact source mappings reconstruct the retained bytes for every sample
///
/// # Errors
/// Rejects invalid samples or mappings, changed sources, and any retained-byte disagreement
pub fn verify_sample_bytes(
    sources: &mut [SourceReader],
    samples: &[Sample<'_>],
    expected: &[&[u8]],
) -> Result<(), CarrierError> {
    if samples.len() != expected.len() {
        return Err(CarrierError::SampleContentMismatch);
    }
    let resolved = resolve::resolve_samples(sources, samples)?;
    if resolved
        .iter()
        .zip(expected)
        .any(|(sample, expected)| sample.bytes != *expected)
    {
        return Err(CarrierError::SampleContentMismatch);
    }
    Ok(())
}
