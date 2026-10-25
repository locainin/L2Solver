use super::{MAX_MEASURED_BYTES, MAX_SAMPLE_BYTES, MAX_SAMPLES, MeasurementError};
use serde::Serialize;

/// Byte-frequency and local-order measurements over explicit message samples
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ByteProfile {
    /// Number of samples in the request
    pub sample_count: usize,
    /// Sample lengths in the same order as the supplied inputs
    pub sample_lengths: Vec<usize>,
    /// Total retained sample bytes
    pub total_bytes: usize,
    /// Occurrence count for every byte value from 0 through 255
    pub byte_counts: Vec<u64>,
    /// One-bit counts in least-significant-bit-first order
    pub bit_ones: [u64; 8],
    /// Count of ASCII uppercase letters
    pub ascii_uppercase: u64,
    /// Count of ASCII lowercase letters
    pub ascii_lowercase: u64,
    /// Count of ASCII decimal digits
    pub ascii_digits: u64,
    /// Count of ASCII whitespace bytes
    pub ascii_whitespace: u64,
    /// Count of printable ASCII bytes
    pub ascii_printable: u64,
    /// Equal adjacent byte pairs within each sample, excluding sample boundaries
    pub adjacent_equal_pairs: u64,
    /// Distinct ordered adjacent-byte pairs across all samples
    pub distinct_adjacent_pairs: u64,
}

/// Measure literal byte counts, bit positions, ASCII classes, and adjacent pairs
///
/// Empty samples are valid and remain visible in the sample length list. The
/// function assigns no encryption, compression, or protocol meaning to counts
///
/// # Errors
/// Returns an error for an empty request or a sample, request-count, or byte limit
pub fn measure_bytes(samples: &[&[u8]]) -> Result<ByteProfile, MeasurementError> {
    validate_sample_count(samples.len())?;
    let mut profile = empty_profile(samples.len());
    let mut seen_pairs = vec![false; 65_536];
    for sample in samples {
        measure_sample(sample, &mut profile, &mut seen_pairs)?;
    }
    Ok(profile)
}

const fn validate_sample_count(count: usize) -> Result<(), MeasurementError> {
    if count == 0 {
        return Err(MeasurementError::InsufficientSamples { count, minimum: 1 });
    }
    if count > MAX_SAMPLES {
        return Err(MeasurementError::TooManySamples {
            count,
            maximum: MAX_SAMPLES,
        });
    }
    Ok(())
}

fn empty_profile(sample_count: usize) -> ByteProfile {
    ByteProfile {
        sample_count,
        sample_lengths: Vec::with_capacity(sample_count),
        total_bytes: 0,
        byte_counts: vec![0; 256],
        bit_ones: [0; 8],
        ascii_uppercase: 0,
        ascii_lowercase: 0,
        ascii_digits: 0,
        ascii_whitespace: 0,
        ascii_printable: 0,
        adjacent_equal_pairs: 0,
        distinct_adjacent_pairs: 0,
    }
}

fn measure_sample(
    sample: &[u8],
    profile: &mut ByteProfile,
    seen_pairs: &mut [bool],
) -> Result<(), MeasurementError> {
    if sample.len() > MAX_SAMPLE_BYTES {
        return Err(MeasurementError::SampleTooLarge {
            length: sample.len(),
            maximum: MAX_SAMPLE_BYTES,
        });
    }
    let total = profile.total_bytes.checked_add(sample.len()).ok_or(
        MeasurementError::TotalBytesExceeded {
            length: usize::MAX,
            maximum: MAX_MEASURED_BYTES,
        },
    )?;
    if total > MAX_MEASURED_BYTES {
        return Err(MeasurementError::TotalBytesExceeded {
            length: total,
            maximum: MAX_MEASURED_BYTES,
        });
    }
    profile.sample_lengths.push(sample.len());
    profile.total_bytes = total;
    let mut previous = None;
    for byte in sample.iter().copied() {
        measure_byte(byte, previous, profile, seen_pairs)?;
        previous = Some(byte);
    }
    Ok(())
}

fn measure_byte(
    byte: u8,
    previous: Option<u8>,
    profile: &mut ByteProfile,
    seen_pairs: &mut [bool],
) -> Result<(), MeasurementError> {
    let Some(count) = profile.byte_counts.get_mut(usize::from(byte)) else {
        return Err(MeasurementError::TotalBytesExceeded {
            length: usize::MAX,
            maximum: MAX_MEASURED_BYTES,
        });
    };
    *count += 1;
    for (bit, ones) in profile.bit_ones.iter_mut().enumerate() {
        if (byte >> bit) & 1 != 0 {
            *ones += 1;
        }
    }
    profile.ascii_uppercase += u64::from(byte.is_ascii_uppercase());
    profile.ascii_lowercase += u64::from(byte.is_ascii_lowercase());
    profile.ascii_digits += u64::from(byte.is_ascii_digit());
    profile.ascii_whitespace += u64::from(byte.is_ascii_whitespace());
    profile.ascii_printable += u64::from(byte.is_ascii_graphic() || byte == b' ');
    if let Some(previous) = previous {
        if previous == byte {
            profile.adjacent_equal_pairs += 1;
        }
        let pair = (usize::from(previous) << 8) | usize::from(byte);
        let Some(seen) = seen_pairs.get_mut(pair) else {
            return Err(MeasurementError::TotalBytesExceeded {
                length: usize::MAX,
                maximum: MAX_MEASURED_BYTES,
            });
        };
        if !*seen {
            *seen = true;
            profile.distinct_adjacent_pairs += 1;
        }
    }
    Ok(())
}
