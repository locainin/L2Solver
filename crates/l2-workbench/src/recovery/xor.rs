//! Bounded hypotheses for repeating XOR over structured text
//!
//! Candidates are provisional: text structure does not prove a key or protocol

use crate::{
    allocation::{Metered, Unrestricted, VectorAdmission, VectorAllocationError},
    derivation::{Operation, Recipe},
    job::{MemoryError, MemoryLease},
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// Version of XOR scoring, search limits, message normalization, and evidence format
pub const XOR_PROPOSAL_FORMAT_VERSION: u16 = 1;
/// Maximum number of prefix bytes inspected from one source
pub const XOR_SAMPLE_BYTES: usize = 4096;
/// Maximum retained hypotheses independent of the requested budget
pub const XOR_MAX_CANDIDATES: usize = 32;
const MIN_SAMPLE_BYTES: usize = 48;
const MAX_PERIOD: usize = 4;
const PHASE_CHOICES: usize = 4;
const BEAM_WIDTH: usize = 16;
const SINGLE_BYTE_CHOICES: usize = 32;

/// Structure observed in the decoded prefix of a provisional key hypothesis
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XorEvidence {
    pub sample_bytes: usize,
    pub printable_bytes: usize,
    pub alphabetic_bytes: usize,
    pub complete_lines: usize,
    pub distinct_line_lengths: usize,
    pub text_score: i64,
}

/// A candidate recipe and the observed text structure supporting an attempt
#[derive(Clone, Eq, PartialEq)]
pub struct XorProposal {
    pub recipe: Recipe,
    pub evidence: XorEvidence,
}

impl fmt::Debug for XorProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XorProposal")
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

/// Retained hypotheses and limitations of the bounded discovery pass
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XorProposalReport {
    pub proposals: Vec<XorProposal>,
    /// Eligible hypotheses excluded by the candidate retention limit
    pub omitted_candidates: usize,
    /// The bounded beam leaves other key hypotheses unexamined
    pub search_truncated: bool,
    /// Only the prefix was assessed when the source exceeds the sample limit
    pub sample_truncated: bool,
}

/// Failure to reserve storage for a bounded XOR search
#[derive(Debug)]
pub enum XorProposalError {
    Memory(MemoryError),
    Allocation,
}

impl fmt::Display for XorProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Allocation => formatter.write_str("xor proposal allocation failed"),
        }
    }
}

impl Error for XorProposalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Allocation => None,
        }
    }
}

impl From<VectorAllocationError> for XorProposalError {
    fn from(error: VectorAllocationError) -> Self {
        match error {
            VectorAllocationError::Memory(error) => Self::Memory(error),
            VectorAllocationError::Allocation => Self::Allocation,
        }
    }
}

/// Upper bound on byte visits and histogram scoring for one discovery pass
#[must_use]
pub fn xor_proposal_scan_work_bound(input_length: usize) -> Option<usize> {
    let sample = input_length.min(XOR_SAMPLE_BYTES);
    if sample < MIN_SAMPLE_BYTES {
        return Some(0);
    }
    // Every period builds a histogram; each phase scores all byte/key combinations
    let histogram_scores = (1 + 2 + 3 + 4) * 256 * 256;
    // A partial UTF-8 tail may require a second validation of the prefix
    let hypothesis_visits = (SINGLE_BYTE_CHOICES + (MAX_PERIOD - 1) * BEAM_WIDTH) * 4;
    sample
        .checked_mul(MAX_PERIOD + hypothesis_visits + 3)?
        .checked_add(histogram_scores)
}

/// Discover bounded, provisional XOR recipes for structured multiline text
///
/// The sample is at most 4096 bytes and keys have periods one through four. Search
/// uses a fixed beam and can miss valid keys; a retained result is not identification.
#[must_use]
pub fn propose_xor(input: &[u8], max_candidates: usize) -> XorProposalReport {
    match propose_xor_inner(input, max_candidates, &mut Unrestricted) {
        Ok(report) => report,
        Err(never) => match never {},
    }
}

/// Discover XOR hypotheses while charging all detector allocations to a shared lease
///
/// Keep the lease alive while the report is retained. Temporary allocations remain
/// conservatively charged until the lease is released. Failure preserves the incoming charge.
///
/// # Errors
/// Returns an allocation or memory admission error
pub fn propose_xor_with_memory(
    input: &[u8],
    max_candidates: usize,
    memory: &mut MemoryLease,
) -> Result<XorProposalReport, XorProposalError> {
    let mut retained = memory.try_sibling(0).map_err(XorProposalError::Memory)?;
    let report = propose_xor_inner(input, max_candidates, &mut Metered(&mut retained))?;
    memory.absorb(retained);
    Ok(report)
}

fn propose_xor_inner<A: VectorAdmission>(
    input: &[u8],
    max_candidates: usize,
    admission: &mut A,
) -> Result<XorProposalReport, A::Error> {
    let sample = input
        .get(..input.len().min(XOR_SAMPLE_BYTES))
        .unwrap_or(input);
    let mut report = XorProposalReport {
        proposals: Vec::new(),
        omitted_candidates: 0,
        search_truncated: false,
        sample_truncated: input.len() > sample.len(),
    };
    if sample.len() < MIN_SAMPLE_BYTES || already_structured(sample, report.sample_truncated) {
        return Ok(report);
    }
    // A fixed beam keeps the key search finite, so omissions remain explicit
    report.search_truncated = true;

    // Evaluate a bounded beam at each period while preserving phase at byte zero
    let mut eligible = Vec::new();
    for period in 1..=MAX_PERIOD {
        let mut histograms = [[0_u32; 256]; MAX_PERIOD];
        for (position, byte) in sample.iter().copied().enumerate() {
            if let Some(count) = histograms
                .get_mut(position % period)
                .and_then(|histogram| histogram.get_mut(usize::from(byte)))
            {
                *count += 1;
            }
        }
        for key in key_beam(&histograms, period, admission)? {
            let Some(key_bytes) = key.bytes.get(..period) else {
                continue;
            };
            // Skip identity and repeated keys already represented at a shorter period
            if key_bytes.iter().all(|byte| *byte == 0) || has_shorter_period(key_bytes) {
                continue;
            }
            if let Some(evidence) = assess(sample, key_bytes, key.score, report.sample_truncated) {
                admission.reserve_one(&mut eligible)?;
                eligible.push((key, period, evidence));
            }
        }
    }
    eligible.sort_unstable_by(|left, right| {
        right
            .2
            .text_score
            .cmp(&left.2.text_score)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.0.bytes.cmp(&right.0.bytes))
    });
    let keep = max_candidates.min(XOR_MAX_CANDIDATES).min(eligible.len());
    report.omitted_candidates = eligible.len() - keep;
    for (key, period, evidence) in eligible.into_iter().take(keep) {
        let mut key_bytes = Vec::new();
        for byte in key.bytes.iter().take(period) {
            admission.reserve_one(&mut key_bytes)?;
            key_bytes.push(*byte);
        }
        let mut steps = Vec::new();
        admission.reserve_one(&mut steps)?;
        steps.push(Operation::XorRepeat {
            key: key_bytes,
            offset: 0,
        });
        admission.reserve_one(&mut report.proposals)?;
        report.proposals.push(XorProposal {
            recipe: Recipe {
                steps,
                constraints: Vec::new(),
            },
            evidence,
        });
    }
    Ok(report)
}

#[derive(Clone, Copy)]
struct KeyScore {
    bytes: [u8; MAX_PERIOD],
    score: i64,
}

fn key_beam<A: VectorAdmission>(
    histograms: &[[u32; 256]; MAX_PERIOD],
    period: usize,
    admission: &mut A,
) -> Result<Vec<KeyScore>, A::Error> {
    let mut beam = Vec::new();
    admission.reserve_one(&mut beam)?;
    beam.push(KeyScore {
        bytes: [0; MAX_PERIOD],
        score: 0,
    });
    for (phase, histogram) in histograms.iter().enumerate().take(period) {
        let mut choices = Vec::new();
        for key in u8::MIN..=u8::MAX {
            // Score each possible phase byte from counts, without rescanning the sample
            let score: i64 = (u8::MIN..=u8::MAX)
                .zip(histogram)
                .map(|(byte, count)| i64::from(*count) * text_byte_score(byte ^ key))
                .sum();
            admission.reserve_one(&mut choices)?;
            choices.push((key, score));
        }
        choices.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
        });
        let width = if period == 1 {
            SINGLE_BYTE_CHOICES
        } else {
            PHASE_CHOICES
        };
        let mut next = Vec::new();
        for previous in &beam {
            for (key, score) in choices.iter().take(width) {
                let mut candidate = *previous;
                if let Some(phase_byte) = candidate.bytes.get_mut(phase) {
                    *phase_byte = *key;
                }
                candidate.score += *score;
                admission.reserve_one(&mut next)?;
                next.push(candidate);
            }
        }
        next.sort_unstable_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.bytes.cmp(&right.bytes))
        });
        next.truncate(if period == 1 {
            SINGLE_BYTE_CHOICES
        } else {
            BEAM_WIDTH
        });
        beam = next;
    }
    Ok(beam)
}

const fn text_byte_score(byte: u8) -> i64 {
    // Prefer common text bytes while allowing punctuation and message separators
    match byte {
        b' ' => 7,
        b'e' | b't' | b'a' | b'o' | b'i' | b'n' => 6,
        b'a'..=b'z' => 5,
        b'A'..=b'Z' => 4,
        b'0'..=b'9' | b'\n' | b'\r' | b'\t' => 3,
        0x21..=0x7e => 2,
        _ => -12,
    }
}

fn has_shorter_period(key: &[u8]) -> bool {
    (1..key.len()).any(|period| {
        key.len().is_multiple_of(period)
            && key
                .iter()
                .enumerate()
                .all(|(i, byte)| Some(byte) == key.get(i % period))
    })
}

fn already_structured(sample: &[u8], sample_truncated: bool) -> bool {
    let Some(text) = valid_text_prefix(sample, sample_truncated) else {
        return false;
    };
    let (printable, newlines) = text
        .chars()
        .fold((0, 0), |(printable, newlines), character| {
            (
                printable
                    + character.len_utf8()
                        * usize::from(
                            !character.is_control() || matches!(character, '\n' | '\r' | '\t'),
                        ),
                newlines + usize::from(character == '\n'),
            )
        });
    printable * 100 >= text.len() * 95 && newlines >= 3
}

fn valid_text_prefix(bytes: &[u8], sample_truncated: bool) -> Option<&str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(error) if sample_truncated && error.error_len().is_none() => {
            std::str::from_utf8(bytes.get(..error.valid_up_to())?).ok()
        }
        Err(_) => None,
    }
}

fn assess(sample: &[u8], key: &[u8], score: i64, sample_truncated: bool) -> Option<XorEvidence> {
    let mut decoded = [0_u8; XOR_SAMPLE_BYTES];
    for (position, encrypted) in sample.iter().copied().enumerate() {
        *decoded.get_mut(position)? = encrypted ^ key.get(position % key.len())?;
    }
    let decoded = decoded.get(..sample.len())?;
    // A bounded prefix may end in the middle of one valid UTF-8 character
    let text = valid_text_prefix(decoded, sample_truncated)?;
    let mut printable = 0;
    let mut alphabetic = 0;
    let mut lines = 0;
    let mut line_length = 0_usize;
    let mut line_lengths = [false; 513];
    let mut separators = 0;
    for character in text.chars() {
        let length = character.len_utf8();
        printable += length
            * usize::from(!character.is_control() || matches!(character, '\n' | '\r' | '\t'));
        alphabetic += length * usize::from(character.is_alphabetic());
        separators += length
            * usize::from(
                character == ' ' || character.is_ascii_punctuation() || character.is_ascii_digit(),
            );
        if character == '\n' {
            if (3..=512).contains(&line_length) {
                lines += 1;
                if let Some(seen) = line_lengths.get_mut(line_length) {
                    *seen = true;
                }
            }
            line_length = 0;
        } else if character != '\r' {
            line_length = line_length.saturating_add(length);
        }
    }
    let distinct = line_lengths.into_iter().filter(|present| *present).count();
    // Multiple varied complete lines and readable text are required together
    if printable * 100 < text.len() * 95
        || alphabetic * 100 < text.len() * 35
        || separators * 100 < text.len() * 10
        || lines < 3
        || distinct < 2
    {
        return None;
    }
    Some(XorEvidence {
        sample_bytes: sample.len(),
        printable_bytes: printable,
        alphabetic_bytes: alphabetic,
        complete_lines: lines,
        distinct_line_lengths: distinct,
        text_score: score,
    })
}
