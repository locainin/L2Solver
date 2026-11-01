//! Suggest decoding steps from encoding syntax and compression headers
//!
//! The recovery scheduler uses these checks to choose plausible decoders for a byte source
//! One pass checks hexadecimal, four Base64 alphabet/padding combinations, gzip, and zlib
//! It returns recipes for the shared derivation engine, evidence for each decision, and exact
//! counts for candidates or assessment details omitted by the caller's retention budgets
//!
//! All seven checks run even when the returned lists are full, so a budget-limited report keeps
//! its omission counts accurate. The caller reserves scan work before requesting a pass
//! Recipe execution and structural artifact validation happen later in the recovery pipeline
//! A valid encoding or compression header supports an attempt; the decoded result still needs
//! its own integrity and format checks

use crate::{
    allocation::{Metered, Unrestricted, VectorAdmission, VectorAllocationError},
    derivation::{Base64Alphabet, Base64Padding, Operation, Recipe},
    job::{MemoryError, MemoryLease},
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[cfg(test)]
#[path = "../../tests/recovery/proposals/admission.rs"]
mod admission_tests;

/// Number of canonical operations checked by one complete proposal pass
pub const TRANSFORM_PROPOSAL_OPERATION_COUNT: usize = 7;

/// Version of the syntax proposal algorithm and serialized assessment format
pub const TRANSFORM_PROPOSAL_FORMAT_VERSION: u16 = 2;

/// Upper bound for byte visits in one complete syntax assessment pass
///
/// Hexadecimal and Base64 syntax each scan the input once. Gzip may scan two
/// disjoint optional fields and then checksum the header, so reserve two input
/// lengths for that operation. Zlib reads at most six fixed header bytes
#[must_use]
pub fn transform_proposal_scan_work_bound(input_length: usize) -> Option<usize> {
    if input_length == 0 {
        return Some(0);
    }

    // Seven input-length passes cover hex, four Base64 modes, and both gzip scans
    // The six-byte addition covers the optional zlib dictionary identifier
    input_length
        .checked_mul(TRANSFORM_PROPOSAL_OPERATION_COUNT)
        .and_then(|work| work.checked_add(6))
}

/// Caller-resolved limits for returned proposals and eligibility assessments
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
pub struct TransformProposalBudget {
    /// Maximum number of unique eligible execution recipes to return
    pub max_candidates: usize,
    /// Maximum number of per-operation eligibility assessments to return
    pub max_reports: usize,
}

/// One eligible single-operation recipe with the evidence supporting its proposal
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformProposal {
    /// Canonical recipe containing the proposed operation
    pub recipe: Recipe,
    /// Complete syntax or header evidence used for eligibility
    pub evidence: TransformEvidence,
}

/// Eligibility evidence attached to one proposed operation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformEvidence {
    /// Every input byte is part of a non-empty, even-length hexadecimal string
    HexSyntax { digit_count: usize },
    /// The complete input satisfies one canonical Base64 alphabet and padding mode
    Base64Syntax {
        alphabet: Base64Alphabet,
        padding: Base64Padding,
        encoded_bytes: usize,
        decoded_bytes: usize,
    },
    /// The gzip header, including any optional fields and header checksum, is valid
    GzipHeader {
        header_bytes: usize,
        flags: u8,
        header_crc_checked: bool,
    },
    /// The RFC 1950 header is valid, including a complete dictionary identifier when present
    ZlibHeader {
        cmf: u8,
        flg: u8,
        dictionary_id: Option<u32>,
    },
}

/// Why a syntactic candidate was not eligible for a proposal
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformIneligibility {
    /// Empty input has no bytes that identify an encoding or compression format
    EmptyInput,
    /// Hexadecimal input has an odd number of digits
    OddHexLength,
    /// Hexadecimal input contains a byte outside the ASCII hexadecimal alphabet
    InvalidHexDigit { offset: usize },
    /// The complete Base64 input fails the selected alphabet or padding rules
    InvalidBase64Syntax,
    /// The input does not contain a complete valid gzip header
    InvalidGzipHeader,
    /// The input does not contain a complete valid RFC 1950 header
    InvalidZlibHeader,
}

/// Result of checking one supported canonical operation against the complete input
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformAssessment {
    /// Operation checked in stable format order
    pub operation: Operation,
    /// Eligibility evidence or the reason no proposal was made
    pub result: TransformAssessmentResult,
}

/// Eligibility decision and, when eligible, its unique recipe's retention or alias status
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformAssessmentResult {
    /// Complete syntax or header evidence supports a proposal
    Eligible {
        evidence: TransformEvidence,
        disposition: TransformProposalDisposition,
    },
    /// The input does not satisfy this operation's complete syntax or header
    Ineligible { reason: TransformIneligibility },
}

/// Whether an eligible operation was retained, omitted, or aliases an earlier Base64 mode
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformProposalDisposition {
    /// The recipe is present in the returned proposal list
    Proposed,
    /// This operation is eligible, but its execution-class budget was full
    OmittedByCandidateBudget,
    /// This syntax mode decodes to the same bytes as an earlier eligible Base64 mode
    AliasOf {
        /// First eligible Base64 operation in the fixed assessment order
        representative: Operation,
    },
}

/// Counts for eligible candidates and assessments omitted by caller-selected budgets
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformProposalOmissions {
    /// Unique eligible recipes omitted by the candidate budget
    pub candidates: usize,
    /// Per-operation assessments omitted by the report budget
    pub reports: usize,
}

/// Deterministic proposals, bounded assessments, and explicit omission counts
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransformProposalReport {
    /// Unique eligible one-operation recipes in stable format order
    pub proposals: Vec<TransformProposal>,
    /// Per-operation results up to the caller-selected report budget
    pub assessments: Vec<TransformAssessment>,
    /// Unique eligible execution classes and assessments left out by the selected budgets
    pub omissions: TransformProposalOmissions,
}

/// Propose only complete hexadecimal, Base64, gzip, or zlib syntax candidates
///
/// The operation order is fixed: hexadecimal, standard Base64 required and forbidden,
/// URL-safe Base64 required and forbidden, gzip, then zlib. Eligibility uses only full
/// hexadecimal and Base64 syntax or a complete format header. It does not decode bytes,
/// validate compressed bodies, rank candidates, or infer keys and bytewise transforms
#[must_use]
pub fn propose_transforms(
    input: &[u8],
    budget: TransformProposalBudget,
) -> TransformProposalReport {
    match propose_inner(input, budget, &mut Unrestricted) {
        Ok(report) => report,
        Err(never) => match never {},
    }
}

#[derive(Debug)]
pub(crate) enum ProposalMemoryError {
    Memory(MemoryError),
    Allocation,
}

impl fmt::Display for ProposalMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Allocation => formatter.write_str("transform proposal allocation failed"),
        }
    }
}

impl Error for ProposalMemoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Allocation => None,
        }
    }
}

impl From<MemoryError> for ProposalMemoryError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

impl From<VectorAllocationError> for ProposalMemoryError {
    fn from(error: VectorAllocationError) -> Self {
        match error {
            VectorAllocationError::Memory(error) => Self::Memory(error),
            VectorAllocationError::Allocation => Self::Allocation,
        }
    }
}

/// The caller keeps this charge until the report and its moved recipes are dropped
pub(crate) fn propose_transforms_with_memory(
    input: &[u8],
    budget: TransformProposalBudget,
    memory: &mut MemoryLease,
) -> Result<TransformProposalReport, ProposalMemoryError> {
    let mut retained = memory.try_sibling(0)?;
    let report = propose_inner(input, budget, &mut Metered(&mut retained))?;
    memory.absorb(retained);
    Ok(report)
}

fn propose_inner<A: VectorAdmission>(
    input: &[u8],
    budget: TransformProposalBudget,
    admission: &mut A,
) -> Result<TransformProposalReport, A::Error> {
    let mut proposals = Vec::new();
    let mut assessments = Vec::new();
    let mut unique_eligible_count = 0_usize;
    let mut base64_representative = None;
    let mut report_count = 0_usize;

    // This fixed candidate list is the complete supported search space
    for candidate in candidate_kinds() {
        let operation = candidate.operation();
        let eligibility = assess(input, candidate);
        let result = match eligibility {
            Ok(evidence) => {
                let representative = match candidate {
                    CandidateKind::Base64 { .. } => base64_representative.clone(),
                    CandidateKind::Hex | CandidateKind::Gzip | CandidateKind::Zlib => None,
                };
                let disposition = if let Some(representative) = representative {
                    // Shared alphabet bytes and complete quartets decode equally across aliases
                    TransformProposalDisposition::AliasOf { representative }
                } else {
                    if matches!(candidate, CandidateKind::Base64 { .. }) {
                        base64_representative = Some(operation.clone());
                    }
                    unique_eligible_count += 1;
                    if proposals.len() < budget.max_candidates {
                        let mut steps = Vec::new();
                        admission.reserve_one(&mut steps)?;
                        steps.push(operation.clone());
                        admission.reserve_one(&mut proposals)?;
                        proposals.push(TransformProposal {
                            recipe: Recipe {
                                steps,
                                constraints: Vec::new(),
                            },
                            evidence: evidence.clone(),
                        });
                        TransformProposalDisposition::Proposed
                    } else {
                        TransformProposalDisposition::OmittedByCandidateBudget
                    }
                };
                TransformAssessmentResult::Eligible {
                    evidence,
                    disposition,
                }
            }
            Err(reason) => TransformAssessmentResult::Ineligible { reason },
        };

        report_count += 1;
        // Candidate generation continues after the report budget so omitted counts stay exact
        if assessments.len() < budget.max_reports {
            admission.reserve_one(&mut assessments)?;
            assessments.push(TransformAssessment { operation, result });
        }
    }

    Ok(TransformProposalReport {
        omissions: TransformProposalOmissions {
            candidates: unique_eligible_count - proposals.len(),
            reports: report_count - assessments.len(),
        },
        proposals,
        assessments,
    })
}

#[derive(Clone, Copy)]
enum CandidateKind {
    Hex,
    Base64 {
        alphabet: Base64Alphabet,
        padding: Base64Padding,
    },
    Gzip,
    Zlib,
}

impl CandidateKind {
    const fn operation(self) -> Operation {
        match self {
            Self::Hex => Operation::HexDecode {},
            Self::Base64 { alphabet, padding } => Operation::Base64Decode { alphabet, padding },
            Self::Gzip => Operation::GzipDecompress {},
            Self::Zlib => Operation::ZlibDecompress {},
        }
    }
}

const fn candidate_kinds() -> [CandidateKind; TRANSFORM_PROPOSAL_OPERATION_COUNT] {
    [
        CandidateKind::Hex,
        CandidateKind::Base64 {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        },
        CandidateKind::Base64 {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Forbidden,
        },
        CandidateKind::Base64 {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Required,
        },
        CandidateKind::Base64 {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Forbidden,
        },
        CandidateKind::Gzip,
        CandidateKind::Zlib,
    ]
}

/// Return the exact ordered operation templates considered by proposal discovery
pub fn transform_proposal_operations() -> impl Iterator<Item = Operation> {
    candidate_kinds().into_iter().map(CandidateKind::operation)
}

fn assess(
    input: &[u8],
    candidate: CandidateKind,
) -> Result<TransformEvidence, TransformIneligibility> {
    if input.is_empty() {
        return Err(TransformIneligibility::EmptyInput);
    }

    match candidate {
        CandidateKind::Hex => assess_hex(input),
        CandidateKind::Base64 { alphabet, padding } => {
            let decoded_bytes = base64_decoded_length(input, alphabet, padding)
                .ok_or(TransformIneligibility::InvalidBase64Syntax)?;
            Ok(TransformEvidence::Base64Syntax {
                alphabet,
                padding,
                encoded_bytes: input.len(),
                decoded_bytes,
            })
        }
        CandidateKind::Gzip => gzip_header(input),
        CandidateKind::Zlib => zlib_header(input),
    }
}

fn assess_hex(input: &[u8]) -> Result<TransformEvidence, TransformIneligibility> {
    if !input.len().is_multiple_of(2) {
        return Err(TransformIneligibility::OddHexLength);
    }

    // Reuse the same ASCII digit parser as the canonical hexadecimal operation
    for (offset, byte) in input.iter().copied().enumerate() {
        if crate::hex::decode_nibble(byte).is_none() {
            return Err(TransformIneligibility::InvalidHexDigit { offset });
        }
    }

    Ok(TransformEvidence::HexSyntax {
        digit_count: input.len(),
    })
}

fn base64_decoded_length(
    input: &[u8],
    alphabet: Base64Alphabet,
    padding: Base64Padding,
) -> Option<usize> {
    let mut symbol_count = 0_usize;
    let mut padding_count = 0_usize;
    let mut padding_started = false;
    let mut last_symbol = None;

    // Validate symbols and the terminal padding in one bounded input pass
    for byte in input.iter().copied() {
        if byte == b'=' {
            padding_started = true;
            padding_count += 1;
            if padding_count > 2 {
                return None;
            }
            continue;
        }
        if padding_started {
            return None;
        }
        last_symbol = Some(base64_symbol(byte, alphabet)?);
        symbol_count += 1;
    }

    let symbol_remainder = symbol_count % 4;
    if symbol_remainder == 1 {
        return None;
    }

    match padding {
        Base64Padding::Required => {
            if !input.len().is_multiple_of(4) {
                return None;
            }
            let expected_padding = match symbol_remainder {
                0 => 0,
                2 => 2,
                3 => 1,
                _ => return None,
            };
            if padding_count != expected_padding {
                return None;
            }
        }
        Base64Padding::Forbidden => {
            if padding_count != 0 {
                return None;
            }
        }
    }

    // Canonical Base64 requires unused bits in the last symbol to be zero
    let unused_bit_mask = match symbol_remainder {
        2 => 0x0f,
        3 => 0x03,
        _ => 0,
    };
    if last_symbol.is_some_and(|symbol| symbol & unused_bit_mask != 0) {
        return None;
    }

    let full_groups = (symbol_count / 4) * 3;
    let partial_group = (symbol_remainder * 6) / 8;
    full_groups.checked_add(partial_group)
}

fn base64_symbol(byte: u8, alphabet: Base64Alphabet) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' if alphabet == Base64Alphabet::Standard => Some(62),
        b'/' if alphabet == Base64Alphabet::Standard => Some(63),
        b'-' if alphabet == Base64Alphabet::UrlSafe => Some(62),
        b'_' if alphabet == Base64Alphabet::UrlSafe => Some(63),
        _ => None,
    }
}

fn gzip_header(input: &[u8]) -> Result<TransformEvidence, TransformIneligibility> {
    let invalid_header = || TransformIneligibility::InvalidGzipHeader;
    if input.len() < 10 || input.first() != Some(&0x1f) || input.get(1) != Some(&0x8b) {
        return Err(invalid_header());
    }
    if input.get(2) != Some(&8) {
        return Err(invalid_header());
    }

    let flags = input.get(3).copied().ok_or_else(invalid_header)?;
    if flags & 0xe0 != 0 {
        return Err(invalid_header());
    }

    let mut cursor = 10_usize;
    if flags & 0x04 != 0 {
        let extra_length_end = cursor.checked_add(2).ok_or_else(invalid_header)?;
        let extra_length_bytes = input
            .get(cursor..extra_length_end)
            .ok_or_else(invalid_header)?;
        let extra_length = usize::from(*extra_length_bytes.first().ok_or_else(invalid_header)?)
            | (usize::from(*extra_length_bytes.get(1).ok_or_else(invalid_header)?) << 8);
        let extra_end = extra_length_end
            .checked_add(extra_length)
            .ok_or_else(invalid_header)?;
        input
            .get(extra_length_end..extra_end)
            .ok_or_else(invalid_header)?;
        cursor = extra_end;
    }

    if flags & 0x08 != 0 {
        cursor = after_zero_terminated_field(input, cursor).ok_or_else(invalid_header)?;
    }
    if flags & 0x10 != 0 {
        cursor = after_zero_terminated_field(input, cursor).ok_or_else(invalid_header)?;
    }

    let header_crc_checked = flags & 0x02 != 0;
    if header_crc_checked {
        let checksum_end = cursor.checked_add(2).ok_or_else(invalid_header)?;
        let checksum_bytes = input.get(cursor..checksum_end).ok_or_else(invalid_header)?;
        let expected = u16::from_le_bytes([
            *checksum_bytes.first().ok_or_else(invalid_header)?,
            *checksum_bytes.get(1).ok_or_else(invalid_header)?,
        ]);
        let header_bytes = input.get(..cursor).ok_or_else(invalid_header)?;
        let [crc_low, crc_high, _, _] = crc32fast::hash(header_bytes).to_le_bytes();
        let actual = u16::from_le_bytes([crc_low, crc_high]);
        if actual != expected {
            return Err(invalid_header());
        }
        cursor = checksum_end;
    }

    Ok(TransformEvidence::GzipHeader {
        header_bytes: cursor,
        flags,
        header_crc_checked,
    })
}

fn after_zero_terminated_field(input: &[u8], start: usize) -> Option<usize> {
    let field = input.get(start..)?;
    let terminator_offset = field.iter().position(|byte| *byte == 0)?;
    start.checked_add(terminator_offset)?.checked_add(1)
}

fn zlib_header(input: &[u8]) -> Result<TransformEvidence, TransformIneligibility> {
    let invalid_header = || TransformIneligibility::InvalidZlibHeader;
    let cmf = input.first().copied().ok_or_else(invalid_header)?;
    let flg = input.get(1).copied().ok_or_else(invalid_header)?;
    let compression_method = cmf & 0x0f;
    let window_size_info = cmf >> 4;
    let header_word = (u16::from(cmf) << 8) | u16::from(flg);

    if compression_method != 8 || window_size_info > 7 || header_word % 31 != 0 {
        return Err(invalid_header());
    }

    let dictionary_id = if flg & 0x20 != 0 {
        let bytes = input.get(2..6).ok_or_else(invalid_header)?;
        Some(u32::from_be_bytes([
            *bytes.first().ok_or_else(invalid_header)?,
            *bytes.get(1).ok_or_else(invalid_header)?,
            *bytes.get(2).ok_or_else(invalid_header)?,
            *bytes.get(3).ok_or_else(invalid_header)?,
        ]))
    } else {
        None
    };

    Ok(TransformEvidence::ZlibHeader {
        cmf,
        flg,
        dictionary_id,
    })
}
