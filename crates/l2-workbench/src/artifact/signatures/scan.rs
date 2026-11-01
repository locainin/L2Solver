use super::catalogue::{
    CATALOGUE_REVIEWED_ON, CATALOGUE_SOURCE, CATALOGUE_VERSION, Pattern, SignatureOffsets,
    SignatureRule, rule_count, rules,
};
use super::model::{
    FileSignatureCatalogue, FileSignatureMatch, FileSignatureMatchKind, FileSignatureReport,
};
use crate::artifact::FileRange;

const EXACT_INTERPRETATION: &str = "The bytes match a published signature at its declared offset and support a format candidate; this does not prove a complete object, structural validity, delivery, execution, or malicious intent";
const AMBIGUOUS_INTERPRETATION: &str = "The bytes match a shared or container signature at its declared offset and support a candidate; this does not prove an application subtype, complete object, structural validity, delivery, execution, or malicious intent";
const ISO_9660_LOGICAL_SECTOR_SIZE: usize = 2_048;
const LIMITATIONS: &[&str] = &[
    "A signature match is a byte-pattern observation; it does not establish a complete or valid file, a container subtype, delivery, execution, or malicious intent",
    "The checked-in catalogue covers supported high-value signatures and declared offsets; no match does not establish that bytes lack a file format",
    "Automatic evaluation does not search arbitrary interior offsets because short signatures can occur incidentally in unrelated payloads",
];

/// Evaluate every built-in rule at its format-defined offset
///
/// The operation is deterministic and examines the complete supplied slice. It does not
/// infer an extension, carve interior objects, or choose one meaning for shared signatures.
#[must_use]
pub fn scan_file_signatures(bytes: &[u8]) -> FileSignatureReport {
    let matches = file_signature_matches(bytes);
    FileSignatureReport {
        schema_version: 1,
        source_sha256: crate::sha256(bytes),
        source_length: bytes.len(),
        catalogue: FileSignatureCatalogue {
            version: CATALOGUE_VERSION,
            name: "l2solver-file-signatures",
            source: CATALOGUE_SOURCE,
            reviewed_on: CATALOGUE_REVIEWED_ON,
            rules_evaluated: rule_count(),
        },
        matches,
        limitations: LIMITATIONS,
    }
}

fn file_signature_matches(bytes: &[u8]) -> Vec<FileSignatureMatch> {
    let mut matches = Vec::new();
    visit_file_signature_matches(bytes, |rule, offset, observed| {
        matches.push(observation(rule, offset, observed));
    });
    // Offset order makes the evidence easy to read while the stable ID breaks ties
    matches.sort_by(|left, right| {
        left.range
            .offset
            .cmp(&right.range.offset)
            .then_with(|| left.rule_id.cmp(right.rule_id))
    });
    matches
}

pub(in crate::artifact) fn count_file_signature_matches(bytes: &[u8]) -> usize {
    let mut count = 0;
    visit_file_signature_matches(bytes, |_, _, _| count += 1);
    count
}

pub(in crate::artifact) fn matches_zip_signature(bytes: &[u8]) -> bool {
    let (prefix, _) = bytes.split_at(bytes.len().min(8));
    let mut found = false;
    visit_file_signature_matches(prefix, |rule, _, _| {
        found |= rule.formats.contains(&"zip_container");
    });
    found
}

fn visit_file_signature_matches(
    bytes: &[u8],
    mut visit: impl FnMut(&'static SignatureRule, usize, &[u8]),
) {
    for rule in rules() {
        let mut inspect_offset = |offset| {
            if let Some(observed) = matching_bytes(bytes, offset, &rule.pattern) {
                visit(rule, offset, observed);
                true
            } else {
                false
            }
        };
        match rule.offsets {
            SignatureOffsets::Declared(offsets) => {
                for offset in offsets {
                    inspect_offset(*offset);
                }
            }
            SignatureOffsets::Hdf5Superblocks => {
                inspect_offset(0);
                let Some(last_start) = bytes.len().checked_sub(rule.pattern.length()) else {
                    continue;
                };
                let mut offset = 512_usize;
                while offset <= last_start {
                    inspect_offset(offset);
                    let Some(next) = offset.checked_mul(2) else {
                        break;
                    };
                    offset = next;
                }
            }
            SignatureOffsets::Iso9660VolumeDescriptors => {
                // This strategy uses 2048-byte logical sectors, beginning at sector 16
                let Some(mut descriptor_start) = 16_usize.checked_mul(ISO_9660_LOGICAL_SECTOR_SIZE)
                else {
                    continue;
                };
                while let Some(identifier_offset) = descriptor_start.checked_add(1) {
                    if !inspect_offset(identifier_offset) {
                        break;
                    }

                    // Type 255 marks the end of this descriptor set
                    if bytes.get(descriptor_start) == Some(&u8::MAX) {
                        break;
                    }
                    let Some(next_descriptor_start) =
                        descriptor_start.checked_add(ISO_9660_LOGICAL_SECTOR_SIZE)
                    else {
                        break;
                    };
                    descriptor_start = next_descriptor_start;
                }
            }
        }
    }
}

fn matching_bytes<'a>(bytes: &'a [u8], offset: usize, pattern: &Pattern) -> Option<&'a [u8]> {
    let end = offset.checked_add(pattern.length())?;
    let observed = bytes.get(offset..end)?;
    let matched = match pattern {
        Pattern::Exact(expected) => observed == *expected,
        Pattern::Masked(expected) => expected
            .iter()
            .zip(observed)
            .all(|(candidate, actual)| candidate.is_none_or(|byte| byte == *actual)),
    };
    matched.then_some(observed)
}

fn observation(rule: &'static SignatureRule, offset: usize, observed: &[u8]) -> FileSignatureMatch {
    let match_kind = match rule.pattern {
        Pattern::Exact(_) => FileSignatureMatchKind::Exact,
        Pattern::Masked(_) => FileSignatureMatchKind::Masked,
    };
    FileSignatureMatch {
        rule_id: rule.id,
        description: rule.description,
        possible_formats: rule.formats,
        extensions: rule.extensions,
        media_types: rule.media_types,
        reference: rule.reference,
        range: FileRange {
            offset,
            length: observed.len(),
        },
        pattern_hex: pattern_hex(&rule.pattern),
        observed_hex: bytes_hex(observed),
        match_kind,
        ambiguous: rule.ambiguous,
        interpretation: if rule.ambiguous {
            AMBIGUOUS_INTERPRETATION
        } else {
            EXACT_INTERPRETATION
        },
    }
}

fn pattern_hex(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Exact(bytes) => bytes_hex(bytes),
        Pattern::Masked(bytes) => {
            let mut output = String::with_capacity(bytes.len().saturating_mul(3));
            for (index, byte) in bytes.iter().enumerate() {
                if index != 0 {
                    output.push(' ');
                }
                if let Some(byte) = byte {
                    push_hex_byte(&mut output, *byte);
                } else {
                    output.push_str("??");
                }
            }
            output
        }
    }
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push(' ');
        }
        push_hex_byte(&mut output, *byte);
    }
    output
}

fn push_hex_byte(output: &mut String, byte: u8) {
    output.push(hex_digit(byte >> 4));
    output.push(hex_digit(byte & 0x0f));
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}
