//! Compare retained signature evidence without building a complete scan report

use super::{
    catalogue::SignatureRule,
    scan::{
        bytes_hex_matches, interpretation, match_kind, pattern_hex_matches, visit_start_matches,
    },
};
use serde_json::Value;

/// Check all canonical signature fields for a match at byte zero
///
/// Source identity and graph relationships must be checked by the caller
#[must_use]
pub fn signature_evidence_matches_start(bytes: &[u8], evidence: &Value) -> bool {
    let mut found = false;
    visit_start_matches(bytes, |rule, offset, observed| {
        found |= signature_fields_match(evidence, rule, offset, observed);
    });
    found
}

fn signature_fields_match(
    evidence: &Value,
    rule: &SignatureRule,
    offset: usize,
    observed: &[u8],
) -> bool {
    let (Ok(offset), Ok(length)) = (u64::try_from(offset), u64::try_from(observed.len())) else {
        return false;
    };
    let string_is = |field, expected| evidence.get(field).and_then(Value::as_str) == Some(expected);
    let array_is = |field, expected: &[&str]| {
        evidence
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|actual| {
                actual.len() == expected.len()
                    && actual
                        .iter()
                        .zip(expected)
                        .all(|(actual, expected)| actual.as_str() == Some(*expected))
            })
    };
    let range_matches = evidence
        .get("range")
        .and_then(Value::as_object)
        .is_some_and(|range| {
            range.len() == 2
                && range.get("offset").and_then(Value::as_u64) == Some(offset)
                && range.get("length").and_then(Value::as_u64) == Some(length)
        });
    evidence.get("ambiguous").and_then(Value::as_bool) == Some(rule.ambiguous)
        && string_is("description", rule.description)
        && array_is("extensions", rule.extensions)
        && string_is("interpretation", interpretation(rule.ambiguous))
        && string_is("match_kind", match_kind(&rule.pattern).label())
        && array_is("media_types", rule.media_types)
        && evidence
            .get("pattern_hex")
            .and_then(Value::as_str)
            .is_some_and(|expected| pattern_hex_matches(&rule.pattern, expected))
        && array_is("possible_formats", rule.formats)
        && range_matches
        && string_is("reference", rule.reference)
        && string_is("rule_id", rule.id)
        && evidence
            .get("observed_hex")
            .and_then(Value::as_str)
            .is_some_and(|expected| bytes_hex_matches(observed, expected))
}
