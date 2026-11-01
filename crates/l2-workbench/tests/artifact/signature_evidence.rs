use std::error::Error;

use l2_workbench::artifact::{scan_file_signatures, signature_evidence_matches_start};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn start_evidence_accepts_exact_and_masked_canonical_matches() -> TestResult {
    let inputs: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n",
        b"RIFF\x11\x22\x33\x44WAVEfmt ",
        b"\x89HDF\r\n\x1a\n",
        b"PK\x03\x04",
    ];
    for bytes in inputs {
        let report = scan_file_signatures(bytes);
        let matches: Vec<_> = report
            .matches
            .iter()
            .filter(|candidate| candidate.range.offset == 0)
            .collect();
        assert!(!matches.is_empty(), "fixture must have a start match");
        for candidate in matches {
            let mut details = serde_json::to_value(candidate)?;
            details
                .as_object_mut()
                .ok_or("signature evidence is not an object")?
                .insert("unrelated_context".to_owned(), json!("allowed"));
            assert!(signature_evidence_matches_start(bytes, &details));
        }
    }
    Ok(())
}

#[test]
fn start_evidence_rejects_each_missing_or_changed_canonical_field() -> TestResult {
    let bytes = b"RIFF\x11\x22\x33\x44WAVEfmt ";
    let report = scan_file_signatures(bytes);
    let candidate = report
        .matches
        .iter()
        .find(|matched| matched.rule_id == "riff-wave")
        .ok_or("masked fixture has no WAVE match")?;
    let canonical = serde_json::to_value(candidate)?;
    for field in [
        "ambiguous",
        "description",
        "extensions",
        "interpretation",
        "match_kind",
        "media_types",
        "pattern_hex",
        "possible_formats",
        "range",
        "reference",
        "rule_id",
        "observed_hex",
    ] {
        let mut changed = canonical.clone();
        changed
            .as_object_mut()
            .ok_or("signature evidence is not an object")?
            .insert(field.to_owned(), Value::Null);
        assert!(
            !signature_evidence_matches_start(bytes, &changed),
            "changed {field} must be rejected"
        );
        let mut missing = canonical.clone();
        missing
            .as_object_mut()
            .ok_or("signature evidence is not an object")?
            .remove(field);
        assert!(
            !signature_evidence_matches_start(bytes, &missing),
            "missing {field} must be rejected"
        );
    }
    let mut extra_range_field = canonical.clone();
    extra_range_field
        .get_mut("range")
        .and_then(Value::as_object_mut)
        .ok_or("signature range is not an object")?
        .insert("extra".to_owned(), json!(1));
    assert!(!signature_evidence_matches_start(bytes, &extra_range_field));
    assert!(!signature_evidence_matches_start(
        b"RIFX\x11\x22\x33\x44WAVEfmt ",
        &canonical
    ));
    Ok(())
}

#[test]
fn interior_and_forged_zero_offset_evidence_do_not_match_start() -> TestResult {
    let mut bytes = vec![0; 18 * 2_048];
    bytes
        .get_mut(16 * 2_048 + 1..16 * 2_048 + 6)
        .ok_or("fixture has no ISO descriptor range")?
        .copy_from_slice(b"CD001");
    let report = scan_file_signatures(&bytes);
    let interior = report
        .matches
        .iter()
        .find(|matched| matched.rule_id == "iso-9660")
        .ok_or("fixture has no interior ISO descriptor")?;
    let mut details = serde_json::to_value(interior)?;
    assert!(!signature_evidence_matches_start(&bytes, &details));
    details
        .get_mut("range")
        .and_then(Value::as_object_mut)
        .ok_or("signature range is not an object")?
        .insert("offset".to_owned(), json!(0));
    assert!(!signature_evidence_matches_start(&bytes, &details));
    Ok(())
}
