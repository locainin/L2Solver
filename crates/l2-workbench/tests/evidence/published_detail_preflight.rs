use super::{canonical, replace_record_value, write_published_case};
use l2_workbench::evidence::{
    Case, MAX_NODE_DETAILS_BYTES, PublishedEvidenceLimits, decode_published_evidence,
};
use serde_json::{Value, json};
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(version: u32) -> TestResult<Vec<u8>> {
    let bytes: &[u8] = if version == 3 {
        include_bytes!("fixtures/published-v3.jsonl")
    } else {
        include_bytes!("fixtures/published-v4.jsonl")
    };
    replace_record_value(bytes, "header", "/value/version", json!(version))
}

fn dictionary_attack(version: u32, value: &str, references: usize) -> TestResult<Vec<u8>> {
    let bytes = fixture(version)?;
    let header: Value = serde_json::from_slice(
        bytes
            .split(|byte| *byte == b'\n')
            .next()
            .ok_or("header is missing")?,
    )?;
    let mut dictionary = header
        .pointer("/value/strings")
        .and_then(Value::as_array)
        .ok_or("dictionary is missing")?
        .clone();
    let index = dictionary.len();
    dictionary.push(json!(value));
    let bytes = replace_record_value(&bytes, "header", "/value/strings", json!(dictionary))?;
    let details = if version == 3 {
        let mut fields: Vec<Value> = (0..references)
            .map(|number| json!([format!("key_{number}"), {"kind":"text","value":index}]))
            .collect();
        fields.push(json!(["sentinel", {"kind":"text","value":99999}]));
        json!({"kind":"object","value":fields})
    } else {
        let mut fields: Vec<Value> = (0..references)
            .map(|number| json!([format!("key_{number}"), 0, index]))
            .collect();
        fields.push(json!(["sentinel", 0, 99999]));
        json!([0, fields])
    };
    replace_record_value(&bytes, "node", "/value/4", details)
}

fn expect_early_detail_limit(version: u32, bytes: Vec<u8>) -> TestResult {
    let error = decode_published_evidence(
        version,
        Cursor::new(bytes),
        Vec::new(),
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )
    .err()
    .ok_or("oversized details must be rejected")?;
    assert!(
        error
            .to_string()
            .contains("node details exceed their limit"),
        "detail expansion must stop before the later invalid reference: {error}"
    );
    Ok(())
}

#[test]
fn oversized_dictionary_values_stop_before_later_references_in_all_versions() -> TestResult {
    for version in 3..=6 {
        expect_early_detail_limit(
            version,
            dictionary_attack(version, &"x".repeat(MAX_NODE_DETAILS_BYTES + 1), 1)?,
        )?;
    }
    Ok(())
}

#[test]
fn repeated_dictionary_values_are_counted_before_they_are_cloned() -> TestResult {
    for version in 3..=6 {
        expect_early_detail_limit(version, dictionary_attack(version, &"x".repeat(1000), 5)?)?;
    }
    Ok(())
}

#[test]
fn raw_detail_values_stop_before_later_references_in_all_versions() -> TestResult {
    for version in 3..=6 {
        let details = if version == 3 {
            json!({"kind":"object","value":[
                ["first", {"kind":"value","value":"x".repeat(MAX_NODE_DETAILS_BYTES + 1)}],
                ["sentinel", {"kind":"text","value":99999}]
            ]})
        } else {
            json!([
                0,
                [
                    ["first", 1, "x".repeat(MAX_NODE_DETAILS_BYTES + 1)],
                    ["sentinel", 0, 99999]
                ]
            ])
        };
        let forged = replace_record_value(&fixture(version)?, "node", "/value/4", details)?;
        expect_early_detail_limit(version, forged)?;
    }
    Ok(())
}

#[test]
fn non_object_raw_details_are_bounded_before_value_construction() -> TestResult {
    for version in 3..=6 {
        let raw = json!(["x".repeat(MAX_NODE_DETAILS_BYTES + 1)]);
        let details = if version == 3 {
            json!({"kind":"value","value":raw})
        } else {
            json!([1, raw])
        };
        let forged = replace_record_value(&fixture(version)?, "node", "/value/4", details)?;
        expect_early_detail_limit(version, forged)?;
    }
    Ok(())
}

#[test]
fn digest_references_are_counted_before_later_invalid_references() -> TestResult {
    let mut fields: Vec<Value> = (0..70)
        .map(|number| json!([format!("key_{number}"), 2, null]))
        .collect();
    fields.push(json!(["sentinel", 0, 99999]));
    for version in 5..=6 {
        let forged =
            replace_record_value(&fixture(version)?, "node", "/value/4", json!([0, fields]))?;
        expect_early_detail_limit(version, forged)?;
    }
    Ok(())
}

fn case_with_raw_details(version: u32, raw: &str) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let details: Value = serde_json::from_str(raw)?;
    let mut case = Case::new();
    case.add_node("probe", None, Vec::new(), details)?;
    let scope = json!({"kind":"detail_preflight"});
    let (_, canonical) = canonical(&case, &scope, 1)?;
    let mut bytes = Vec::new();
    write_published_case(&case, &scope, 1, &mut bytes)?;
    let bytes = replace_record_value(&bytes, "header", "/value/version", json!(version))?;
    let marker = "detail_preflight_raw_value_marker";
    let wrapper = if version == 3 {
        json!({"kind":"value","value":marker})
    } else {
        json!([1, marker])
    };
    let bytes = replace_record_value(&bytes, "node", "/value/4", wrapper)?;
    let wire = String::from_utf8(bytes)?.replace(&format!("\"{marker}\""), raw);
    Ok((wire.into_bytes(), canonical))
}

#[test]
fn canonical_raw_values_keep_duplicate_keys_whitespace_escapes_and_numbers() -> TestResult {
    let raw = format!(
        r#" {{ "nested":{{"value":"{}", "value":"kept"}}, "escape":"a\u000ab", "emoji":"\ud83d\udca1", "negative_zero":-0.0, "number":1e0, "large":18446744073709551616, "small":1e-6 }} "#,
        "x".repeat(8_000)
    );
    for version in 3..=6 {
        let (wire, expected) = case_with_raw_details(version, &raw)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            version,
            Cursor::new(wire),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn escaped_wire_values_may_exceed_the_limit_when_their_canonical_form_fits() -> TestResult {
    let raw = format!("\"{}\"", r"\u0061".repeat(1_000));
    assert!(raw.len() > MAX_NODE_DETAILS_BYTES);
    for version in 3..=6 {
        let (wire, expected) = case_with_raw_details(version, &raw)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            version,
            Cursor::new(wire),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn exact_limit_with_escapes_and_utf8_remains_readable_in_all_versions() -> TestResult {
    let prefix = "quote\" slash\\ newline\n light💡";
    let initial = json!({"text":prefix});
    let padding = MAX_NODE_DETAILS_BYTES - serde_json::to_vec(&initial)?.len();
    let details = json!({"text":format!("{prefix}{}", "x".repeat(padding))});
    let raw = serde_json::to_string(&details)?;
    assert_eq!(raw.len(), MAX_NODE_DETAILS_BYTES);
    for version in 3..=6 {
        let (wire, expected) = case_with_raw_details(version, &raw)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            version,
            Cursor::new(wire),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn exact_limit_object_fields_remain_readable_in_all_versions() -> TestResult {
    let prefix = "quote\" slash\\ newline\n light💡";
    let initial = json!({"value":prefix,"z":false,"index":7});
    let padding = MAX_NODE_DETAILS_BYTES - serde_json::to_vec(&initial)?.len();
    let text = format!("{prefix}{}", "x".repeat(padding));
    let details = json!({"value":text,"z":false,"index":7});
    assert_eq!(serde_json::to_vec(&details)?.len(), MAX_NODE_DETAILS_BYTES);
    let mut case = Case::new();
    case.add_node("probe", None, Vec::new(), details)?;
    let scope = json!({"kind":"detail_preflight"});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let mut bytes = Vec::new();
    write_published_case(&case, &scope, 1, &mut bytes)?;
    for version in 3..=6 {
        let mut wire = replace_record_value(&bytes, "header", "/value/version", json!(version))?;
        if version == 3 {
            wire = replace_record_value(
                &wire,
                "node",
                "/value/4",
                json!({"kind":"object","value":[
                    ["value", {"kind":"text","value":text}],
                    ["z", {"kind":"value","value":false}],
                    ["index", {"kind":"value","value":7}]
                ]}),
            )?;
        }
        let mut decoded = Vec::new();
        decode_published_evidence(
            version,
            Cursor::new(wire),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn nested_raw_values_near_the_parser_depth_limit_remain_readable() -> TestResult {
    let raw = format!("{}0{}", "[".repeat(120), "]".repeat(120));
    for version in 3..=6 {
        let (wire, expected) = case_with_raw_details(version, &raw)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            version,
            Cursor::new(wire),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}
