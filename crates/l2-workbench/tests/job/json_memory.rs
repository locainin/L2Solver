use l2_workbench::job::{JsonMemoryError, MemoryBudget, MemoryClass, admit_json};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn owned_json_admission_keeps_retained_state_charged_after_decoding() -> TestResult {
    let bytes = br#"{"inputs":[{"name":"seed\u0020range","offset":32}],"enabled":true}"#;
    let budget = MemoryBudget::new(64 * 1024);
    let admission = admit_json(bytes, &budget, MemoryClass::Executor)?;
    let during_decode = budget.snapshot()?.used_bytes;
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let retained = admission.into_retained();
    assert_eq!(budget.snapshot()?.used_bytes, retained.bytes());
    assert!(
        during_decode > retained.bytes(),
        "decode scratch must be released"
    );
    assert_eq!(
        value.get("enabled").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    drop(value);
    drop(retained);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn dense_json_is_rejected_before_its_owned_tree_is_materialized() -> TestResult {
    let bytes = format!("[{}]", vec!["0"; 4096].join(","));
    let budget = MemoryBudget::new(64 * 1024);
    assert!(matches!(
        admit_json(bytes.as_bytes(), &budget, MemoryClass::Executor),
        Err(JsonMemoryError::Memory(_))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn escaped_string_scratch_is_admitted_before_the_parser_starts() -> TestResult {
    let bytes = format!("\"{}\\n\"", "x".repeat(8192));
    let budget = MemoryBudget::new(2 * u64::try_from(bytes.len())?);
    let error = admit_json(bytes.as_bytes(), &budget, MemoryClass::Executor)
        .err()
        .ok_or("escaped string exceeded its scratch admission")?;
    assert!(
        matches!(
            error,
            JsonMemoryError::Memory(l2_workbench::job::MemoryError::Limit { used: 0, .. })
        ),
        "scratch must cover a growing parser buffer before decoding: {error}"
    );
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn invalid_or_trailing_json_releases_its_temporary_charge() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    for bytes in [
        b"{\"unfinished\":".as_slice(),
        b"[] true".as_slice(),
        b"\"\\uD800\"".as_slice(),
    ] {
        assert!(matches!(
            admit_json(bytes, &budget, MemoryClass::Cache),
            Err(JsonMemoryError::InvalidJson { .. })
        ));
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[test]
fn escaped_json_strings_charge_the_same_retained_text_as_literal_strings() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    let escaped =
        admit_json(br#"["\u0061\u0062\u0063"]"#, &budget, MemoryClass::Executor)?.into_retained();
    let literal = admit_json(br#"["abc"]"#, &budget, MemoryClass::Executor)?.into_retained();
    assert_eq!(escaped.bytes(), literal.bytes());
    drop(escaped);
    drop(literal);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn json_admission_preserves_the_selected_allocation_class() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    let admission = admit_json(b"[1,2,3]", &budget, MemoryClass::Cache)?;
    assert!(budget.snapshot()?.used(MemoryClass::Cache) > 0);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Executor), 0);
    drop(admission);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
