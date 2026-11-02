use l2_workbench::artifact::{
    self, ArtifactError, FunctionRejectionReason, MAX_R2_CODE_BYTES, MAX_R2_FUNCTION_BYTES,
};
use std::error::Error;

use super::support::minimal_elf;

const ENTRYPOINTS: &[u8] = br#"[{"paddr":256,"vaddr":4194304,"type":"program"}]"#;
const IMPORTS: &[u8] = br#"[{"ordinal":1,"bind":"GLOBAL","type":"FUNC","name":"network_send"}]"#;
const XREFS: &[u8] =
    br#"[{"from":4194305,"addr":4194560,"type":"CALL","refname":"sym.imp.network_send"}]"#;
const NO_XREFS: &[u8] = b"[]";

#[test]
fn r2_json_source_function_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let expected_hash = l2_workbench::sha256(&bytes);
    let receipt = artifact::import_r2_json(
        &bytes,
        &expected_hash,
        "6.2.2",
        ENTRYPOINTS,
        br#"[{"addr":4194304,"name":"sym.process_frame","size":8}]"#,
        IMPORTS,
        XREFS,
    )?;

    assert_eq!(receipt.source_sha256, expected_hash);
    assert_eq!(receipt.tool.name, "radare2");
    assert_eq!(receipt.tool.version, "6.2.2");
    assert!(receipt.complete);
    assert_eq!(receipt.rejected_functions.len(), 0);
    let function = receipt
        .functions
        .first()
        .ok_or("mapped function is missing")?;
    assert_eq!(function.file_offset, 0x100);
    assert_eq!(function.code_bytes_hex, "9091929394959697");
    let function_bytes = bytes
        .get(0x100..0x108)
        .ok_or("fixture function bytes are missing")?;
    assert_eq!(function.code_sha256, l2_workbench::sha256(function_bytes));
    let observation = function
        .external_observations
        .first()
        .ok_or("function cross-reference is missing")?;
    assert_eq!(
        observation.reference_name.as_deref(),
        Some("sym.imp.network_send")
    );
    Ok(())
}

#[test]
fn mixed_function_verified_bytes_unmapped() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let source_hash = l2_workbench::sha256(&bytes);
    let function_records = serde_json::to_vec(&serde_json::json!([
        {"addr": 4_194_304, "name": "mapped", "size": 8},
        {"addr": 999_999, "name": "unmapped", "size": 8}
    ]))?;
    let receipt = artifact::import_r2_json(
        &bytes,
        &source_hash,
        "6.2.2",
        NO_XREFS,
        &function_records,
        NO_XREFS,
        NO_XREFS,
    )?;

    assert!(!receipt.complete);
    assert_eq!(receipt.functions.len(), 1);
    assert_eq!(
        receipt
            .functions
            .first()
            .map(|function| function.name.as_str()),
        Some("mapped")
    );
    let rejected = receipt
        .rejected_functions
        .first()
        .ok_or("unmapped function rejection is missing")?;
    assert_eq!(rejected.name, "unmapped");
    assert_eq!(rejected.address, 999_999);
    assert_eq!(rejected.length, 8);
    assert_eq!(rejected.reason, FunctionRejectionReason::UnmappedAddress);
    Ok(())
}

#[test]
fn oversized_function_without_later_valid() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let hash = l2_workbench::sha256(&bytes);
    let oversized = u64::try_from(MAX_R2_FUNCTION_BYTES)? + 1;
    let functions = serde_json::json!([
        {"addr":4_194_304,"name":"too_large","size":oversized},
        {"addr":4_194_304,"name":"mapped","size":8}
    ]);
    let functions = serde_json::to_vec(&functions)?;
    let receipt = artifact::import_r2_json(
        &bytes, &hash, "6.2.2", NO_XREFS, &functions, NO_XREFS, NO_XREFS,
    )?;

    assert!(!receipt.complete);
    assert_eq!(receipt.functions.len(), 1);
    let rejected = receipt
        .rejected_functions
        .first()
        .ok_or("oversized function rejection is missing")?;
    assert_eq!(rejected.reason, FunctionRejectionReason::FunctionSizeLimit);
    assert_eq!(rejected.length, oversized);
    Ok(())
}

#[test]
fn aggregate_function_budget_function_exceeds() -> Result<(), Box<dyn Error>> {
    let mut bytes = minimal_elf()?;
    let mapped_bytes = MAX_R2_CODE_BYTES
        .checked_add(MAX_R2_FUNCTION_BYTES)
        .ok_or("fixture mapping size overflow")?;
    let total_size = 0x100_usize
        .checked_add(mapped_bytes)
        .ok_or("fixture image size overflow")?;
    bytes.resize(total_size, 0x90);
    let mapped_bytes = u64::try_from(mapped_bytes)?;
    super::support::put_u64(&mut bytes, 96, mapped_bytes)?;
    super::support::put_u64(&mut bytes, 104, mapped_bytes)?;
    let records = (0..=MAX_R2_CODE_BYTES / MAX_R2_FUNCTION_BYTES)
        .map(|index| {
            serde_json::json!({
                "addr": 4_194_304,
                "name": format!("function_{index}"),
                "size": MAX_R2_FUNCTION_BYTES
            })
        })
        .collect::<Vec<_>>();
    let functions = serde_json::to_vec(&records)?;
    let hash = l2_workbench::sha256(&bytes);
    let receipt = artifact::import_r2_json(
        &bytes, &hash, "6.2.2", NO_XREFS, &functions, NO_XREFS, NO_XREFS,
    )?;

    assert_eq!(
        receipt.functions.len(),
        MAX_R2_CODE_BYTES / MAX_R2_FUNCTION_BYTES
    );
    assert_eq!(receipt.rejected_functions.len(), 1);
    assert_eq!(
        receipt
            .rejected_functions
            .first()
            .map(|function| function.reason),
        Some(FunctionRejectionReason::AggregateCodeLimit)
    );
    assert!(!receipt.complete);
    Ok(())
}

#[test]
fn stale_r2_source_hash_rejected() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let stale_hash = l2_workbench::sha256(b"different original source");
    assert!(matches!(
        artifact::import_r2_json(
            &bytes,
            &stale_hash,
            "6.2.2",
            NO_XREFS,
            NO_XREFS,
            NO_XREFS,
            NO_XREFS,
        ),
        Err(ArtifactError::SourceHashMismatch)
    ));
    Ok(())
}

#[test]
fn malformed_unbounded_r2_payloads_errors() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let hash = l2_workbench::sha256(&bytes);
    assert!(matches!(
        artifact::import_r2_json(
            &bytes,
            &hash,
            "6.2.2",
            b"not json",
            NO_XREFS,
            NO_XREFS,
            NO_XREFS
        ),
        Err(ArtifactError::InvalidR2Json { .. })
    ));

    let large = vec![b' '; artifact::MAX_R2_JSON_BYTES + 1];
    assert!(matches!(
        artifact::import_r2_json(&bytes, &hash, "6.2.2", &large, NO_XREFS, NO_XREFS, NO_XREFS),
        Err(ArtifactError::R2JsonTooLarge { .. })
    ));
    Ok(())
}
