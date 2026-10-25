use l2_workbench::artifact::{
    self, CodeLinkLimits, CodeLinkSourceChecks, CodeLinkSourceVerification,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn tracks_source_verification_independently() -> Result<(), Box<dyn Error>> {
    let binary = super::super::support::minimal_elf()?;
    let receipt = super::receipt_for(&binary)?;
    let mapping_source = b"runtime map source";
    let module_map = super::one_mapping(
        &receipt,
        mapping_source,
        artifact::RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = super::trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    for (binary_bytes, mapping_source_bytes) in [
        (None, None),
        (Some(binary.as_slice()), None),
        (None, Some(mapping_source.as_slice())),
        (Some(binary.as_slice()), Some(mapping_source.as_slice())),
    ] {
        let report = artifact::link_code_to_trace(
            &receipt,
            &module_map,
            &trace,
            &correlations,
            &CodeLinkSourceChecks {
                mapping_document_sha256: &document_hash,
                binary_bytes,
                mapping_source_bytes,
            },
            CodeLinkLimits::default(),
        )?;

        let expected = CodeLinkSourceVerification {
            binary_source_verified: binary_bytes.is_some(),
            mapping_source_verified: mapping_source_bytes.is_some(),
        };
        assert_eq!(report.source_verification, expected);
        let output = serde_json::to_value(&report)?;
        // Existing command consumers receive the same flat boolean fields
        assert_eq!(
            output.get("binary_source_verified"),
            Some(&Value::Bool(expected.binary_source_verified))
        );
        assert_eq!(
            output.get("mapping_source_verified"),
            Some(&Value::Bool(expected.mapping_source_verified))
        );
        assert!(output.get("source_verification").is_none());
    }
    Ok(())
}
