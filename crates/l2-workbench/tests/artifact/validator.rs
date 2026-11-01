use l2_workbench::artifact::zip::ZipArtifactLimits;
use l2_workbench::artifact::{
    ArtifactBoundaryEvidence, ArtifactResourceOmissionReason, ArtifactStructure,
    ArtifactValidationFailure, ArtifactValidationFormat, ArtifactValidationOutcome,
    ArtifactValidationPolicy, ArtifactValidationPolicyError, ArtifactValidator, DerError,
    DerLimits, FileRange, PNG_SIGNATURE, PngError, PngLimits,
};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
use std::error::Error;

use super::{png, support, zip_support};

#[test]
fn png_ranges_iend() -> Result<(), Box<dyn Error>> {
    let png = png::minimal_png()?;
    let mut input = png.clone();
    input.extend_from_slice(b"trailing bytes");
    let result = ArtifactValidator::default().validate(&input);

    let ArtifactValidationOutcome::Validated {
        format,
        range,
        boundary,
        structure: ArtifactStructure::Png(report),
    } = result
    else {
        return Err("expected structurally validated PNG".into());
    };

    assert_eq!(format, ArtifactValidationFormat::Png);
    assert_eq!(
        range,
        FileRange {
            offset: 0,
            length: png.len()
        }
    );
    assert_eq!(boundary, ArtifactBoundaryEvidence::PngIend);
    assert_eq!(report.bytes_after_iend, b"trailing bytes");
    Ok(())
}

#[test]
fn png_signature_requires_structure() {
    let input = PNG_SIGNATURE;
    assert!(matches!(
        ArtifactValidator::default().validate(&input),
        ArtifactValidationOutcome::Rejected {
            format: ArtifactValidationFormat::Png,
            reason: ArtifactValidationFailure::Png(PngError::MissingIend),
            ..
        }
    ));
}

#[test]
fn zip_signature_requires_structure() {
    assert!(matches!(
        ArtifactValidator::default().validate(b"PK\x03\x04"),
        ArtifactValidationOutcome::Rejected {
            format: ArtifactValidationFormat::Zip,
            reason: ArtifactValidationFailure::Zip(_),
            ..
        }
    ));
}

#[test]
fn der_requires_explicit_format() {
    let der = [0x04, 0x01, 0x7f];
    let validator = ArtifactValidator::default();

    assert!(matches!(
        validator.validate(&der),
        ArtifactValidationOutcome::Unsupported { .. }
    ));
    assert!(matches!(
        validator.validate_as(ArtifactValidationFormat::Der, &der),
        ArtifactValidationOutcome::Validated {
            format: ArtifactValidationFormat::Der,
            range: FileRange {
                offset: 0,
                length: 3
            },
            boundary: ArtifactBoundaryEvidence::DerEncodedLength,
            structure: ArtifactStructure::Der(_),
        }
    ));
}

#[test]
fn der_rejection_stays_typed() -> Result<(), Box<dyn Error>> {
    let der = [0x04, 0x02, 0x7f];
    assert!(matches!(
        ArtifactValidator::default().validate_as(ArtifactValidationFormat::Der, &der),
        ArtifactValidationOutcome::Rejected {
            format: ArtifactValidationFormat::Der,
            reason: ArtifactValidationFailure::Der(DerError::InvalidDer),
            ..
        }
    ));
    let budget = MemoryBudget::new(64 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Publication, 11)?;
    let blocker = budget.try_reserve(MemoryClass::Cache, budget.snapshot()?.limit_bytes - 11)?;
    let valid = [0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
    assert!(matches!(
        ArtifactValidator::default().validate_as_with_memory(
            ArtifactValidationFormat::Der,
            &valid,
            &mut lease,
        ),
        Err(MemoryError::Limit { .. })
    ));
    assert_eq!(lease.bytes(), 11);
    drop(blocker);

    // The second child ends before its declared value can be read
    let truncated = [0x30, 0x04, 0x05, 0x00, 0x05, 0x01];
    let outcome = ArtifactValidator::default().validate_as_with_memory(
        ArtifactValidationFormat::Der,
        &truncated,
        &mut lease,
    )?;
    assert!(matches!(
        outcome,
        ArtifactValidationOutcome::Rejected {
            format: ArtifactValidationFormat::Der,
            reason: ArtifactValidationFailure::Der(DerError::InvalidDer),
            ..
        }
    ));
    assert_eq!(lease.bytes(), 11);
    drop(outcome);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn unsupported_bytes_stay_unsupported() {
    assert!(matches!(
        ArtifactValidator::default().validate(b"ordinary bytes"),
        ArtifactValidationOutcome::Unsupported {
            input_range: FileRange {
                offset: 0,
                length: 14
            }
        }
    ));
}

#[test]
fn parser_limit_omits_work() -> Result<(), Box<dyn Error>> {
    let png = png::minimal_png()?;
    let limits = ArtifactValidationPolicy {
        png_limits: PngLimits {
            max_input_bytes: png.len() - 1,
            ..PngLimits::default()
        },
        ..ArtifactValidationPolicy::default()
    };
    let validator = ArtifactValidator::new(limits)?;

    assert!(matches!(
        validator.validate(&png),
        ArtifactValidationOutcome::Omitted {
            format: Some(ArtifactValidationFormat::Png),
            reason: ArtifactResourceOmissionReason::InputTooLarge {
                length,
                maximum
            },
            ..
        } if length == png.len() && maximum == png.len() - 1
    ));
    Ok(())
}

#[test]
fn invalid_policy_is_rejected() {
    let policy = ArtifactValidationPolicy {
        der_limits: DerLimits {
            max_object_bytes: 0,
            ..DerLimits::default()
        },
        ..ArtifactValidationPolicy::default()
    };
    assert!(matches!(
        ArtifactValidator::new(policy),
        Err(ArtifactValidationPolicyError::InvalidLimit {
            field: "DER object bytes"
        })
    ));
}

#[test]
fn zip_validates_exact_input() -> Result<(), Box<dyn Error>> {
    let bytes =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"member.txt", b"content")])?;
    let result = ArtifactValidator::default().validate(&bytes);

    let ArtifactValidationOutcome::Validated {
        format,
        range,
        boundary,
        structure: ArtifactStructure::Zip(report),
    } = result
    else {
        return Err("expected structurally validated ZIP".into());
    };

    assert_eq!(format, ArtifactValidationFormat::Zip);
    assert_eq!(
        range,
        FileRange {
            offset: 0,
            length: bytes.len()
        }
    );
    assert_eq!(boundary, ArtifactBoundaryEvidence::ZipEndRecord);
    assert_eq!(report.archive_size, bytes.len());
    Ok(())
}

#[test]
fn explicit_zip_validation_consumes_expansion_budget_before_failed_member_data()
-> Result<(), Box<dyn Error>> {
    let content = b"payload whose checksum will fail";
    let bytes =
        zip_support::build_zip(&[
            zip_support::FixtureEntry::stored(b"member.txt", content).with_crc(0)
        ])?;
    let mut remaining = content.len();

    let result = ArtifactValidator::default().validate_as_with_zip_budget(
        ArtifactValidationFormat::Zip,
        &bytes,
        &mut remaining,
    );

    let ArtifactValidationOutcome::Validated {
        structure: ArtifactStructure::Zip(report),
        ..
    } = result
    else {
        return Err("expected ZIP structure with one failed member".into());
    };
    assert_eq!(remaining, 0);
    assert_eq!(report.expanded_work_byte_count, content.len());
    assert_eq!(report.omitted_entry_count, 1);
    Ok(())
}

#[test]
fn zip_entry_limit_omits() -> Result<(), Box<dyn Error>> {
    let bytes = zip_support::build_zip(&[
        zip_support::FixtureEntry::stored(b"one", b"1"),
        zip_support::FixtureEntry::stored(b"two", b"2"),
    ])?;
    let policy = ArtifactValidationPolicy {
        zip_limits: ZipArtifactLimits {
            max_entries: 1,
            ..ZipArtifactLimits::default()
        },
        ..ArtifactValidationPolicy::default()
    };

    assert!(matches!(
        ArtifactValidator::new(policy)?.validate(&bytes),
        ArtifactValidationOutcome::Omitted {
            format: Some(ArtifactValidationFormat::Zip),
            reason: ArtifactResourceOmissionReason::ZipEntryLimit { maximum: 1, .. },
            ..
        }
    ));
    Ok(())
}

#[test]
fn executable_boundary_stays_explicit() -> Result<(), Box<dyn Error>> {
    for bytes in [support::minimal_elf()?, support::minimal_pe()?] {
        assert!(matches!(
            ArtifactValidator::default().validate(&bytes),
            ArtifactValidationOutcome::BoundaryUnproven {
                format: ArtifactValidationFormat::Elf
                    | ArtifactValidationFormat::PortableExecutable,
                ..
            }
        ));
    }
    Ok(())
}

#[test]
fn executable_type_mismatch_unsupported() -> Result<(), Box<dyn Error>> {
    let bytes = support::minimal_elf()?;
    assert!(matches!(
        ArtifactValidator::default()
            .validate_as(ArtifactValidationFormat::PortableExecutable, &bytes),
        ArtifactValidationOutcome::Unsupported { .. }
    ));
    Ok(())
}
