use std::error::Error;

use l2_workbench::artifact::{
    AnalysisFormat, AnalysisStatus, AnalyzerLimits, ArtifactAnalysisOptions, ArtifactOrigin,
    ArtifactValidationFormat, ArtifactValidationState, ArtifactValidator, RecoveryMode,
    analyze_artifacts, analyze_artifacts_with_source_sha256,
    zip::{ZipArtifactLimits, inspect_zip_with_limits},
};

use super::{image_support::structural_png, zip_support};

#[test]
fn standalone_png_keeps_the_same_structural_boundary_as_capture_bytes() -> Result<(), Box<dyn Error>>
{
    let png = structural_png(&[])?;
    let standalone = ArtifactValidator::default().validate(&png);
    let report = analyze_artifacts(&png, ArtifactAnalysisOptions::default())?;
    let artifact = report
        .artifacts
        .first()
        .ok_or("source artifact is missing")?;

    assert!(matches!(
        standalone,
        l2_workbench::artifact::ArtifactValidationOutcome::Validated {
            format: ArtifactValidationFormat::Png,
            range,
            ..
        } if range.length == png.len()
    ));
    assert_eq!(
        artifact.validation.state,
        ArtifactValidationState::Validated
    );
    assert_eq!(artifact.validation.format, Some(AnalysisFormat::Png));
    assert_eq!(
        artifact.validation.range,
        Some(l2_workbench::artifact::FileRange {
            offset: 0,
            length: png.len(),
        })
    );
    assert_eq!(artifact.validation.structure_count, 2);
    assert_eq!(artifact.bytes, png);
    Ok(())
}

#[test]
fn standalone_zip_uses_the_existing_zip_parser_and_retains_its_member() -> Result<(), Box<dyn Error>>
{
    let content = b"member payload";
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"member.bin", content)])?;
    let structural = inspect_zip_with_limits(&archive, ZipArtifactLimits::default())?;
    let report = analyze_artifacts(&archive, ArtifactAnalysisOptions::default())?;
    let source = report
        .artifacts
        .first()
        .ok_or("source archive artifact is missing")?;

    assert_eq!(source.validation.format, Some(AnalysisFormat::Zip));
    assert_eq!(source.validation.structure_count, structural.entry_count);
    assert_eq!(
        source.validation.range,
        Some(l2_workbench::artifact::FileRange {
            offset: 0,
            length: archive.len(),
        })
    );
    assert!(report.artifacts.iter().any(|artifact| {
        artifact.bytes == content
            && artifact.origins.iter().any(|origin| {
                matches!(origin, ArtifactOrigin::ArchiveMember { entry_index: 0, .. })
            })
    }));
    Ok(())
}

#[test]
fn encoded_input_can_yield_a_valid_object_inside_unrelated_bytes() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let decoded = [b"unrelated prefix".as_slice(), &png, b"unrelated suffix"].concat();
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &decoded);
    let report = analyze_artifacts(encoded.as_bytes(), ArtifactAnalysisOptions::default())?;

    let transformed = report
        .artifacts
        .iter()
        .position(|artifact| artifact.bytes == decoded)
        .ok_or("decoded bytes were not retained")?;
    let carved = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == png)
        .ok_or("interior PNG was not carved")?;
    assert!(
        report
            .artifacts
            .get(transformed)
            .ok_or("decoded artifact disappeared")?
            .origins
            .iter()
            .any(|origin| matches!(origin, ArtifactOrigin::Transformation { .. }))
    );
    assert!(carved.origins.iter().any(|origin| matches!(
        origin,
        ArtifactOrigin::EmbeddedObject { range, .. } if range.length == png.len()
    )));
    Ok(())
}

#[test]
fn embedded_png_and_zip_keep_parent_origins_without_self_ranges() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let zip = zip_support::build_zip(&[zip_support::FixtureEntry::stored(
        b"member.bin",
        b"member payload",
    )])?;

    for bytes in [png, zip] {
        let mut input = b"prefix".to_vec();
        let offset = input.len();
        input.extend_from_slice(&bytes);
        input.extend_from_slice(b"suffix");
        let report = analyze_artifacts(&input, ArtifactAnalysisOptions::default())?;
        let artifact = report
            .artifacts
            .iter()
            .find(|artifact| artifact.bytes == bytes)
            .ok_or("embedded object was not retained")?;
        let parent_origin = artifact.origins.iter().any(|origin| {
            matches!(origin, ArtifactOrigin::EmbeddedObject { parent_index: 0, range, .. }
                if range.offset == offset && range.length == bytes.len())
        });
        let self_origin = artifact.origins.iter().any(|origin| {
            matches!(origin, ArtifactOrigin::EmbeddedObject { parent_index, range, .. }
                if *parent_index == artifact.index
                    && range.offset == 0
                    && range.length == bytes.len())
        });

        assert!(
            parent_origin,
            "the genuine containing-source origin is retained"
        );
        assert!(
            !self_origin,
            "an object does not originate from its own full range"
        );
    }
    Ok(())
}

#[test]
fn duplicate_object_from_a_second_parent_keeps_both_real_origins() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let zip = zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"image.png", &png)])?;
    let mut input = b"prefix".to_vec();
    let png_offset = input.len();
    input.extend_from_slice(&png);
    input.extend_from_slice(b"separator");
    input.extend_from_slice(&zip);
    input.extend_from_slice(b"suffix");
    let report = analyze_artifacts(&input, ArtifactAnalysisOptions::default())?;
    let image = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == png)
        .ok_or("embedded PNG was not retained")?;
    let archive = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == zip)
        .ok_or("embedded ZIP was not retained")?;

    assert!(image.origins.iter().any(|origin| {
        matches!(origin, ArtifactOrigin::EmbeddedObject { parent_index: 0, range, .. }
            if range.offset == png_offset && range.length == png.len())
    }));
    assert!(image.origins.iter().any(|origin| {
        matches!(origin, ArtifactOrigin::ArchiveMember { parent_index, entry_index: 0, .. }
            if *parent_index == archive.index)
    }));
    assert!(!image.origins.iter().any(|origin| {
        matches!(origin, ArtifactOrigin::EmbeddedObject { parent_index, range, .. }
            if *parent_index == image.index
                && range.offset == 0
                && range.length == png.len())
    }));
    Ok(())
}

#[test]
fn encoded_region_between_binary_headers_and_trailers_keeps_exact_transform_range()
-> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &png);
    let mut input = b"\x01\x02|".to_vec();
    let payload_start = input.len();
    input.extend_from_slice(encoded.as_bytes());
    let payload_length = encoded.len();
    input.extend_from_slice(b"|\xfe\x03");
    let original = input.clone();

    let report = analyze_artifacts(&input, ArtifactAnalysisOptions::default())?;
    let transformed = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == png)
        .ok_or("encoded payload was not derived into the PNG")?;
    let source_artifact = report
        .artifacts
        .first()
        .ok_or("source artifact is missing")?;
    let source_regions = report
        .region_transform_reports
        .iter()
        .find(|entry| entry.artifact_index == 0)
        .ok_or("source region report is missing")?;
    let payload_region = source_regions
        .report
        .regions
        .iter()
        .find(|region| {
            region.range.start == payload_start
                && region.range.end == payload_start + payload_length
        })
        .ok_or("payload region did not retain its exact assessment range")?;

    assert_eq!(source_artifact.bytes, original);
    assert!(source_regions.report.coverage.complete);
    assert_eq!(payload_region.proposal_report.assessments.len(), 7);
    assert!(transformed.origins.iter().any(|origin| matches!(
        origin,
        ArtifactOrigin::Transformation {
            input_range,
            operation: l2_workbench::derivation::Operation::Base64Decode { .. },
            cue_origins,
            ..
        } if input_range.offset == payload_start
            && input_range.length == payload_length
            && cue_origins.iter().any(|origin| matches!(
                origin,
                l2_workbench::recovery::regions::RegionCueOrigin::EncodingRun
            ))
    )));
    Ok(())
}

#[test]
fn invalid_region_syntax_remains_a_complete_negative_for_its_exact_range()
-> Result<(), Box<dyn Error>> {
    let input = b"\x01\x02|SGVsbG8=bad|\xfe";
    let start = 3;
    let end = start + b"SGVsbG8=bad".len();
    let report = analyze_artifacts(input, ArtifactAnalysisOptions::default())?;
    let source_regions = report
        .region_transform_reports
        .iter()
        .find(|entry| entry.artifact_index == 0)
        .ok_or("source region report is missing")?;
    let region = source_regions
        .report
        .regions
        .iter()
        .find(|region| region.range.start == start && region.range.end == end)
        .ok_or("invalid encoded text range is missing")?;

    assert!(source_regions.report.coverage.complete);
    assert!(region.proposal_report.proposals.is_empty());
    assert!(
        region
            .proposal_report
            .assessments
            .iter()
            .filter(|assessment| {
                matches!(
                    assessment.operation,
                    l2_workbench::derivation::Operation::Base64Decode { .. }
                )
            })
            .all(|assessment| matches!(
                assessment.result,
                l2_workbench::recovery::proposals::TransformAssessmentResult::Ineligible { .. }
            ))
    );
    assert_eq!(report.artifacts.len(), 1);
    Ok(())
}

#[test]
fn magic_bytes_alone_do_not_promote_an_invalid_object() -> Result<(), Box<dyn Error>> {
    let invalid = b"prefix\x89PNG\r\n\x1a\ntruncated";
    let report = analyze_artifacts(invalid, ArtifactAnalysisOptions::default())?;
    let source = report
        .artifacts
        .first()
        .ok_or("source artifact is missing")?;

    assert_eq!(report.artifacts.len(), 1);
    assert_ne!(source.validation.state, ArtifactValidationState::Validated);
    assert!(
        source
            .origins
            .iter()
            .any(|origin| matches!(origin, ArtifactOrigin::Source))
    );
    Ok(())
}

#[test]
fn nested_archives_are_expanded_with_parent_lineage() -> Result<(), Box<dyn Error>> {
    let deepest = b"nested member bytes";
    let inner = zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"deep.bin", deepest)])?;
    let outer =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"nested.zip", &inner)])?;
    let report = analyze_artifacts(&outer, ArtifactAnalysisOptions::default())?;
    let member = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == inner)
        .ok_or("inner archive was not retained")?;
    let nested_member = report
        .artifacts
        .iter()
        .find(|artifact| artifact.bytes == deepest)
        .ok_or("nested archive member was not retained")?;

    assert!(member.origins.iter().any(|origin| matches!(
        origin,
        ArtifactOrigin::ArchiveMember {
            parent_index: 0,
            ..
        }
    )));
    assert!(nested_member.origins.iter().any(|origin| matches!(
        origin,
        ArtifactOrigin::ArchiveMember { parent_index, .. }
            if *parent_index == member.index
    )));
    Ok(())
}

#[test]
fn identical_runs_have_the_same_logical_result() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let first = analyze_artifacts(&png, ArtifactAnalysisOptions::default())?;
    let second = analyze_artifacts(&png, ArtifactAnalysisOptions::default())?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn analysis_metadata_round_trips_without_embedding_artifact_bytes() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let decoded = [b"unrelated prefix".as_slice(), &png, b"unrelated suffix"].concat();
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &decoded);
    let report = analyze_artifacts(encoded.as_bytes(), ArtifactAnalysisOptions::default())?;

    let encoded = serde_json::to_vec(&report)?;
    let metadata: l2_workbench::artifact::ArtifactAnalysis = serde_json::from_slice(&encoded)?;
    let first_metadata_artifact = metadata
        .artifacts
        .first()
        .ok_or("first metadata artifact is missing")?;

    assert_eq!(metadata.source_sha256, report.source_sha256);
    assert_eq!(metadata.artifacts.len(), report.artifacts.len());
    assert!(first_metadata_artifact.bytes.is_empty());
    for (cached, original) in metadata.artifacts.iter().zip(&report.artifacts) {
        assert_eq!(cached.index, original.index);
        assert_eq!(cached.sha256, original.sha256);
        assert_eq!(cached.origins, original.origins);
        assert_eq!(cached.validation, original.validation);
        assert!(cached.bytes.is_empty());
    }
    assert_eq!(metadata.status, report.status);
    Ok(())
}

#[test]
fn analysis_accepts_an_already_verified_source_digest() -> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let digest = l2_workbench::sha256(&png);
    let report =
        analyze_artifacts_with_source_sha256(&png, &digest, ArtifactAnalysisOptions::default())?;

    assert_eq!(report.source_sha256, digest);
    Ok(())
}

#[test]
fn analysis_rejects_an_unformatted_source_digest() {
    let result = analyze_artifacts_with_source_sha256(
        b"source",
        "not-a-sha256",
        ArtifactAnalysisOptions::default(),
    );

    assert!(matches!(
        result,
        Err(l2_workbench::artifact::AnalyzerError::InvalidSourceHash)
    ));
}

#[test]
fn artifact_and_work_limits_return_a_partial_report() -> Result<(), Box<dyn Error>> {
    let archive = zip_support::build_zip(&[zip_support::FixtureEntry::stored(
        b"member.bin",
        b"member data",
    )])?;
    let options = ArtifactAnalysisOptions {
        limits: AnalyzerLimits {
            max_artifacts: 1,
            max_total_work_bytes: 0,
            ..AnalyzerLimits::default()
        },
        recovery: RecoveryMode::Conservative,
    };
    let report = analyze_artifacts(&archive, options)?;

    assert_eq!(report.artifacts.len(), 1);
    assert_eq!(report.status, AnalysisStatus::Partial);
    assert!(!report.omissions.is_empty());
    Ok(())
}

#[test]
fn zero_archive_expansion_budget_does_not_extract_even_one_byte() -> Result<(), Box<dyn Error>> {
    let archive =
        zip_support::build_zip(&[zip_support::FixtureEntry::stored(b"member.bin", b"x")])?;
    let options = ArtifactAnalysisOptions {
        limits: AnalyzerLimits {
            max_zip_expanded_bytes: 0,
            ..AnalyzerLimits::default()
        },
        recovery: RecoveryMode::Conservative,
    };

    let report = analyze_artifacts(&archive, options)?;

    assert!(
        !report
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == b"x")
    );
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        l2_workbench::artifact::AnalysisOmission::ZipMember {
            reason:
                l2_workbench::artifact::zip::ZipArtifactOmissionReason::OperationExpandedByteLimit,
            ..
        }
    )));
    Ok(())
}

#[test]
fn salvage_mode_reports_unsupported_repair_without_changing_source() -> Result<(), Box<dyn Error>> {
    let input = b"damaged section with no complete object";
    let report = analyze_artifacts(
        input,
        ArtifactAnalysisOptions {
            recovery: RecoveryMode::Salvage,
            ..ArtifactAnalysisOptions::default()
        },
    )?;

    assert_eq!(
        report
            .artifacts
            .first()
            .ok_or("source artifact is missing")?
            .bytes,
        input
    );
    assert_eq!(report.status, AnalysisStatus::Partial);
    assert!(
        report
            .omissions
            .iter()
            .any(l2_workbench::artifact::AnalysisOmission::is_salvage_unsupported)
    );
    Ok(())
}

#[test]
fn salvage_mode_keeps_a_complete_object_complete_when_no_repair_is_needed()
-> Result<(), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let report = analyze_artifacts(
        &png,
        ArtifactAnalysisOptions {
            recovery: RecoveryMode::Salvage,
            ..ArtifactAnalysisOptions::default()
        },
    )?;

    assert_eq!(report.status, AnalysisStatus::Complete);
    assert!(report.omissions.is_empty());
    assert_eq!(
        report
            .artifacts
            .first()
            .ok_or("PNG artifact is missing")?
            .bytes,
        png
    );
    Ok(())
}

#[test]
fn input_limit_preserves_original_hash_and_length() -> Result<(), Box<dyn Error>> {
    let input = b"plain bytes";
    let report = analyze_artifacts(
        input,
        ArtifactAnalysisOptions {
            limits: AnalyzerLimits {
                max_input_bytes: input.len() - 1,
                ..AnalyzerLimits::default()
            },
            ..ArtifactAnalysisOptions::default()
        },
    )?;

    assert!(report.artifacts.is_empty());
    assert_eq!(report.source_sha256, l2_workbench::sha256(input));
    assert_eq!(report.source_length, input.len());
    assert_eq!(report.status, AnalysisStatus::Partial);
    assert!(
        report
            .omissions
            .iter()
            .any(l2_workbench::artifact::AnalysisOmission::is_input_limit)
    );
    Ok(())
}
