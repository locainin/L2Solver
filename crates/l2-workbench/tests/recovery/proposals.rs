use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, DerivationStatus, Operation, Recipe, run},
    recovery::proposals::{
        TransformAssessment, TransformAssessmentResult, TransformEvidence, TransformProposalBudget,
        TransformProposalDisposition, propose_transforms, transform_proposal_scan_work_bound,
    },
};

const fn budget(max_candidates: usize, max_reports: usize) -> TransformProposalBudget {
    TransformProposalBudget {
        max_candidates,
        max_reports,
    }
}

const fn base64_mode(alphabet: Base64Alphabet, padding: Base64Padding) -> Operation {
    Operation::Base64Decode { alphabet, padding }
}

fn alias_of(representative: &Operation) -> TransformProposalDisposition {
    TransformProposalDisposition::AliasOf {
        representative: representative.clone(),
    }
}

fn proposed_operations(
    report: &l2_workbench::recovery::proposals::TransformProposalReport,
) -> Vec<Operation> {
    report
        .proposals
        .iter()
        .filter_map(|proposal| proposal.recipe.steps.first().cloned())
        .collect()
}

fn eligible_base64_mode_count(
    report: &l2_workbench::recovery::proposals::TransformProposalReport,
) -> usize {
    report
        .assessments
        .iter()
        .filter(|assessment| {
            matches!(
                &assessment.result,
                TransformAssessmentResult::Eligible {
                    evidence: TransformEvidence::Base64Syntax { .. },
                    ..
                }
            )
        })
        .count()
}

fn eligible_base64_dispositions(
    report: &l2_workbench::recovery::proposals::TransformProposalReport,
) -> Vec<(Operation, TransformProposalDisposition)> {
    report
        .assessments
        .iter()
        .filter_map(|assessment| match &assessment.result {
            TransformAssessmentResult::Eligible {
                evidence: TransformEvidence::Base64Syntax { .. },
                disposition,
            } => Some((assessment.operation.clone(), disposition.clone())),
            TransformAssessmentResult::Eligible { .. }
            | TransformAssessmentResult::Ineligible { .. } => None,
        })
        .collect()
}

fn assessment<'a>(
    report: &'a l2_workbench::recovery::proposals::TransformProposalReport,
    operation: &Operation,
) -> Option<&'a TransformAssessment> {
    report
        .assessments
        .iter()
        .find(|item| &item.operation == operation)
}

#[test]
fn proposes_complete_syntax() {
    let report = propose_transforms(b"4142", budget(8, 8));

    assert_eq!(
        proposed_operations(&report),
        vec![
            Operation::HexDecode {},
            Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            },
        ]
    );
    assert_eq!(report.proposals.len(), 2);
    assert_eq!(report.assessments.len(), 7);
    assert_eq!(eligible_base64_mode_count(&report), 4);
    assert!(report.proposals.iter().all(|proposal| {
        proposal.recipe.steps.len() == 1 && proposal.recipe.constraints.is_empty()
    }));
}

#[test]
fn rejects_partial_encodings() {
    let odd_hex = propose_transforms(b"123", budget(8, 8));
    let invalid_hex = propose_transforms(b"4g", budget(8, 8));

    assert!(
        assessment(&odd_hex, &Operation::HexDecode {}).is_some_and(|item| {
            matches!(&item.result, TransformAssessmentResult::Ineligible { .. })
        })
    );
    assert!(
        assessment(&invalid_hex, &Operation::HexDecode {}).is_some_and(|item| {
            matches!(&item.result, TransformAssessmentResult::Ineligible { .. })
        })
    );
}

#[test]
fn rejects_noncanonical_base64() {
    for input in [b"TQ=".as_slice(), b"TR==", b"TR", b"Q"] {
        let report = propose_transforms(input, budget(8, 8));
        assert!(report.proposals.iter().all(|proposal| {
            !matches!(
                proposal.recipe.steps.first(),
                Some(Operation::Base64Decode { .. })
            )
        }));
    }
}

#[test]
fn proposes_headers_only() {
    let gzip_header = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3];
    let zlib_header = [0x78, 0x9c];
    let gzip = propose_transforms(&gzip_header, budget(8, 8));
    let zlib = propose_transforms(&zlib_header, budget(8, 8));

    assert_eq!(
        proposed_operations(&gzip),
        vec![Operation::GzipDecompress {}]
    );
    assert_eq!(
        proposed_operations(&zlib),
        vec![Operation::ZlibDecompress {}]
    );
    assert!(gzip.assessments.iter().any(|item| matches!(
        &item.result,
        TransformAssessmentResult::Eligible {
            evidence: TransformEvidence::GzipHeader { .. },
            disposition: TransformProposalDisposition::Proposed,
        }
    )));
    assert!(zlib.assessments.iter().any(|item| matches!(
        &item.result,
        TransformAssessmentResult::Eligible {
            evidence: TransformEvidence::ZlibHeader { .. },
            disposition: TransformProposalDisposition::Proposed,
        }
    )));
}

#[test]
fn rejects_invalid_headers() {
    let invalid_gzip = [0x1f, 0x8b, 0x08, 0xe0, 0, 0, 0, 0, 0, 3];
    let invalid_zlib = [0x78, 0x00];
    let incomplete_gzip_name = [0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 3, b'n'];
    let incomplete_zlib_dictionary = [0x78, 0x20];

    let gzip = propose_transforms(&invalid_gzip, budget(8, 8));
    let zlib = propose_transforms(&invalid_zlib, budget(8, 8));
    let incomplete_name = propose_transforms(&incomplete_gzip_name, budget(8, 8));
    let incomplete_dictionary = propose_transforms(&incomplete_zlib_dictionary, budget(8, 8));
    assert_eq!(proposed_operations(&gzip).len(), 0);
    assert_eq!(proposed_operations(&zlib).len(), 0);
    assert_eq!(proposed_operations(&incomplete_name).len(), 0);
    assert_eq!(proposed_operations(&incomplete_dictionary).len(), 0);
}

#[test]
fn reports_budget_omissions() {
    let report = propose_transforms(b"4142", budget(2, 3));

    assert_eq!(report.proposals.len(), 2);
    assert_eq!(report.assessments.len(), 3);
    assert_eq!(report.omissions.candidates, 0);
    assert_eq!(report.omissions.reports, 4);
}

#[test]
fn keeps_budgets_independent() {
    let report = propose_transforms(b"4142", budget(1, 0));

    assert_eq!(report.proposals.len(), 1);
    assert_eq!(report.assessments.len(), 0);
    assert_eq!(report.omissions.candidates, 1);
    assert_eq!(report.omissions.reports, 7);
    assert!(matches!(
        report.proposals.first().map(|proposal| &proposal.evidence),
        Some(TransformEvidence::HexSyntax { digit_count: 4 })
    ));
}

#[test]
fn rejects_empty_input() {
    let report = propose_transforms(b"", budget(8, 8));

    assert_eq!(report.proposals.len(), 0);
    assert_eq!(report.assessments.len(), 7);
    assert_eq!(report.omissions.candidates, 0);
    assert!(report.assessments.iter().all(|item| matches!(
        &item.result,
        TransformAssessmentResult::Ineligible {
            reason: l2_workbench::recovery::proposals::TransformIneligibility::EmptyInput,
        }
    )));
}

#[test]
fn reports_padding_variants() {
    let standard_padded = propose_transforms(b"+/8=", budget(8, 8));
    let url_unpadded = propose_transforms(b"-_8", budget(8, 8));

    assert_eq!(
        proposed_operations(&standard_padded),
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }]
    );
    assert_eq!(
        proposed_operations(&url_unpadded),
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Forbidden,
        }]
    );
}

#[test]
fn shares_one_candidate_for_unpadded_full_quartets() {
    let report = propose_transforms(b"TWFu", budget(8, 8));
    let representative = base64_mode(Base64Alphabet::Standard, Base64Padding::Required);

    assert_eq!(proposed_operations(&report), vec![representative.clone()]);
    assert_eq!(eligible_base64_mode_count(&report), 4);
    assert_eq!(
        eligible_base64_dispositions(&report),
        vec![
            (
                representative.clone(),
                TransformProposalDisposition::Proposed
            ),
            (
                base64_mode(Base64Alphabet::Standard, Base64Padding::Forbidden),
                alias_of(&representative)
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Required),
                alias_of(&representative)
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Forbidden),
                alias_of(&representative)
            ),
        ]
    );
    assert_eq!(report.omissions.candidates, 0);
}

#[test]
fn shares_candidates_for_padded_and_unpadded_partial_inputs() {
    let padded = propose_transforms(b"TWE=", budget(8, 8));
    let unpadded = propose_transforms(b"TWE", budget(8, 8));
    let padded_representative = base64_mode(Base64Alphabet::Standard, Base64Padding::Required);
    let unpadded_representative = base64_mode(Base64Alphabet::Standard, Base64Padding::Forbidden);

    assert_eq!(
        proposed_operations(&padded),
        vec![padded_representative.clone()]
    );
    assert_eq!(eligible_base64_mode_count(&padded), 2);
    assert_eq!(
        eligible_base64_dispositions(&padded),
        vec![
            (
                padded_representative.clone(),
                TransformProposalDisposition::Proposed
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Required),
                alias_of(&padded_representative)
            ),
        ]
    );
    assert_eq!(
        proposed_operations(&unpadded),
        vec![unpadded_representative.clone()]
    );
    assert_eq!(eligible_base64_mode_count(&unpadded), 2);
    assert_eq!(
        eligible_base64_dispositions(&unpadded),
        vec![
            (
                unpadded_representative.clone(),
                TransformProposalDisposition::Proposed
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Forbidden),
                alias_of(&unpadded_representative)
            ),
        ]
    );
}

#[test]
fn keeps_alphabet_specific_modes_distinct_and_rejects_mixed_alphabets() {
    let standard = propose_transforms(b"+///", budget(8, 8));
    let url_safe = propose_transforms(b"-_8", budget(8, 8));
    let mixed = propose_transforms(b"+_8", budget(8, 8));
    let standard_representative = base64_mode(Base64Alphabet::Standard, Base64Padding::Required);

    assert_eq!(
        proposed_operations(&standard),
        vec![standard_representative.clone()]
    );
    assert_eq!(eligible_base64_mode_count(&standard), 2);
    assert_eq!(
        eligible_base64_dispositions(&standard),
        vec![
            (
                standard_representative.clone(),
                TransformProposalDisposition::Proposed
            ),
            (
                base64_mode(Base64Alphabet::Standard, Base64Padding::Forbidden),
                alias_of(&standard_representative)
            ),
        ]
    );
    assert_eq!(
        proposed_operations(&url_safe),
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Forbidden,
        }]
    );
    assert_eq!(eligible_base64_mode_count(&url_safe), 1);
    assert_eq!(proposed_operations(&mixed).len(), 0);
    assert_eq!(eligible_base64_mode_count(&mixed), 0);
    assert_eq!(mixed.assessments.len(), 7);
    let mixed_base64_assessments = mixed
        .assessments
        .iter()
        .filter(|assessment| matches!(&assessment.operation, Operation::Base64Decode { .. }))
        .collect::<Vec<_>>();
    assert_eq!(mixed_base64_assessments.len(), 4);
    assert!(mixed_base64_assessments.iter().all(|assessment| matches!(
        &assessment.result,
        TransformAssessmentResult::Ineligible {
            reason: l2_workbench::recovery::proposals::TransformIneligibility::InvalidBase64Syntax,
        }
    )));
}

#[test]
fn serialized_report_round_trips_aliases_and_rejection_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let report = propose_transforms(b"+///", budget(8, 7));
    let serialized = serde_json::to_vec(&report)?;
    let restored: l2_workbench::recovery::proposals::TransformProposalReport =
        serde_json::from_slice(&serialized)?;

    assert_eq!(restored, report);
    assert!(
        eligible_base64_dispositions(&restored)
            .iter()
            .any(|(_, disposition)| matches!(
                disposition,
                TransformProposalDisposition::AliasOf { .. }
            ))
    );
    assert!(restored.assessments.iter().any(|assessment| matches!(
        &assessment.result,
        TransformAssessmentResult::Ineligible {
            reason: l2_workbench::recovery::proposals::TransformIneligibility::InvalidBase64Syntax,
        }
    )));
    Ok(())
}

#[test]
fn zero_candidate_budget_counts_equivalence_classes_and_retains_assessments() {
    let report = propose_transforms(b"TWFu", budget(0, 7));
    let representative = base64_mode(Base64Alphabet::Standard, Base64Padding::Required);

    assert_eq!(report.proposals.len(), 0);
    assert_eq!(report.assessments.len(), 7);
    assert_eq!(report.omissions.candidates, 1);
    assert_eq!(report.omissions.reports, 0);
    assert_eq!(eligible_base64_mode_count(&report), 4);
    assert_eq!(
        eligible_base64_dispositions(&report),
        vec![
            (
                representative.clone(),
                TransformProposalDisposition::OmittedByCandidateBudget
            ),
            (
                base64_mode(Base64Alphabet::Standard, Base64Padding::Forbidden),
                alias_of(&representative)
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Required),
                alias_of(&representative)
            ),
            (
                base64_mode(Base64Alphabet::UrlSafe, Base64Padding::Forbidden),
                alias_of(&representative)
            ),
        ]
    );
}

#[test]
fn matches_base64_decoder_rules() -> Result<(), Box<dyn std::error::Error>> {
    let inputs: &[&[u8]] = &[
        b"TWFu", b"TWE=", b"TWE", b"TQ==", b"TQ=", b"TR==", b"TR", b"Q", b"+/8=", b"-_8", b"+/8",
        b"-_8=", b"+_8", b"AA==\n", b"AAAAA",
    ];

    for input in inputs {
        let proposal_report = propose_transforms(input, budget(8, 8));
        for alphabet in [Base64Alphabet::Standard, Base64Alphabet::UrlSafe] {
            for padding in [Base64Padding::Required, Base64Padding::Forbidden] {
                let operation = Operation::Base64Decode { alphabet, padding };
                let recipe = Recipe {
                    steps: vec![operation.clone()],
                    constraints: Vec::new(),
                };
                let canonical = run(input, &recipe)?;
                let expected_eligible = canonical.status == DerivationStatus::Completed;
                let observed_eligible =
                    assessment(&proposal_report, &operation).is_some_and(|item| {
                        matches!(&item.result, TransformAssessmentResult::Eligible { .. })
                    });

                assert_eq!(observed_eligible, expected_eligible);
                if expected_eligible {
                    let evidence_length =
                        assessment(&proposal_report, &operation).and_then(|item| {
                            match &item.result {
                                TransformAssessmentResult::Eligible {
                                    evidence: TransformEvidence::Base64Syntax { decoded_bytes, .. },
                                    ..
                                } => Some(*decoded_bytes),
                                TransformAssessmentResult::Eligible { .. }
                                | TransformAssessmentResult::Ineligible { .. } => None,
                            }
                        });
                    assert_eq!(evidence_length, Some(canonical.output.len()));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn accepts_complete_optional_headers() -> Result<(), Box<dyn std::error::Error>> {
    let mut gzip_header = vec![
        0x1f, 0x8b, 0x08, 0x1e, 0, 0, 0, 0, 0, 3, // fixed header
        2, 0, 0xaa, 0xbb, // extra field
        b'n', b'a', b'm', b'e', 0, // original file name
        b'c', b'o', b'm', b'm', b'e', b'n', b't', 0, // comment
    ];
    let header_crc =
        u16::try_from(crc32fast::hash(&gzip_header) & u32::from(u16::MAX))?.to_le_bytes();
    gzip_header.extend_from_slice(&header_crc);
    let report = propose_transforms(&gzip_header, budget(8, 8));

    assert_eq!(
        proposed_operations(&report),
        vec![Operation::GzipDecompress {}]
    );
    assert!(report.assessments.iter().any(|item| matches!(
        &item.result,
        TransformAssessmentResult::Eligible {
            evidence: TransformEvidence::GzipHeader {
                header_crc_checked: true,
                ..
            },
            ..
        }
    )));
    Ok(())
}

#[test]
fn accepts_dictionary_header() {
    let zlib_header = [0x78, 0x20, 0x00, 0x00, 0x00, 0x01];
    let report = propose_transforms(&zlib_header, budget(8, 8));

    assert_eq!(
        proposed_operations(&report),
        vec![Operation::ZlibDecompress {}]
    );
    assert!(report.assessments.iter().any(|item| matches!(
        &item.result,
        TransformAssessmentResult::Eligible {
            evidence: TransformEvidence::ZlibHeader {
                dictionary_id: Some(1),
                ..
            },
            ..
        }
    )));
}

#[test]
fn exposes_recipe_operations() {
    let report = propose_transforms(b"4142", budget(1, 7));
    let proposal = report.proposals.first();

    assert_eq!(
        proposal.map(|item| &item.recipe),
        Some(&Recipe {
            steps: vec![Operation::HexDecode {}],
            constraints: Vec::new(),
        })
    );
}

#[test]
fn proposal_scan_work_bound_covers_full_input_passes_and_fixed_header_reads() {
    assert_eq!(transform_proposal_scan_work_bound(0), Some(0));
    assert_eq!(transform_proposal_scan_work_bound(1), Some(13));
    assert_eq!(transform_proposal_scan_work_bound(64), Some(7 * 64 + 6));
    assert_eq!(transform_proposal_scan_work_bound(usize::MAX), None);
}
