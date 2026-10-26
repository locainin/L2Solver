use super::validation::ValidationDecision;
use super::{
    CaseIndex, Executor, RecoveryExecutionError, RecoveryExecutionPolicy, RecoveryOmission,
    RecoveryPlan, TransformExplorationBudget, discovery_input_coverage_complete, execute,
    normal_policy, report_details_complete, search_exhaustive_within_plan,
};
use crate::workbench::framing_materialize::FramingSelectionBasis;
use crate::workbench::{decode::service::DecodeBatchLimits, expand::ExpansionLimits};
use l2_workbench::{
    derivation::{
        Base64Alphabet, Base64Padding, Constraint, DerivationLimits, HexCase, Operation, Recipe,
    },
    evidence::{
        ByteMapping, Case, Edge, EvidenceError, EvidenceStatus, MAX_EDGES, MAX_NODE_DETAILS_BYTES,
        MAX_NODES, SourceRange,
    },
    protocol::FramingKind,
    recovery::{
        RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState, RecoveryCoordinator,
        RecoveryError, RecoveryResource, RecoveryResourcePolicy, RecoveryResult, RecoveryStage,
        RecoveryTask, proposals::TransformProposalBudget,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
};

#[test]
fn recovery_status_separates_transform_search_and_report_omissions() {
    let candidate_omission = RecoveryOmission::TransformDiscoveryAnalysis {
        input_node_id: 7,
        omitted_candidates: 1,
        omitted_reports: 0,
    };
    assert!(!search_exhaustive_within_plan(std::slice::from_ref(
        &candidate_omission
    )));
    assert!(discovery_input_coverage_complete(std::slice::from_ref(
        &candidate_omission
    )));
    assert!(report_details_complete(std::slice::from_ref(
        &candidate_omission
    )));

    let association_omission = RecoveryOmission::TransformProposalAssociations {
        report_node_id: 12,
        input_node_id: 7,
        used: 1,
        limit: 1,
        requested: 1,
        omitted_count: 1,
    };
    assert!(!search_exhaustive_within_plan(std::slice::from_ref(
        &association_omission
    )));
    assert!(report_details_complete(std::slice::from_ref(
        &association_omission
    )));

    let report_omission = RecoveryOmission::TransformDiscoveryAnalysis {
        input_node_id: 8,
        omitted_candidates: 0,
        omitted_reports: 2,
    };
    assert!(search_exhaustive_within_plan(std::slice::from_ref(
        &report_omission
    )));
    assert!(!report_details_complete(std::slice::from_ref(
        &report_omission
    )));

    let report_output_exhaustion = RecoveryOmission::ResourceExhausted {
        task: RecoveryTask::TransformDiscovery,
        input_node_ids: vec![8],
        resource: RecoveryResource::OutputBytes,
        limit: 1,
        used: 1,
        requested: 1,
    };
    assert!(search_exhaustive_within_plan(std::slice::from_ref(
        &report_output_exhaustion
    )));
    assert!(!report_details_complete(std::slice::from_ref(
        &report_output_exhaustion
    )));

    let transform_work_exhaustion = RecoveryOmission::ResourceExhausted {
        task: RecoveryTask::TransformDiscovery,
        input_node_ids: vec![9],
        resource: RecoveryResource::WorkBytes,
        limit: 1,
        used: 0,
        requested: 2,
    };
    assert!(!search_exhaustive_within_plan(std::slice::from_ref(
        &transform_work_exhaustion
    )));
    assert!(report_details_complete(std::slice::from_ref(
        &transform_work_exhaustion
    )));

    let input_omission = RecoveryOmission::FramingDiscoveryInputs {
        source_id: Some("source".to_owned()),
        omitted_runs: 1,
        reason_counts: BTreeMap::default(),
    };
    assert!(!discovery_input_coverage_complete(std::slice::from_ref(
        &input_omission
    )));
    assert!(search_exhaustive_within_plan(std::slice::from_ref(
        &input_omission
    )));
}

#[test]
fn record_case_scan_exhaustion_does_not_skip_unrelated_transform_work() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    source(&mut case, "imported_source", b"4142")?;
    let mut execution_policy = normal_policy(&case)?;
    execution_policy.record_phase_work_limit = 0;
    let plan = RecoveryPlan {
        recipes: vec![hex_recipe()],
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let transform = only_transform(&outcome.candidates, &hex_recipe(), &blob_id(b"4142"))?;
    assert!(matches!(
        transform.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { .. },
            ..
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery,
            resource: RecoveryResource::WorkBytes,
            limit: 0,
            ..
        }
    )));
    Ok(())
}

#[test]
fn shared_origin_context() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let http = source(&mut case, "http_body", b"4142")?;
    let udp = source(&mut case, "udp_payload", b"4142")?;
    let outcome = execute(&mut case, &hex_plan(), &policy())?;

    let transform = only_transform(&outcome.candidates, &hex_recipe(), &blob_id(b"4142"))?;
    let input = transform.inputs().first().ok_or("input is missing")?;
    assert_eq!(
        input
            .origin_node_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([http, udp])
    );
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived { evidence_node_id },
        ..
    } = transform.state()
    else {
        return Err("shared transform did not finish with terminal evidence".into());
    };
    let direct_terminal_origins = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.from == *evidence_node_id
                && edge.relation == "derived_from"
                && edge.status == EvidenceStatus::Observed
        })
        .map(|edge| edge.to)
        .collect::<BTreeSet<_>>();
    assert_eq!(direct_terminal_origins, BTreeSet::from([http, udp]));
    Ok(())
}

#[test]
fn repeated_contextual_decoding_view_reuses_the_same_provenance_node() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let input_node = case.add_bytes_node("source", b"input", Vec::new(), json!({}))?;
    let output_node = case.add_bytes_node("decoding_output", b"output", Vec::new(), json!({}))?;
    let receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    let other_input_node = case.add_bytes_node("source", b"other input", Vec::new(), json!({}))?;
    let other_receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    let plan = RecoveryPlan::default();
    let execution_policy = policy();
    let mut executor = super::test_support::build_executor(&mut case, &plan, &execution_policy)?;

    let first_view = executor.contextual_decoding_view(output_node, receipt_node, input_node)?;
    let node_count_after_first = executor.case.nodes().len();
    let edge_count_after_first = executor.case.edges().len();
    let repeated_view = executor.contextual_decoding_view(output_node, receipt_node, input_node)?;

    assert_eq!(repeated_view, first_view);
    assert_eq!(executor.case.nodes().len(), node_count_after_first);
    assert_eq!(executor.case.edges().len(), edge_count_after_first);

    let other_input_view =
        executor.contextual_decoding_view(output_node, receipt_node, other_input_node)?;
    let other_receipt_view =
        executor.contextual_decoding_view(output_node, other_receipt_node, input_node)?;
    assert_ne!(other_input_view, first_view);
    assert_ne!(other_receipt_view, first_view);
    assert_ne!(other_input_view, other_receipt_view);
    assert_eq!(executor.case.nodes().len(), node_count_after_first + 2);
    assert_eq!(executor.case.edges().len(), edge_count_after_first + 6);
    Ok(())
}

#[test]
fn contextual_decoding_view_reuses_a_preindexed_node_and_repairs_links()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("source", b"input", Vec::new(), json!({}))?;
    let output_node = case.add_bytes_node("decoding_output", b"output", Vec::new(), json!({}))?;
    let receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    let existing_view = case.add_bytes_node(
        "decoding_output",
        b"output",
        Vec::new(),
        json!({
            "external_acceptance":"not_tested",
            "shared_transform_receipt":receipt_node,
            "source_input_node":input_node
        }),
    )?;
    let plan = RecoveryPlan::default();
    let execution_policy = policy();
    let mut executor = super::test_support::build_executor(&mut case, &plan, &execution_policy)?;
    let node_count_before = executor.case.nodes().len();

    let view = executor.contextual_decoding_view(output_node, receipt_node, input_node)?;
    let repeated_view = executor.contextual_decoding_view(output_node, receipt_node, input_node)?;

    assert_eq!(view, existing_view);
    assert_eq!(repeated_view, existing_view);
    assert_eq!(executor.case.nodes().len(), node_count_before);
    assert_eq!(executor.case.edges().len(), 3);
    Ok(())
}

#[test]
fn failed_contextual_decoding_view_commit_does_not_cache_rolled_back_node()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("source", b"input", Vec::new(), json!({}))?;
    let output_node = case.add_bytes_node("decoding_output", b"output", Vec::new(), json!({}))?;
    let receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    fill_edges_to_quota(&mut case, input_node, MAX_EDGES - 2)?;
    let plan = RecoveryPlan::default();
    let execution_policy = policy();
    let mut executor = super::test_support::build_executor(&mut case, &plan, &execution_policy)?;
    let before = executor.case.clone();
    let key = (blob_id(b"output"), receipt_node, input_node);

    assert!(
        executor
            .contextual_decoding_view(output_node, receipt_node, input_node)
            .is_err()
    );

    assert_eq!(*executor.case, before);
    assert!(
        !executor
            .case_index
            .contextual_decoding_views
            .contains_key(&key)
    );
    Ok(())
}

#[test]
fn repeated_embedded_paths_merge() -> Result<(), Box<dyn Error>> {
    let object = png(&[])?;
    let mut source_bytes = b"prefix".to_vec();
    source_bytes.extend_from_slice(&object);
    source_bytes.extend_from_slice(b"between");
    source_bytes.extend_from_slice(&object);
    let mut case = Case::new();
    source(&mut case, "http_body", &source_bytes)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy())?;

    let object_validations = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::StructuralValidation
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.blob_id() == blob_id(&object))
        })
        .collect::<Vec<_>>();
    let validation_depths = object_validations
        .iter()
        .map(|candidate| candidate.depth())
        .collect::<BTreeSet<_>>();
    let validation_origins = object_validations
        .iter()
        .flat_map(|candidate| {
            candidate
                .inputs()
                .first()
                .into_iter()
                .flat_map(|input| input.origin_node_ids().iter().copied())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(object_validations.len(), validation_depths.len());
    assert!(validation_origins.len() >= 2);
    assert!(outcome.candidates.iter().all(is_terminal));
    Ok(())
}

#[test]
fn direct_png_reaches_fixed_point_without_self_expansion_omission() -> Result<(), Box<dyn Error>> {
    let object = tiny_png()?;
    let mut case = Case::new();
    let source_node = source(&mut case, "http_body", &object)?;
    let equivalent_source_node = source(&mut case, "udp_payload", &object)?;
    let mut containing_stream = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec();
    containing_stream.extend_from_slice(&object);
    let stream_node = source(&mut case, "tcp_byte_run", &containing_stream)?;

    let production_policy = normal_policy(&case)?;
    let outcome = execute(&mut case, &RecoveryPlan::default(), &production_policy)?;

    assert!(
        outcome.complete,
        "a whole-input PNG must not exhaust recursion depth by rediscovering itself: {:?}",
        outcome.omissions
    );
    assert_eq!(outcome.validated_artifact_count, 1);
    assert_png_structure_origins(&case, &object, stream_node)?;
    assert_direct_png_validation(
        &case,
        &outcome.candidates,
        source_node,
        equivalent_source_node,
    )
}

fn assert_png_structure_origins(
    case: &Case,
    object: &[u8],
    stream_node: u64,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        case.nodes()
            .iter()
            .filter(|node| node.kind == "png_structure")
            .count(),
        2,
        "the direct PNG and its distinct nested stream occurrence each retain one structure"
    );
    let nested_artifact = case.nodes().iter().find(|node| {
        node.kind == "embedded_artifact"
            && node.blob.as_deref() == Some(&blob_id(object))
            && node
                .details
                .get("input_node")
                .and_then(serde_json::Value::as_u64)
                == Some(stream_node)
    });
    let nested_artifact_id = nested_artifact
        .map(|node| node.id)
        .ok_or("the distinct nested PNG occurrence was not retained")?;
    assert!(case.edges().iter().any(|edge| {
        edge.from == stream_node
            && edge.to == nested_artifact_id
            && edge.relation == "contains_embedded_candidate"
            && edge.status == EvidenceStatus::Observed
    }));
    Ok(())
}

fn assert_direct_png_validation(
    case: &Case,
    candidates: &[RecoveryCandidate],
    source_node: u64,
    equivalent_source_node: u64,
) -> Result<(), Box<dyn Error>> {
    let source_validation = candidates.iter().find(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate.depth() == 0
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&source_node))
    });
    assert!(matches!(
        source_validation.map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::ObservedValidation { .. },
            ..
        })
    ));
    let validation_origins = source_validation
        .and_then(|candidate| candidate.inputs().first())
        .map(|input| {
            input
                .origin_node_ids()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        })
        .ok_or("direct PNG validation input is missing")?;
    assert_eq!(
        validation_origins,
        BTreeSet::from([source_node, equivalent_source_node])
    );
    let validation_receipt = case.nodes().iter().find(|node| {
        node.kind == "artifact_validation_receipt"
            && node
                .details
                .get("input_node")
                .and_then(serde_json::Value::as_u64)
                == Some(source_node)
    });
    let validation_receipt_id = validation_receipt
        .map(|node| node.id)
        .ok_or("direct PNG validation receipt is missing")?;
    let validation_source_origins = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.from == validation_receipt_id
                && edge.relation == "validated_by"
                && edge.status == EvidenceStatus::Observed
        })
        .map(|edge| edge.to)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        validation_source_origins,
        BTreeSet::from([equivalent_source_node])
    );
    assert!(case.edges().iter().any(|edge| {
        edge.from == source_node
            && edge.to == validation_receipt_id
            && edge.relation == "validated_range"
            && edge.status == EvidenceStatus::Observed
    }));
    assert!(!case.edges().iter().any(|edge| {
        edge.from == validation_receipt_id
            && edge.to == source_node
            && edge.relation == "validated_by"
    }));
    Ok(())
}

#[test]
fn expansion_keeps_absolute_depth() -> Result<(), Box<dyn Error>> {
    let leaf = png(&[])?;
    let inner = stored_zip(b"leaf.png", &leaf)?;
    let middle = stored_zip(b"inner.zip", &inner)?;
    let outer = stored_zip(b"middle.zip", &middle)?;
    let mut case = Case::new();
    source(&mut case, "imported_source", &outer)?;
    let mut limited = policy();
    limited.resources.max_depth = 2;
    limited.expansion_limits.depth = 2;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    let inner_blob_id = blob_id(&inner);
    let inner_node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "archive_member" && node.blob.as_deref() == Some(&inner_blob_id))
        .ok_or("middle ZIP did not retain the inner archive")?;
    let inner_validation = outcome.candidates.iter().find(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&inner_node.id))
    });
    assert_eq!(inner_validation.map(RecoveryCandidate::depth), Some(2));
    let inner_expansion = outcome.candidates.iter().find(|candidate| {
        candidate.task() == &RecoveryTask::RecursiveExpansion
            && candidate.depth() == 2
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&inner_node.id))
    });
    assert!(matches!(
        inner_expansion.map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::RecursionDepth,
                ..
            },
            ..
        })
    ));
    assert!(!case.nodes().iter().any(|node| {
        node.kind == "archive_member"
            && node
                .details
                .get("archive_node")
                .and_then(serde_json::Value::as_u64)
                == Some(inner_node.id)
    }));
    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                resource: RecoveryResource::RecursionDepth,
                ..
            }
        )
    }));
    Ok(())
}

#[test]
fn rejected_candidate_continues() -> Result<(), Box<dyn Error>> {
    let mut corrupt = png(&[])?;
    let last = corrupt.last_mut().ok_or("PNG fixture is empty")?;
    *last ^= 1;
    let valid = png(&[])?;
    let mut input = corrupt.clone();
    input.extend_from_slice(&valid);
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", &input)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy())?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&input_node))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Rejected { .. },
                    ..
                }
            )
    }));
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::EmbeddedDiscovery
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&input_node))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    assert!(validated_input_bytes(&case, &outcome.candidates).contains(&valid));
    let receipt = case.nodes().iter().find(|node| {
        node.kind == "embedded_discovery_receipt"
            && node
                .details
                .get("input_node")
                .and_then(serde_json::Value::as_u64)
                == Some(input_node)
    });
    let receipt_blob = receipt
        .and_then(|node| node.blob.as_deref())
        .ok_or("embedded discovery receipt report blob is missing")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("embedded discovery receipt report bytes are missing")?;
    let full_report: serde_json::Value = serde_json::from_slice(receipt_bytes)?;
    let candidates = full_report
        .get("candidates")
        .and_then(serde_json::Value::as_array)
        .ok_or("embedded discovery receipt is missing candidate results")?;
    assert_eq!(
        candidates
            .first()
            .and_then(|candidate| candidate.get("validation"))
            .and_then(|validation| validation.get("status"))
            .and_then(serde_json::Value::as_str),
        Some("rejected")
    );
    assert_eq!(
        candidates
            .get(1)
            .and_then(|candidate| candidate.get("validation"))
            .and_then(|validation| validation.get("status"))
            .and_then(serde_json::Value::as_str),
        Some("validated")
    );
    Ok(())
}

#[test]
fn explicit_transform_chain() -> Result<(), Box<dyn Error>> {
    let object = png(&[])?;
    let key = [0x5a, 0x17, 0xc3];
    let encrypted = xor(&object, &key)?;
    let encoded = hex_encode(&encrypted)?;
    let mut case = Case::new();
    source(&mut case, "imported_source", encoded.as_bytes())?;
    let plan = RecoveryPlan {
        recipes: vec![Recipe {
            steps: vec![
                Operation::HexDecode {},
                Operation::XorRepeat {
                    key: key.to_vec(),
                    offset: 0,
                },
            ],
            constraints: Vec::new(),
        }],
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    assert!(validated_input_bytes(&case, &outcome.candidates).contains(&object));
    assert!(outcome.complete);
    Ok(())
}

#[test]
fn transform_output_limit_is_resource_exhaustion() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "imported_source", b"a")?;
    let recipe = Recipe {
        steps: vec![Operation::Base64Encode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        ..RecoveryPlan::default()
    };
    let mut limited = policy();
    limited.resources.max_output_bytes = 1;

    let outcome = execute(&mut case, &plan, &limited)?;

    let transform = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::Transform(recipe.clone())
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids().contains(&input_node))
        })
        .ok_or("transform candidate is missing")?;
    assert!(matches!(
        transform.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::OutputBytes,
                limit: 1,
                ..
            },
            ..
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::Transform(selected),
                resource: RecoveryResource::OutputBytes,
                limit: 1,
                ..
            } if selected == &recipe
        )
    }));
    assert!(
        case.nodes()
            .iter()
            .all(|node| node.kind != "decoding_output")
    );
    Ok(())
}

#[test]
fn reordered_seed_equivalence() -> Result<(), Box<dyn Error>> {
    let first = png(&[])?;
    let second = b"unstructured bytes".to_vec();
    let forward = recover_in_order(&[("http_body", &first), ("udp_payload", &second)])?;
    let reverse = recover_in_order(&[("udp_payload", &second), ("http_body", &first)])?;

    assert_eq!(forward.0, reverse.0);
    assert_eq!(forward.1, reverse.1);
    Ok(())
}

#[test]
fn fixed_point_drains() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", b"4142")?;

    let outcome = execute(&mut case, &hex_plan(), &policy())?;

    let transform_candidates = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::Transform(hex_recipe()))
        .count();
    assert_eq!(transform_candidates, 3);
    assert!(outcome.candidates.iter().all(is_terminal));
    Ok(())
}

#[test]
fn inverse_tasks_stop_cycle() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", b"AB")?;
    let plan = RecoveryPlan {
        recipes: vec![
            Recipe {
                steps: vec![Operation::HexEncode {
                    case: HexCase::Lower,
                }],
                constraints: Vec::new(),
            },
            Recipe {
                steps: vec![Operation::HexDecode {}],
                constraints: Vec::new(),
            },
        ],
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    assert!(outcome.cycle_skips > 0);
    assert!(outcome.candidates.iter().all(is_terminal));
    Ok(())
}

#[test]
fn shallow_expansion_retries() -> Result<(), Box<dyn Error>> {
    let inner = png(&[])?;
    let mut outer = png(&[])?;
    outer.extend_from_slice(&inner);
    let outer_encoded = hex_encode(&outer)?;
    let inner_encoded = hex_encode(&inner)?;
    let mut case = Case::new();
    source(&mut case, "imported_source", outer_encoded.as_bytes())?;
    source(&mut case, "udp_payload", inner_encoded.as_bytes())?;

    let outcome = execute(&mut case, &hex_plan(), &policy())?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::RecursiveExpansion
            && candidate.depth() == 1
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.blob_id() == blob_id(&inner))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn embedded_scan_omission_stays_partial() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = source(&mut case, "http_body", b"unstructured bytes")?;
    let mut limited = policy();
    limited.embedded_limits.max_scan_bytes = 1;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::EmbeddedDiscovery {
                input_node_id,
                omissions
            } if *input_node_id == input && omissions.unscanned_range.is_some()
        )
    }));
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::EmbeddedDiscovery
            && candidate
                .inputs()
                .first()
                .is_some_and(|entry| entry.origin_node_ids().contains(&input))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Omitted,
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn false_embedded_signatures_do_not_create_artifacts() -> Result<(), Box<dyn Error>> {
    let false_signatures = [
        b"\x89PNG\r\n\x1a\nnot a PNG chunk".as_slice(),
        b"PK\x03\x04not a ZIP archive".as_slice(),
    ];
    for bytes in false_signatures {
        let mut case = Case::new();
        let input_node = source(&mut case, "http_body", bytes)?;

        let outcome = execute(&mut case, &RecoveryPlan::default(), &policy())?;

        assert!(outcome.candidates.iter().any(|candidate| {
            candidate.task() == &RecoveryTask::EmbeddedDiscovery
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids().contains(&input_node))
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Rejected { .. },
                        ..
                    }
                )
        }));
        assert!(
            case.nodes()
                .iter()
                .all(|node| node.kind != "embedded_artifact")
        );
        assert_eq!(outcome.validated_artifact_count, 0);
    }
    Ok(())
}

#[test]
fn large_child_work_omitted() -> Result<(), Box<dyn Error>> {
    let child = vec![b'x'; 4096];
    let outer = png(&[(*b"IDAT", child.as_slice())])?;
    let mut case = Case::new();
    source(&mut case, "http_body", &outer)?;
    let mut limited = policy();
    limited.resources.max_work_bytes = outer.len().saturating_mul(3).saturating_add(8);
    limited.embedded_limits.max_scan_bytes = 8;
    limited.embedded_limits.max_validation_attempts = 0;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    assert!(
        outcome
            .omissions
            .iter()
            .any(|omission| { matches!(omission, RecoveryOmission::ArtifactExpansion { .. }) })
    );
    assert!(
        case.nodes()
            .iter()
            .all(|node| node.kind != "png_chunk_payload")
    );
    assert_eq!(outcome.validated_artifact_count, 1);
    Ok(())
}

#[test]
fn only_semantic_sources_seed() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let semantic_sources = [
        ("imported_source", b"4141".as_slice()),
        ("http_body", b"4242".as_slice()),
        ("ftp_data_candidate", b"4343".as_slice()),
        ("tcp_byte_run", b"4444".as_slice()),
        ("udp_payload", b"4545".as_slice()),
        ("udp_trailing_bytes", b"4646".as_slice()),
    ];
    let mut semantic_nodes = Vec::new();
    for (kind, bytes) in semantic_sources {
        semantic_nodes.push((source(&mut case, kind, bytes)?, bytes));
    }
    let packet = case.add_bytes_node("packet", b"4747", Vec::new(), json!({}))?;
    let receipt = case.add_bytes_node(
        "artifact_validation_receipt",
        b"4848",
        Vec::new(),
        json!({}),
    )?;

    let outcome = execute(&mut case, &hex_plan(), &policy())?;

    for (node_id, bytes) in semantic_nodes {
        let transform = only_transform(&outcome.candidates, &hex_recipe(), &blob_id(bytes))?;
        assert!(
            transform
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&node_id))
        );
    }
    assert!(outcome.candidates.iter().all(|candidate| {
        candidate.task() != &RecoveryTask::Transform(hex_recipe())
            || candidate.inputs().first().is_none_or(|input| {
                !input.origin_node_ids().contains(&packet)
                    && !input.origin_node_ids().contains(&receipt)
            })
    }));
    Ok(())
}

#[test]
fn large_source_reaches_discovery() -> Result<(), Box<dyn Error>> {
    let bytes = vec![b'x'; 16 * 1024 * 1024 + 1];
    let mut case = Case::new();
    let input_node = source(&mut case, "imported_source", &bytes)?;
    let policy = normal_policy(&case)?;
    assert!(policy.resources.max_input_bytes_per_item >= bytes.len());
    assert_eq!(policy.resources.max_inputs_per_candidate, MAX_NODES);
    let default_plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let embedded_child_tasks =
        super::policy::task_templates_for_node(&default_plan, "embedded_artifact", true);
    let expanded_child_tasks =
        super::policy::task_templates_for_node(&default_plan, "archive_member", true);
    let parent_task_multiplicity = embedded_child_tasks
        .len()
        .max(expanded_child_tasks.len())
        .checked_add(super::policy::transform_proposal_capacity()?)
        .ok_or("parent task multiplicity is not representable")?;
    assert_eq!(
        policy.resources.max_parent_links,
        MAX_EDGES * parent_task_multiplicity
    );
    assert_eq!(
        policy.resources.max_lineage_work,
        (3 * MAX_NODES + 2 * policy.resources.max_parent_links) * (policy.resources.max_depth + 1)
    );
    let resources = policy.resources;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::EmbeddedDiscovery
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&input_node))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Unsupported,
                    ..
                }
            )
    }));
    assert_eq!(
        outcome.resources.max_parent_links,
        resources.max_parent_links
    );
    assert_eq!(
        outcome.resources.max_lineage_work,
        resources.max_lineage_work
    );
    assert_eq!(
        outcome.resources.parent_links_retained + outcome.resources.parent_links_remaining,
        outcome.resources.max_parent_links
    );
    assert_eq!(
        outcome.resources.lineage_work_charged + outcome.resources.lineage_work_remaining,
        outcome.resources.max_lineage_work
    );
    Ok(())
}

#[test]
fn large_source_reaches_validation() -> Result<(), Box<dyn Error>> {
    let bytes = vec![b'x'; 64 * 1024 * 1024];
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", &bytes)?;
    let policy = normal_policy(&case)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&input_node))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Unsupported,
                    ..
                }
            )
    }));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    Ok(())
}

#[test]
fn large_zip_child_reaches_validation() -> Result<(), Box<dyn Error>> {
    let member = vec![b'x'; 16 * 1024 * 1024];
    let member_blob_id = blob_id(&member);
    let archive = stored_zip(b"member.bin", &member)?;
    let mut case = Case::new();
    source(&mut case, "imported_source", &archive)?;
    let policy = normal_policy(&case)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy)?;

    let child_validation = outcome.candidates.iter().find(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.blob_id() == member_blob_id)
    });
    assert!(matches!(
        child_validation.map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::Unsupported,
            ..
        })
    ));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    Ok(())
}

#[test]
fn normal_policy_covers_nested_archive_work() -> Result<(), Box<dyn Error>> {
    let leaf = png(&[])?;
    let inner = stored_zip(b"leaf.png", &leaf)?;
    let outer = stored_zip(b"nested.zip", &inner)?;
    let leaf_blob_id = blob_id(&leaf);
    let mut case = Case::new();
    source(&mut case, "imported_source", &outer)?;
    let policy = normal_policy(&case)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::RecursiveExpansion
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.blob_id() == blob_id(&inner))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    assert!(validated_input_bytes(&case, &outcome.candidates).contains(&leaf));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    assert!(case.blobs().iter().any(|blob| blob.id == leaf_blob_id));
    Ok(())
}

#[test]
fn validation_zip_work_is_shared() -> Result<(), Box<dyn Error>> {
    let first_content = b"first data";
    let second_content = b"other data";
    let first_archive = stored_zip(b"payload", first_content)?;
    let second_archive = stored_zip(b"payload", second_content)?;
    let mut case = Case::new();
    source(&mut case, "imported_source", &first_archive)?;
    source(&mut case, "imported_source", &second_archive)?;
    let root_task_passes = [
        RecoveryTask::EmbeddedDiscovery,
        RecoveryTask::StructuralValidation,
    ];
    let baseline_input_work = first_archive
        .len()
        .checked_mul(root_task_passes.len())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("ZIP fixture baseline work overflowed")?;
    let first_expansion = first_content.len();
    let available_for_second = second_content.len().saturating_sub(1);
    let max_work = baseline_input_work
        .checked_add(first_expansion)
        .and_then(|work| work.checked_add(available_for_second))
        .ok_or("ZIP fixture work limit overflowed")?;
    let mut limited = policy();
    limited.resources.max_work_bytes = max_work;
    limited.embedded_limits.max_validation_attempts = 0;
    limited.embedded_limits.max_zip_operation_expanded_bytes = 0;
    limited.expansion_limits.input_bytes = 0;
    limited.expansion_limits.zip_work_bytes = 0;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    assert_eq!(outcome.validated_artifact_count, 2);
    assert_eq!(
        case.nodes()
            .iter()
            .filter(|node| node.kind == "artifact_validation_receipt")
            .count(),
        2
    );
    assert_eq!(
        outcome
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.task() == &RecoveryTask::StructuralValidation
                    && matches!(
                        candidate.state(),
                        RecoveryCandidateState::Finished {
                            result: RecoveryResult::ObservedValidation { .. },
                            ..
                        }
                    )
            })
            .count(),
        2
    );
    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::StructuralValidation,
                resource: RecoveryResource::WorkBytes,
                used,
                requested,
                limit,
                ..
            } if used.saturating_add(*requested) > *limit
        )
    }));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    Ok(())
}

#[test]
fn validation_keeps_zip_artifact_when_shared_member_work_is_omitted() -> Result<(), Box<dyn Error>>
{
    let first_content = b"first";
    let second_content = b"second";
    let archive = stored_zip_entries(&[
        (b"first.bin", first_content),
        (b"second.bin", second_content),
    ])?;
    let mut case = Case::new();
    let input_node = source(&mut case, "imported_source", &archive)?;

    let root_task_passes = [
        RecoveryTask::TransformDiscovery,
        RecoveryTask::EmbeddedDiscovery,
        RecoveryTask::StructuralValidation,
    ];
    let input_work = archive
        .len()
        .checked_mul(root_task_passes.len())
        .ok_or("ZIP fixture baseline work overflowed")?;
    let max_work = input_work
        .checked_add(first_content.len())
        .and_then(|work| work.checked_add(second_content.len().saturating_sub(1)))
        .ok_or("ZIP fixture work limit overflowed")?;
    let mut limited = policy();
    limited.resources.max_work_bytes = max_work;
    limited.embedded_limits.max_validation_attempts = 0;
    limited.embedded_limits.max_zip_operation_expanded_bytes = 0;
    limited.expansion_limits.input_bytes = 0;
    limited.expansion_limits.zip_work_bytes = 0;
    limited.transform_exploration.max_scan_work_bytes_per_input = 0;
    let plan = RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &limited)?;

    assert_retained_zip_validation(&case, &outcome)?;
    assert!(has_zip_member_work_limit(
        &outcome.omissions,
        input_node,
        input_work + first_content.len(),
        second_content.len(),
        max_work,
    ));
    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::StageWorkLimit {
                task: RecoveryTask::TransformDiscovery,
                ..
            }
        )
    }));
    assert!(discovery_input_coverage_complete(&outcome.omissions));
    assert!(!search_exhaustive_within_plan(&outcome.omissions));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    Ok(())
}

fn assert_retained_zip_validation(
    case: &Case,
    outcome: &super::RecoveryExecutionOutcome,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(outcome.validated_artifact_count, 1, "{outcome:?}");
    let validation_receipt = case
        .nodes()
        .iter()
        .find(|node| node.kind == "artifact_validation_receipt")
        .ok_or("the ZIP validation receipt is missing")?;
    assert_eq!(
        validation_receipt
            .details
            .get("status")
            .and_then(Value::as_str),
        Some("validated")
    );
    assert_eq!(
        validation_receipt
            .details
            .get("format")
            .and_then(Value::as_str),
        Some("zip")
    );
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ObservedValidation { .. },
                    ..
                }
            )
    }));
    Ok(())
}

fn has_zip_member_work_limit(
    omissions: &[RecoveryOmission],
    input_node: u64,
    expected_used: usize,
    expected_request: usize,
    expected_limit: usize,
) -> bool {
    omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::StructuralValidation,
                input_node_ids,
                resource: RecoveryResource::WorkBytes,
                used,
                requested,
                limit,
                ..
            } if input_node_ids == &[input_node]
                && *used == expected_used
                && *requested == expected_request
                && *limit == expected_limit
                && used.saturating_add(*requested) > *limit
        )
    })
}

#[test]
fn record_report_work_is_bounded() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", &vec![1; 4096])?;
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":0,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":1,
        "length_meaning":"whole_record",
        "sequence_base":1,
        "terminal_sequence":null
    }))?;
    let plan = RecoveryPlan {
        record_schemas: vec![schema.clone()],
        ..RecoveryPlan::default()
    };
    let mut limited = policy();
    limited.resources.max_work_bytes = 64 * 1024;
    limited.record_limits.max_report_bytes = 4 * 1024 * 1024;

    let outcome = execute(&mut case, &plan, &limited)?;

    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_parse_receipt")
    );
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ResourceExhausted {
                        resource: RecoveryResource::WorkBytes,
                        ..
                    },
                    ..
                }
            )
    }));
    assert!(outcome.resources.work_charged_bytes <= outcome.resources.max_work_bytes);
    Ok(())
}

#[test]
fn record_output_budget_precedes_commit() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", &[1, 1, 4, 7])?;
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":2,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"whole_record",
        "sequence_base":1,
        "terminal_sequence":null
    }))?;
    let plan = RecoveryPlan {
        record_schemas: vec![schema.clone()],
        ..RecoveryPlan::default()
    };
    let mut limited = policy();
    limited.resources.max_output_bytes = 128;

    let outcome = execute(&mut case, &plan, &limited)?;

    assert!(!case.nodes().iter().any(|node| {
        matches!(
            node.kind.as_str(),
            "record_parse_receipt" | "record_candidate" | "record_object"
        )
    }));
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ResourceExhausted {
                        resource: RecoveryResource::OutputBytes,
                        ..
                    },
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn explicit_record_keeps_transforms() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0x44, 0, 8];
    bytes.extend_from_slice(b"64656164");
    let mut case = Case::new();
    source(&mut case, "imported_source", &bytes)?;
    let schema = candidate_record_schema()?;
    let plan = RecoveryPlan {
        record_schemas: vec![schema],
        discover_transforms: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    let candidate = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "record_candidate"
                && node.details.get("record_count").and_then(Value::as_u64) == Some(1)
        })
        .ok_or("single-record candidate is missing")?;
    assert!(outcome.candidates.iter().any(|recovery| {
        recovery.task() == &RecoveryTask::TransformDiscovery
            && recovery
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&candidate.id))
    }));
    assert!(!outcome.candidates.iter().any(|recovery| {
        recovery.task() == &RecoveryTask::RecursiveExpansion
            && recovery
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&candidate.id))
    }));
    assert!(outcome.candidates.iter().any(|recovery| {
        recovery.task() == &RecoveryTask::StructuralValidation
            && recovery
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().contains(&candidate.id))
    }));
    assert!(case.blobs().iter().any(|blob| blob.bytes == [0xde, 0xad]));
    Ok(())
}

#[test]
fn unsupported_bytes_skip_expansion() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", b"unstructured bytes")?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy())?;

    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| candidate.task() == &RecoveryTask::RecursiveExpansion)
    );
    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::StructuralValidation
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Unsupported,
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn records_group_framed_messages() -> Result<(), Box<dyn Error>> {
    let bytes = framed_record_bytes();
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"framed record inputs")?;
    let schema = framed_record_schema()?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema],
        ..RecoveryPlan::default()
    };

    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    execute(&mut case, &plan, &execution_policy)?;

    let object = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_object")
        .ok_or("records split across sibling frames were not assembled")?;
    let object_blob = object
        .blob
        .as_deref()
        .ok_or("record object bytes are missing")?;
    let object_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == object_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record object blob is missing")?;
    assert_eq!(object_bytes, b"xy");
    Ok(())
}

#[test]
fn framed_transform_lineage_batches_second_stage_outputs() -> Result<(), Box<dyn Error>> {
    let bytes = base64_hex_framed_record_bytes()?;
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"multi-stage framed record inputs")?;
    let schema = framed_record_schema()?;
    let base64_recipe = Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let hex_recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: Vec::new(),
    };
    let plan = RecoveryPlan {
        recipes: vec![base64_recipe, hex_recipe],
        framings: vec![FramingKind::FixedSize { bytes: 24 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };

    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let batch = successful_record_batch(&outcome.candidates, &schema, 2)?;
    let input_nodes = record_batch_input_nodes(batch)?;
    let expected_parts = framed_record_bytes()
        .chunks_exact(8)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let expected_hex_inputs = expected_parts
        .iter()
        .map(Vec::as_slice)
        .map(hexadecimal_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        batch
            .inputs()
            .iter()
            .map(l2_workbench::recovery::RecoveryInput::blob_id)
            .collect::<Vec<_>>(),
        expected_parts
            .iter()
            .map(Vec::as_slice)
            .map(blob_id)
            .collect::<Vec<_>>()
    );
    assert_eq!(input_nodes.len(), 2);
    for (output_node, expected_hex) in input_nodes.iter().copied().zip(&expected_hex_inputs) {
        assert_second_stage_transform_lineage(
            &case,
            &outcome.candidates,
            output_node,
            expected_hex,
        )?;
    }
    assert_record_receipt_positions(&case, batch, &input_nodes)?;
    let object = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_object")
        .ok_or("assembled record object is missing")?;
    let object_bytes = case
        .blobs()
        .iter()
        .find(|blob| object.blob.as_deref() == Some(blob.id.as_str()))
        .map(|blob| blob.bytes.as_slice())
        .ok_or("assembled record bytes are missing")?;
    assert_eq!(object_bytes, b"xy");
    Ok(())
}

#[test]
fn equivalent_recipes_share_frame_batch() -> Result<(), Box<dyn Error>> {
    let record_bytes = framed_record_bytes();
    let first_frame = record_bytes
        .get(..8)
        .ok_or("first framed record is missing")?
        .to_vec();
    let mut bytes = first_frame.clone();
    bytes.extend_from_slice(&first_frame);
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"equivalent recipe batch")?;
    let first_recipe = Recipe {
        steps: vec![Operation::RotateBits { count: 0 }],
        constraints: Vec::new(),
    };
    let equivalent_recipe = Recipe {
        steps: vec![Operation::RotateBits { count: 8 }],
        constraints: Vec::new(),
    };
    let schema = framed_record_schema()?;
    let plan = RecoveryPlan {
        recipes: vec![first_recipe.clone(), equivalent_recipe.clone()],
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let transform_count = shared_frame_transform_count(
        &case,
        &outcome.candidates,
        &[first_recipe, equivalent_recipe],
    );
    assert_eq!(transform_count, 1);
    let batch_count = equivalent_record_batch_count(&case, &outcome.candidates, &schema);
    assert_eq!(batch_count, 1);
    let contextual_views = contextual_frame_view_count(&case);
    assert_eq!(contextual_views, 2);
    Ok(())
}

fn successful_record_batch<'a>(
    candidates: &'a [RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
    input_count: usize,
) -> Result<&'a RecoveryCandidate, Box<dyn Error>> {
    candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == input_count
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .ok_or_else(|| "ordered record batch is missing".into())
}

fn record_batch_input_nodes(batch: &RecoveryCandidate) -> Result<Vec<u64>, Box<dyn Error>> {
    batch
        .inputs()
        .iter()
        .map(|input| {
            input
                .origin_node_ids()
                .first()
                .copied()
                .ok_or_else(|| "record input provenance is missing".into())
        })
        .collect()
}

fn assert_second_stage_transform_lineage(
    case: &Case,
    candidates: &[RecoveryCandidate],
    output_node: u64,
    expected_hex_input: &[u8],
) -> Result<(), Box<dyn Error>> {
    let second_receipt = decoding_receipt_for_output(case, output_node)?;
    assert_receipt_item_index(case, second_receipt, 0)?;
    let second_stage = transform_candidate_for_receipt(candidates, &hex_recipe(), second_receipt)?;
    assert_eq!(second_stage.depth(), 2);
    let expected_hex_blob = blob_id(expected_hex_input);
    assert_eq!(
        second_stage
            .inputs()
            .first()
            .map(l2_workbench::recovery::RecoveryInput::blob_id),
        Some(expected_hex_blob.as_str())
    );
    let first_output = second_stage
        .inputs()
        .first()
        .and_then(|input| input.origin_node_ids().first())
        .copied()
        .ok_or("first-stage output provenance is missing")?;
    let first_receipt = decoding_receipt_for_output(case, first_output)?;
    let first_stage =
        transform_candidate_for_receipt(candidates, &base64_decode_recipe(), first_receipt)?;
    assert_eq!(first_stage.depth(), 1);
    let first_stage_position = candidates
        .iter()
        .position(|candidate| candidate == first_stage)
        .ok_or("first-stage candidate position is missing")?;
    assert!(
        second_stage
            .parent_ids()
            .iter()
            .any(|parent| parent.index() == first_stage_position)
    );
    let first_output_node = case
        .nodes()
        .iter()
        .find(|node| node.id == first_output)
        .ok_or("first-stage output node is missing")?;
    assert_eq!(
        first_output_node.blob.as_deref(),
        Some(expected_hex_blob.as_str())
    );
    Ok(())
}

fn transform_candidate_for_receipt<'a>(
    candidates: &'a [RecoveryCandidate],
    recipe: &Recipe,
    receipt_node: u64,
) -> Result<&'a RecoveryCandidate, Box<dyn Error>> {
    candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::Transform(recipe.clone())
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { evidence_node_id },
                        ..
                    } if *evidence_node_id == receipt_node
                )
        })
        .ok_or_else(|| "transform candidate receipt is missing".into())
}

fn decoding_receipt_for_output(case: &Case, output_node: u64) -> Result<u64, Box<dyn Error>> {
    case.edges()
        .iter()
        .find(|edge| edge.relation == "produced" && edge.to == output_node)
        .and_then(|edge| {
            case.nodes()
                .iter()
                .find(|node| node.id == edge.from && node.kind == "decoding_receipt")
        })
        .map(|receipt| receipt.id)
        .ok_or_else(|| "decoding receipt for output is missing".into())
}

fn assert_receipt_item_index(
    case: &Case,
    receipt_node: u64,
    expected_index: u64,
) -> Result<(), Box<dyn Error>> {
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.id == receipt_node)
        .ok_or("decoding receipt is missing")?;
    assert_eq!(
        receipt
            .details
            .get("item_index")
            .and_then(serde_json::Value::as_u64),
        Some(expected_index)
    );
    Ok(())
}

fn assert_record_receipt_positions(
    case: &Case,
    batch: &RecoveryCandidate,
    input_nodes: &[u64],
) -> Result<(), Box<dyn Error>> {
    let receipt = record_batch_receipt(batch)?;
    let report = record_receipt_report(case, receipt)?;
    let report_inputs = report
        .get("inputs")
        .and_then(serde_json::Value::as_array)
        .ok_or("record receipt inputs are missing")?;
    assert_eq!(report_inputs.len(), input_nodes.len());
    for (index, output_node) in input_nodes.iter().copied().enumerate() {
        let expected_index = u64::try_from(index)?;
        assert_eq!(
            report_inputs
                .get(index)
                .and_then(|input| input.get("input_node"))
                .and_then(serde_json::Value::as_u64),
            Some(output_node)
        );
        assert_eq!(
            report
                .pointer(&format!("/assembly/groups/0/parts/{index}/input_index"))
                .and_then(serde_json::Value::as_u64),
            Some(expected_index)
        );
        assert_eq!(
            report
                .get("assembly_input_indexes")
                .and_then(serde_json::Value::as_array)
                .and_then(|indexes| indexes.get(index))
                .and_then(serde_json::Value::as_u64),
            Some(expected_index)
        );
    }
    Ok(())
}

#[test]
fn framed_identity_transform_cycle_reaches_a_fixed_point() -> Result<(), Box<dyn Error>> {
    let mut source_bytes = framed_record_bytes()
        .get(..8)
        .ok_or("framed record message is missing")?
        .to_vec();
    source_bytes.push(b'z');
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &source_bytes, b"single framed identity input")?;
    let schema = framed_record_schema()?;
    let plan = RecoveryPlan {
        recipes: vec![Recipe {
            steps: vec![Operation::RotateBits { count: 0 }],
            constraints: vec![l2_workbench::derivation::Constraint::Length { bytes: 8 }],
        }],
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    assert_eq!(outcome.cycle_skips, 1);
    assert!(
        outcome.candidate_count < 64,
        "identity transform should settle within a small candidate bound, got {}",
        outcome.candidate_count
    );
    assert_identity_cycle_record_batches(&case, &outcome.candidates, &schema)?;
    Ok(())
}

fn assert_identity_cycle_record_batches(
    case: &Case,
    candidates: &[RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
) -> Result<(), Box<dyn Error>> {
    let depth_two_batches = candidates
        .iter()
        .filter(|candidate| {
            candidate.depth() == 2
                && candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
        })
        .collect::<Vec<_>>();
    let successful_batches = depth_two_batches
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(successful_batches.len(), 1);
    let successful_batch = successful_batches
        .first()
        .copied()
        .ok_or("successful frame batch is missing")?;
    assert_record_batch_input_kind(case, successful_batch, "decoding_output")?;

    let nested_record_retries = depth_two_batches
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Rejected { .. },
                    ..
                }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(nested_record_retries.len(), 1);
    let nested_record_retry = nested_record_retries
        .first()
        .copied()
        .ok_or("nested record retry is missing")?;
    assert_record_batch_input_kind(case, nested_record_retry, "record_candidate")
}

fn assert_record_batch_input_kind(
    case: &Case,
    candidate: &RecoveryCandidate,
    expected_kind: &str,
) -> Result<(), Box<dyn Error>> {
    let input_node = candidate
        .inputs()
        .first()
        .and_then(|input| input.origin_node_ids().first())
        .copied()
        .ok_or("record batch input provenance is missing")?;
    assert_eq!(candidate.inputs().len(), 1);
    let input = case
        .nodes()
        .iter()
        .find(|node| node.id == input_node)
        .ok_or("record batch input node is missing")?;
    assert_eq!(input.kind, expected_kind);
    Ok(())
}

fn shared_frame_transform_count(
    case: &Case,
    candidates: &[RecoveryCandidate],
    recipes: &[Recipe],
) -> usize {
    candidates
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.task(),
                RecoveryTask::Transform(recipe) if recipes.contains(recipe)
            ) && candidate.depth() == 1
                && candidate.inputs().first().is_some_and(|input| {
                    input
                        .origin_node_ids()
                        .iter()
                        .filter(|origin| {
                            case.nodes().iter().any(|node| {
                                node.id == **origin && node.kind == "custom_protocol_frame"
                            })
                        })
                        .count()
                        == 2
                })
        })
        .count()
}

fn equivalent_record_batch_count(
    case: &Case,
    candidates: &[RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
) -> usize {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 2
                && candidate.inputs().iter().all(|input| {
                    input.origin_node_ids().iter().all(|origin| {
                        case.nodes().iter().any(|node| {
                            node.id == *origin
                                && node.kind == "decoding_output"
                                && node.details.get("source_input_node").is_some()
                        })
                    })
                })
        })
        .count()
}

fn contextual_frame_view_count(case: &Case) -> usize {
    case.nodes()
        .iter()
        .filter(|node| {
            node.kind == "decoding_output"
                && node
                    .details
                    .get("source_input_node")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|source| {
                        case.nodes()
                            .iter()
                            .any(|node| node.id == source && node.kind == "custom_protocol_frame")
                    })
        })
        .count()
}

#[test]
fn record_batch_input_limit_keeps_singletons() -> Result<(), Box<dyn Error>> {
    let bytes = framed_record_bytes();
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"framed record slots")?;
    let schema = framed_record_schema()?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        ..RecoveryPlan::default()
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 1;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(selected),
                resource: RecoveryResource::InputCount,
                ..
            } if selected == &schema
        )
    }));
    let singleton_batches = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 1
                && candidate.inputs().first().is_some_and(|input| {
                    input.origin_node_ids().first().is_some_and(|origin| {
                        case.nodes()
                            .iter()
                            .any(|node| node.id == *origin && node.kind == "custom_protocol_frame")
                    })
                })
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .count();
    assert_eq!(singleton_batches, 2);
    Ok(())
}

#[test]
fn record_batch_origin_limit_keeps_singletons() -> Result<(), Box<dyn Error>> {
    let bytes = framed_record_bytes();
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"framed record origins")?;
    let schema = framed_record_schema()?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        ..RecoveryPlan::default()
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    execution_policy.resources.max_origins_per_candidate = 1;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(selected),
                input_node_ids,
                resource: RecoveryResource::OriginCount,
                limit: 1,
                requested: 2,
                ..
            } if selected == &schema && input_node_ids.len() == 2
        )
    }));
    let singleton_batches = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 1
                && candidate.inputs().first().is_some_and(|input| {
                    input.origin_node_ids().first().is_some_and(|origin| {
                        case.nodes()
                            .iter()
                            .any(|node| node.id == *origin && node.kind == "custom_protocol_frame")
                    })
                })
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .count();
    assert_eq!(singleton_batches, 2);
    assert!(!outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && candidate.inputs().len() == 2
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn record_batch_total_input_limit_keeps_singletons() -> Result<(), Box<dyn Error>> {
    const FRAME_BYTES: usize = 26;
    const TOTAL_INPUT_LIMIT: usize = FRAME_BYTES * 2;

    // Hex encoding expands each framed sibling to the full per-candidate limit
    let mut bytes = vec![0; TOTAL_INPUT_LIMIT];
    for (offset, value) in [(2, 2), (FRAME_BYTES, 0x10), (FRAME_BYTES + 2, 2)] {
        *bytes
            .get_mut(offset)
            .ok_or("framed record fixture offset is missing")? = value;
    }
    let mut case = Case::new();
    mapped_tcp_run(&mut case, &bytes, b"framed record total input bytes")?;
    let schema = total_input_bytes_record_schema()?;
    let recipe = Recipe {
        steps: vec![Operation::HexEncode {
            case: HexCase::Lower,
        }],
        constraints: Vec::new(),
    };
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        framings: vec![FramingKind::FixedSize { bytes: FRAME_BYTES }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    execution_policy
        .resources
        .max_total_input_bytes_per_candidate = TOTAL_INPUT_LIMIT;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let batched_input_ids =
        total_input_limit_batch_inputs(&outcome.omissions, &schema, TOTAL_INPUT_LIMIT)?;

    let frame_ids = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .map(|node| node.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(frame_ids.len(), 2);

    let singleton_records = successful_total_input_record_candidates(
        &case,
        &outcome.candidates,
        &schema,
        &recipe,
        &frame_ids,
    );
    assert_eq!(singleton_records.len(), 2);
    assert_eq!(
        singleton_records
            .iter()
            .map(|(frame_id, _, _, _)| *frame_id)
            .collect::<BTreeSet<_>>(),
        frame_ids
    );
    assert_eq!(
        singleton_records
            .iter()
            .map(|(_, output_node_id, _, _)| *output_node_id)
            .collect::<BTreeSet<_>>(),
        batched_input_ids
    );

    assert_total_input_record_provenance(&case, &singleton_records, TOTAL_INPUT_LIMIT)?;
    Ok(())
}

fn total_input_bytes_record_schema() -> Result<l2_workbench::protocol::RecordSchema, Box<dyn Error>>
{
    Ok(serde_json::from_value(json!({
        "records_offset":2,
        "count":{"kind":"exact","records":1},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":3,"width":1,"byte_order":"big_endian"},
        "data_offset":4,
        "length_meaning":"whole_record",
        "sequence_base":48,
        "terminal_sequence":48
    }))?)
}

fn total_input_limit_batch_inputs(
    omissions: &[RecoveryOmission],
    schema: &l2_workbench::protocol::RecordSchema,
    limit: usize,
) -> Result<BTreeSet<u64>, Box<dyn Error>> {
    omissions
        .iter()
        .find_map(|omission| {
            let RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(selected),
                input_node_ids,
                resource: RecoveryResource::TotalInputBytes,
                limit: selected_limit,
                used,
                requested,
            } = omission
            else {
                return None;
            };
            (selected == schema
                && input_node_ids.len() == 2
                && *selected_limit == limit
                && *used == limit
                && *requested == limit)
                .then(|| input_node_ids.iter().copied().collect())
        })
        .ok_or_else(|| "batched total input limit omission is missing".into())
}

fn successful_total_input_record_candidates(
    case: &Case,
    candidates: &[RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
    recipe: &Recipe,
    frame_ids: &BTreeSet<u64>,
) -> Vec<(u64, u64, u64, u64)> {
    candidates
        .iter()
        .filter_map(|candidate| {
            if candidate.task() != &RecoveryTask::AssembleRecords(schema.clone())
                || candidate.inputs().len() != 1
            {
                return None;
            }
            let [output_node_id] = candidate.inputs().first()?.origin_node_ids() else {
                return None;
            };
            if !case
                .nodes()
                .iter()
                .any(|node| node.id == *output_node_id && node.kind == "decoding_output")
            {
                return None;
            }
            let transform_receipt = decoding_receipt_for_output(case, *output_node_id).ok()?;
            let transform = candidates.iter().find(|candidate| {
                candidate.task() == &RecoveryTask::Transform(recipe.clone())
                    && matches!(
                        candidate.state(),
                        RecoveryCandidateState::Finished {
                            result: RecoveryResult::Derived { evidence_node_id },
                            ..
                        } if *evidence_node_id == transform_receipt
                    )
            })?;
            let [source_frame_id] = transform.inputs().first()?.origin_node_ids() else {
                return None;
            };
            if !frame_ids.contains(source_frame_id) {
                return None;
            }
            let RecoveryCandidateState::Finished {
                result: RecoveryResult::Derived { evidence_node_id },
                ..
            } = candidate.state()
            else {
                return None;
            };
            Some((
                *source_frame_id,
                *output_node_id,
                transform_receipt,
                *evidence_node_id,
            ))
        })
        .collect()
}

fn assert_total_input_record_provenance(
    case: &Case,
    records: &[(u64, u64, u64, u64)],
    output_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    for (frame_id, output_node_id, transform_receipt_id, receipt_id) in records {
        let output_node = case
            .nodes()
            .iter()
            .find(|node| node.id == *output_node_id)
            .ok_or("singleton record input is missing")?;
        let output_blob_id = output_node
            .blob
            .as_deref()
            .ok_or("singleton record input bytes are missing")?;
        assert_eq!(
            case.blobs()
                .iter()
                .find(|blob| blob.id == output_blob_id)
                .map(|blob| blob.bytes.len()),
            Some(output_bytes),
        );
        let transform_origins = case
            .edges()
            .iter()
            .filter(|edge| {
                edge.from == *transform_receipt_id
                    && edge.relation == "decoding_result"
                    && edge.status == EvidenceStatus::Observed
            })
            .map(|edge| edge.to)
            .collect::<BTreeSet<_>>();
        assert_eq!(transform_origins, BTreeSet::from([*frame_id]));
        let receipt_origins = case
            .edges()
            .iter()
            .filter(|edge| {
                edge.from == *receipt_id
                    && edge.relation == "record_assembly"
                    && edge.status == EvidenceStatus::Observed
            })
            .map(|edge| edge.to)
            .collect::<BTreeSet<_>>();
        assert_eq!(receipt_origins, BTreeSet::from([*output_node_id]));
    }
    Ok(())
}

#[test]
fn record_batch_per_item_limit_keeps_valid_sibling() -> Result<(), Box<dyn Error>> {
    let bytes = [2, b'x', 5, b'a', b'b', b'c', b'd'];
    let mut case = Case::new();
    mapped_tcp_run(
        &mut case,
        &bytes,
        b"framed inputs with different encoded sizes",
    )?;
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":4,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":0,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":1,
        "length_meaning":"whole_record",
        "sequence_base":0,
        "terminal_sequence":null
    }))?;
    let recipe = Recipe {
        steps: vec![Operation::Base64Encode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let plan = RecoveryPlan {
        recipes: vec![recipe],
        framings: vec![FramingKind::LengthPrefix {
            offset: 0,
            width: 1,
            byte_order: l2_workbench::protocol::ByteOrder::BigEndian,
            meaning: l2_workbench::protocol::LengthMeaning::WholeMessage,
        }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    execution_policy.resources.max_input_bytes_per_item = bytes.len();

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && candidate.depth() == 2
            && candidate.inputs().len() == 1
            && candidate.inputs().first().is_some_and(|input| {
                case.blobs()
                    .iter()
                    .find(|blob| blob.id == input.blob_id())
                    .is_some_and(|blob| blob.bytes.len() == 4)
            })
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    assert!(has_singleton_item_limit_omission(
        &case,
        &outcome.omissions,
        &schema,
        bytes.len(),
        8,
    ));
    assert!(!outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && candidate.depth() == 2
            && candidate.inputs().len() > 1
    }));
    Ok(())
}

fn has_singleton_item_limit_omission(
    case: &Case,
    omissions: &[RecoveryOmission],
    schema: &l2_workbench::protocol::RecordSchema,
    limit: usize,
    requested: usize,
) -> bool {
    omissions.iter().any(|omission| {
        let RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::AssembleRecords(selected),
            input_node_ids,
            resource: RecoveryResource::InputBytesPerItem,
            limit: selected_limit,
            requested: selected_request,
            ..
        } = omission
        else {
            return false;
        };
        selected == schema
            && input_node_ids.len() == 1
            && *selected_limit == limit
            && *selected_request == requested
            && input_node_ids.first().is_some_and(|input_node_id| {
                case.nodes()
                    .iter()
                    .find(|node| node.id == *input_node_id)
                    .and_then(|node| node.blob.as_deref())
                    .and_then(|blob_id| case.blobs().iter().find(|blob| blob.id == blob_id))
                    .is_some_and(|blob| {
                        blob.bytes.len() == *selected_request && blob.bytes.len() > *selected_limit
                    })
            })
    })
}

#[test]
fn framed_transform_batch_respects_candidate_budget() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    mapped_tcp_run(&mut case, b"AA==AA==", b"capture with framed base64")?;
    let recipe = Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":0,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":1,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":0
    }))?;
    let plan = RecoveryPlan {
        recipes: vec![recipe],
        framings: vec![FramingKind::FixedSize { bytes: 4 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_candidates = 16;
    execution_policy.resources.max_frontier = 16;
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let batch = outcome.candidates.iter().find(|candidate| {
        candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
            && candidate.inputs().len() == 2
            && candidate.inputs().iter().all(|input| {
                input.origin_node_ids().first().is_some_and(|origin| {
                    case.nodes()
                        .iter()
                        .find(|node| node.id == *origin)
                        .is_some_and(|node| node.kind == "decoding_output")
                })
            })
    });
    assert!(matches!(
        batch.map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { .. },
            ..
        })
    ));
    assert!(outcome.candidate_count <= 16);
    Ok(())
}

#[test]
fn framed_transform_keeps_successful_sibling() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    mapped_tcp_run(
        &mut case,
        b"!!!!!!!!AQABeA==",
        b"capture with mixed transform siblings",
    )?;
    let recipe = Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":1,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":0
    }))?;
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let good_frame_blob = blob_id(b"AQABeA==");
    let good_frame = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_frame"
                && node.blob.as_deref() == Some(good_frame_blob.as_str())
        })
        .ok_or("valid base64 frame is missing")?;
    let (evidence_node_id, decoded) =
        successful_frame_transform(&case, &outcome.candidates, &recipe, good_frame.id)?;
    let bad_frame_blob = blob_id(b"!!!!!!!!");
    let bad_frame = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_frame"
                && node.blob.as_deref() == Some(bad_frame_blob.as_str())
        })
        .ok_or("invalid base64 frame is missing")?;
    assert_bad_frame_excluded(&outcome.omissions, &recipe, bad_frame.id);
    assert_transformed_record_batch(&outcome.candidates, &schema, decoded)?;
    assert_record_object_bytes(&case, b"x")?;
    assert_transform_has_no_sibling_frame_link(&case, evidence_node_id, good_frame.id);
    Ok(())
}

fn successful_frame_transform(
    case: &Case,
    candidates: &[RecoveryCandidate],
    recipe: &Recipe,
    frame_id: u64,
) -> Result<(u64, u64), Box<dyn Error>> {
    let transform = candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::Transform(recipe.clone())
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids().contains(&frame_id))
        })
        .ok_or("valid frame transform is missing")?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived { evidence_node_id },
        ..
    } = transform.state()
    else {
        return Err("valid frame transform did not succeed".into());
    };
    let decoded = case
        .edges()
        .iter()
        .find(|edge| edge.from == *evidence_node_id && edge.relation == "produced")
        .map(|edge| edge.to)
        .ok_or("valid frame transform output is missing")?;
    assert!(case.edges().iter().any(|edge| {
        edge.from == decoded && edge.to == *evidence_node_id && edge.relation == "derived_from"
    }));
    Ok((*evidence_node_id, decoded))
}

fn assert_bad_frame_excluded(omissions: &[RecoveryOmission], recipe: &Recipe, frame_id: u64) {
    assert!(omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::SiblingTransformExcluded {
                input_node_id,
                task: RecoveryTask::Transform(selected),
                result: RecoveryResult::Rejected { .. },
                ..
            } if selected == recipe && *input_node_id == frame_id
        )
    }));
}

fn assert_transformed_record_batch(
    candidates: &[RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
    decoded: u64,
) -> Result<(), Box<dyn Error>> {
    let batch = candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 1
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids() == [decoded])
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .ok_or("the valid decoded sibling did not reach record assembly")?;
    assert_eq!(
        batch
            .inputs()
            .first()
            .ok_or("record batch input is missing")?
            .origin_node_ids(),
        &[decoded]
    );
    Ok(())
}

fn assert_record_object_bytes(case: &Case, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let object = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_object")
        .ok_or("successful sibling record was not assembled")?;
    let object_blob = object
        .blob
        .as_deref()
        .ok_or("record object blob is missing")?;
    let object_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == object_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record object bytes are missing")?;
    assert_eq!(object_bytes, expected);
    Ok(())
}

fn assert_transform_has_no_sibling_frame_link(case: &Case, receipt_id: u64, frame_id: u64) {
    assert!(!case.edges().iter().any(|edge| {
        edge.from == receipt_id
            && case.nodes().iter().any(|node| {
                node.id == edge.to && node.kind == "custom_protocol_frame" && node.id != frame_id
            })
    }));
}

#[test]
fn record_batch_excludes_malformed_sibling() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    mapped_tcp_run(
        &mut case,
        b"4142434401000178",
        b"capture with malformed record sibling",
    )?;
    let recipe = hex_recipe();
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":1,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":0
    }))?;
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let bad_output = malformed_frame_output(&case, &outcome.candidates, &recipe)?;
    assert_malformed_record_batch(
        &case,
        &outcome.candidates,
        &outcome.omissions,
        &schema,
        bad_output,
    )?;
    Ok(())
}

fn malformed_frame_output(
    case: &Case,
    candidates: &[RecoveryCandidate],
    recipe: &Recipe,
) -> Result<u64, Box<dyn Error>> {
    let bad_frame_blob = blob_id(b"41424344");
    let bad_frame = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_frame"
                && node.blob.as_deref() == Some(bad_frame_blob.as_str())
        })
        .ok_or("malformed record frame is missing")?;
    let bad_transform = candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::Transform(recipe.clone())
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids().contains(&bad_frame.id))
        })
        .ok_or("malformed record frame transform is missing")?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived { evidence_node_id },
        ..
    } = bad_transform.state()
    else {
        return Err("malformed record frame did not transform successfully".into());
    };
    case.edges()
        .iter()
        .find(|edge| edge.from == *evidence_node_id && edge.relation == "produced")
        .map(|edge| edge.to)
        .ok_or_else(|| "malformed record frame output is missing".into())
}

fn assert_malformed_record_batch(
    case: &Case,
    candidates: &[RecoveryCandidate],
    omissions: &[RecoveryOmission],
    schema: &l2_workbench::protocol::RecordSchema,
    bad_output: u64,
) -> Result<(), Box<dyn Error>> {
    let batch = candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 2
                && candidate
                    .inputs()
                    .first()
                    .is_some_and(|input| input.origin_node_ids() == [bad_output])
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .ok_or("valid record sibling was not assembled")?;
    assert!(omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::RecordInputRejected {
                input_index: 0,
                input_node_id,
                error: l2_workbench::protocol::RecordError::TruncatedRecord { .. }
            } if *input_node_id == bad_output
        )
    }));
    let evidence_node_id = record_batch_receipt(batch)?;
    let receipt_report = record_receipt_report(case, evidence_node_id)?;
    assert_eq!(
        receipt_report
            .get("assembly_complete")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_partial_record_candidate(case, batch, evidence_node_id, bad_output)?;
    assert_receipt_input_map(case, evidence_node_id, 0, 1)?;
    Ok(())
}

fn record_batch_receipt(batch: &RecoveryCandidate) -> Result<u64, Box<dyn Error>> {
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived { evidence_node_id },
        ..
    } = batch.state()
    else {
        return Err("record batch did not retain a derivation receipt".into());
    };
    Ok(*evidence_node_id)
}

fn record_receipt_report(
    case: &Case,
    receipt_node_id: u64,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.id == receipt_node_id)
        .ok_or("record receipt node is missing")?;
    let receipt_blob = receipt
        .blob
        .as_deref()
        .ok_or("record receipt blob is missing")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record receipt bytes are missing")?;
    Ok(serde_json::from_slice(receipt_bytes)?)
}

fn assert_partial_record_candidate(
    case: &Case,
    batch: &RecoveryCandidate,
    receipt_node_id: u64,
    bad_output: u64,
) -> Result<(), Box<dyn Error>> {
    let record_candidate = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "record_candidate"
                && node
                    .details
                    .get("receipt_node")
                    .and_then(serde_json::Value::as_u64)
                    == Some(receipt_node_id)
        })
        .ok_or("valid sibling candidate bytes were not retained")?;
    assert_eq!(
        record_candidate
            .details
            .get("group_complete")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let good_output = batch
        .inputs()
        .get(1)
        .and_then(|input| input.origin_node_ids().first())
        .copied()
        .ok_or("valid sibling input node is missing")?;
    assert!(case.edges().iter().any(|edge| {
        edge.from == good_output
            && edge.to == record_candidate.id
            && edge.relation == "candidate_from"
    }));
    assert!(!case.edges().iter().any(|edge| {
        edge.from == bad_output
            && edge.to == record_candidate.id
            && edge.relation == "candidate_from"
    }));
    let candidate_blob = record_candidate
        .blob
        .as_deref()
        .ok_or("record candidate blob is missing")?;
    let candidate_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == candidate_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record candidate bytes are missing")?;
    assert_eq!(candidate_bytes, b"x");
    Ok(())
}

#[test]
fn partial_receipt_maps_original_input_slots() -> Result<(), Box<dyn Error>> {
    for (source_bytes, rejected_index, assembly_input_index) in [
        (b"4142434401000178".as_slice(), 0_usize, 1_usize),
        (b"0100017841424344".as_slice(), 1_usize, 0_usize),
    ] {
        let mut case = Case::new();
        mapped_tcp_run(&mut case, source_bytes, b"ordered record receipt mapping")?;
        let recipe = hex_recipe();
        let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
            "records_offset":0,
            "count":{"kind":"until_end"},
            "identifier":{"offset":1,"width":1},
            "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
            "length":{"offset":0,"width":1,"byte_order":"big_endian"},
            "data_offset":3,
            "length_meaning":"payload_bytes",
            "sequence_base":0,
            "terminal_sequence":0
        }))?;
        let plan = RecoveryPlan {
            recipes: vec![recipe],
            framings: vec![FramingKind::FixedSize { bytes: 8 }],
            record_schemas: vec![schema.clone()],
            discover_transforms: false,
            discover_framing: false,
            discover_records: false,
        };
        let mut execution_policy = policy();
        execution_policy.resources.max_inputs_per_candidate = 2;
        let outcome = execute(&mut case, &plan, &execution_policy)?;
        let batch = outcome
            .candidates
            .iter()
            .find(|candidate| {
                candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                    && candidate.inputs().len() == 2
                    && matches!(
                        candidate.state(),
                        RecoveryCandidateState::Finished {
                            result: RecoveryResult::Derived { .. },
                            ..
                        }
                    )
            })
            .ok_or("partial record batch is missing")?;
        let RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        } = batch.state()
        else {
            return Err("partial record batch has no derivation receipt".into());
        };
        assert_receipt_input_map(
            &case,
            *evidence_node_id,
            rejected_index,
            assembly_input_index,
        )?;
    }
    Ok(())
}

fn assert_receipt_input_map(
    case: &Case,
    receipt_node_id: u64,
    rejected_index: usize,
    assembly_input_index: usize,
) -> Result<(), Box<dyn Error>> {
    let report = record_receipt_report(case, receipt_node_id)?;
    let part_index = report
        .pointer("/assembly/groups/0/parts/0/input_index")
        .and_then(serde_json::Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or("assembly part source index is missing")?;
    let mapped_index = report
        .get("assembly_input_indexes")
        .and_then(serde_json::Value::as_array)
        .and_then(|indexes| indexes.get(part_index))
        .and_then(serde_json::Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or("assembly input map is missing")?;
    assert_eq!(mapped_index, assembly_input_index);
    let mapped_node = report
        .get("inputs")
        .and_then(serde_json::Value::as_array)
        .and_then(|inputs| inputs.get(mapped_index))
        .and_then(|input| input.get("input_node"))
        .and_then(serde_json::Value::as_u64)
        .ok_or("assembly input node is missing")?;
    let rejected = report
        .get("inputs")
        .and_then(serde_json::Value::as_array)
        .and_then(|inputs| inputs.get(rejected_index))
        .ok_or("rejected input receipt is missing")?;
    let rejected_node = rejected
        .get("input_node")
        .and_then(serde_json::Value::as_u64)
        .ok_or("rejected input node is missing")?;
    assert!(rejected.get("parse_error").is_some());
    assert_receipt_input_edges(case, receipt_node_id, mapped_node, rejected_node);
    Ok(())
}

fn assert_receipt_input_edges(
    case: &Case,
    receipt_node_id: u64,
    mapped_node: u64,
    rejected_node: u64,
) {
    assert!(case.edges().iter().any(|edge| {
        edge.from == mapped_node
            && edge.to == receipt_node_id
            && edge.relation == "parsed_by"
            && edge.status == EvidenceStatus::Observed
    }));
    assert!(case.edges().iter().any(|edge| {
        edge.from == rejected_node
            && edge.to == receipt_node_id
            && edge.relation == "record_parse_rejected"
            && edge.status == EvidenceStatus::ConstraintFailed
    }));
    assert!(case.edges().iter().any(|edge| {
        edge.from == mapped_node
            && edge.relation == "candidate_from"
            && case.nodes().iter().any(|node| {
                node.id == edge.to
                    && node.kind == "record_candidate"
                    && node
                        .details
                        .get("receipt_node")
                        .and_then(serde_json::Value::as_u64)
                        == Some(receipt_node_id)
            })
    }));
    assert!(!case.edges().iter().any(|edge| {
        edge.from == rejected_node
            && edge.relation == "candidate_from"
            && case.nodes().iter().any(|node| {
                node.id == edge.to
                    && node.kind == "record_candidate"
                    && node
                        .details
                        .get("receipt_node")
                        .and_then(serde_json::Value::as_u64)
                        == Some(receipt_node_id)
            })
    }));
}

#[test]
fn framing_sessions_keep_record_batches_separate() -> Result<(), Box<dyn Error>> {
    let bytes = b"0100017801010179";
    let mut case = Case::new();
    mapped_tcp_run(&mut case, bytes, b"first capture session")?;
    mapped_tcp_run(&mut case, bytes, b"second capture session")?;
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":2,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":1
    }))?;
    let plan = RecoveryPlan {
        recipes: vec![hex_recipe()],
        framings: vec![FramingKind::FixedSize { bytes: 8 }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let batches = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 2
                && candidate.inputs().iter().all(|input| {
                    input.origin_node_ids().iter().all(|origin| {
                        case.nodes()
                            .iter()
                            .find(|node| node.id == *origin)
                            .is_some_and(|node| {
                                node.kind == "decoding_output"
                                    && node.details.get("source_input_node").is_some()
                            })
                    })
                })
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        })
        .collect::<Vec<_>>();
    assert_distinct_framing_sessions(&case, &batches)?;
    Ok(())
}

fn assert_distinct_framing_sessions(
    case: &Case,
    batches: &[&RecoveryCandidate],
) -> Result<(), Box<dyn Error>> {
    assert_eq!(batches.len(), 2);
    let first_batch = batches.first().ok_or("first record batch is missing")?;
    let second_batch = batches.get(1).ok_or("second record batch is missing")?;
    let first_batch_inputs = first_batch
        .inputs()
        .iter()
        .map(|input| {
            input
                .origin_node_ids()
                .first()
                .copied()
                .ok_or("first batch input origin is missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let second_batch_inputs = second_batch
        .inputs()
        .iter()
        .map(|input| {
            input
                .origin_node_ids()
                .first()
                .copied()
                .ok_or("second batch input origin is missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_ne!(first_batch_inputs, second_batch_inputs);
    assert!(batches.iter().all(|batch| {
        batch
            .inputs()
            .iter()
            .all(|input| input.origin_node_ids().len() == 1)
    }));
    let session_receipts = batches
        .iter()
        .map(|batch| {
            batch
                .inputs()
                .iter()
                .map(|input| {
                    input
                        .origin_node_ids()
                        .first()
                        .and_then(|view_id| framing_receipt_for_view(case, *view_id))
                })
                .collect::<Option<Vec<_>>>()
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("a transformed view lost its framing parent")?;
    let first_session = session_receipts.first().ok_or("first session is missing")?;
    let second_session = session_receipts.get(1).ok_or("second session is missing")?;
    let first_receipt = first_session
        .first()
        .ok_or("first framing receipt is missing")?;
    let second_receipt = second_session
        .first()
        .ok_or("second framing receipt is missing")?;
    assert!(first_session.iter().all(|receipt| receipt == first_receipt));
    assert!(
        second_session
            .iter()
            .all(|receipt| receipt == second_receipt)
    );
    assert_ne!(first_receipt, second_receipt);
    Ok(())
}

#[test]
fn shared_transform_keeps_unframed_record_path() -> Result<(), Box<dyn Error>> {
    let record = [1_u8, 0, 0, b'x'];
    let intermediate = hex_encode(&record)?;
    let doubly_encoded = hex_encode(intermediate.as_bytes())?;
    let mut case = Case::new();
    source(&mut case, "imported_source", doubly_encoded.as_bytes())?;
    mapped_tcp_run(
        &mut case,
        intermediate.as_bytes(),
        b"capture with same bytes as derived source",
    )?;
    let recipe = hex_recipe();
    let schema: l2_workbench::protocol::RecordSchema = serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":1,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":0,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":0
    }))?;
    let plan = RecoveryPlan {
        recipes: vec![recipe],
        framings: vec![FramingKind::FixedSize {
            bytes: intermediate.len(),
        }],
        record_schemas: vec![schema.clone()],
        discover_transforms: false,
        discover_framing: false,
        discover_records: false,
    };
    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    assert_shared_transform_paths(&case, &outcome.candidates, &schema);
    Ok(())
}

fn assert_shared_transform_paths(
    case: &Case,
    candidates: &[RecoveryCandidate],
    schema: &l2_workbench::protocol::RecordSchema,
) {
    let contextual_views = case
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "decoding_output" && node.details.get("shared_transform_receipt").is_some()
        })
        .collect::<Vec<_>>();
    assert_eq!(contextual_views.len(), 2);
    assert!(contextual_views.iter().all(|view| {
        view.details
            .get("source_input_node")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|source_id| case.nodes().iter().any(|node| node.id == source_id))
    }));
    let mut batched_paths = candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::AssembleRecords(schema.clone())
                && candidate.inputs().len() == 1
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
                && candidate.inputs().first().is_some_and(|input| {
                    input
                        .origin_node_ids()
                        .iter()
                        .any(|origin| contextual_views.iter().any(|view| view.id == *origin))
                })
        })
        .filter_map(|candidate| {
            candidate
                .inputs()
                .first()
                .and_then(|input| input.origin_node_ids().first())
                .copied()
        })
        .collect::<Vec<_>>();
    batched_paths.sort_unstable();
    assert_eq!(
        batched_paths,
        contextual_views
            .iter()
            .map(|view| view.id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn output_budget_stays_terminal() -> Result<(), Box<dyn Error>> {
    let inner = png(&[])?;
    let outer = png(&[(*b"tEXt", inner.as_slice())])?;
    let mut case = Case::new();
    let input = source(&mut case, "http_body", &outer)?;
    let mut limited = policy();
    limited.resources.max_input_bytes_per_item = outer.len();
    limited.resources.max_total_input_bytes_per_candidate = outer.len();
    limited.resources.max_output_bytes = inner
        .len()
        .checked_sub(1)
        .ok_or("nested PNG fixture is empty")?;
    limited.decode_batch_limits.total_output_bytes = outer.len();
    limited.record_limits.max_output_bytes =
        limited.record_limits.max_output_bytes.min(outer.len());
    limited.expansion_limits.retained_bytes = outer.len();
    limited.expansion_limits.objects = 1;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::EmbeddedDiscovery
            && candidate
                .inputs()
                .first()
                .is_some_and(|position| position.origin_node_ids().contains(&input))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ResourceExhausted {
                        resource: RecoveryResource::OutputBytes,
                        ..
                    },
                    ..
                }
            )
    }));
    assert!(
        case.nodes()
            .iter()
            .all(|node| node.kind != "embedded_artifact")
    );
    Ok(())
}

#[test]
fn framing_budget_precedes_commit() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source_id = case.add_source(
        "synthetic.pcap",
        "capture",
        4,
        &l2_workbench::sha256(b"framing input"),
        None,
    )?;
    let mapping = ByteMapping {
        offset: 0,
        range: SourceRange {
            source: source_id,
            packet: Some(1),
            offset: 0,
            length: 4,
        },
    };
    let input_node = case.add_mapped_bytes_node("tcp_byte_run", b"abcd", &[mapping], json!({}))?;
    let mut limited = policy();
    limited.resources.max_output_bytes = 1;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 2 }],
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &limited)?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 })
            && candidate
                .inputs()
                .first()
                .is_some_and(|position| position.origin_node_ids().contains(&input_node))
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::ResourceExhausted {
                        resource: RecoveryResource::OutputBytes,
                        ..
                    },
                    ..
                }
            )
    }));
    assert_eq!(
        case.nodes()
            .iter()
            .filter(|node| {
                node.kind == "custom_protocol_frame" || node.kind == "custom_protocol_framing_tail"
            })
            .count(),
        0
    );
    Ok(())
}

#[test]
fn expanded_work_uses_shared_budget() -> Result<(), Box<dyn Error>> {
    let compressed = hex_bytes(
        "1f8b08000000000002ffedc1010d000000c2a06cef5fca1e0e28000000e0dd004034a6fe00100000",
    )?;
    let mut case = Case::new();
    source(&mut case, "imported_source", &compressed)?;
    let recipe = Recipe {
        steps: vec![Operation::GzipDecompress {}],
        constraints: Vec::new(),
    };
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        ..RecoveryPlan::default()
    };
    let mut limited = policy();
    limited.resources.max_work_bytes = compressed.len().saturating_add(10);

    let outcome = execute(&mut case, &plan, &limited)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::Transform(selected),
                resource: RecoveryResource::WorkBytes,
                ..
            } if selected == &recipe
        )
    }));
    assert!(!outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::Transform(recipe.clone())
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { .. },
                    ..
                }
            )
    }));
    Ok(())
}

#[test]
fn embedded_parser_work_is_shared() -> Result<(), Box<dyn Error>> {
    let object = png(&[])?;
    let mut input = object.clone();
    input.extend_from_slice(&object);
    input.extend_from_slice(&object);
    let mut case = Case::new();
    source(&mut case, "http_body", &input)?;
    let mut limited = policy();
    limited.resources.max_work_bytes = input.len().saturating_mul(2);

    let outcome = execute(&mut case, &RecoveryPlan::default(), &limited)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::EmbeddedDiscovery {
                omissions,
                ..
            } if omissions.unvalidated_candidate_count == 2
        )
    }));
    assert_eq!(
        case.nodes()
            .iter()
            .filter(|node| node.kind == "embedded_artifact")
            .count(),
        1
    );
    assert_eq!(outcome.validated_artifact_count, 0);
    Ok(())
}

#[test]
fn embedded_receipt_details_stay_bounded() -> Result<(), Box<dyn Error>> {
    let mut input = Vec::new();
    for _ in 0..64 {
        input.extend_from_slice(&l2_workbench::artifact::PNG_SIGNATURE);
        input.extend_from_slice(b"invalid marker");
    }
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", &input)?;

    let outcome = execute(&mut case, &RecoveryPlan::default(), &policy())?;

    assert!(outcome.candidates.iter().any(|candidate| {
        candidate.task() == &RecoveryTask::EmbeddedDiscovery
            && matches!(
                candidate.state(),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Rejected { .. },
                    ..
                }
            )
    }));
    let receipt = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "embedded_discovery_receipt"
                && node
                    .details
                    .get("input_node")
                    .and_then(serde_json::Value::as_u64)
                    == Some(input_node)
        })
        .ok_or("embedded receipt is missing")?;
    assert!(serde_json::to_vec(&receipt.details)?.len() <= MAX_NODE_DETAILS_BYTES);
    assert!(receipt.details.get("candidates").is_none());
    let receipt_blob = receipt.blob.as_deref().ok_or("receipt blob is missing")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("receipt bytes are missing")?;
    let receipt_hash = l2_workbench::sha256(receipt_bytes);
    assert_eq!(
        receipt
            .details
            .get("report_sha256")
            .and_then(serde_json::Value::as_str),
        Some(receipt_hash.as_str())
    );
    let full_report: serde_json::Value = serde_json::from_slice(receipt_bytes)?;
    assert_eq!(
        full_report
            .get("candidates")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(64)
    );
    Ok(())
}

#[test]
fn candidate_budget_omission() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    source(&mut case, "imported_source", b"candidate")?;
    let mut limited = policy();
    limited.resources.max_candidates = 1;

    let outcome = execute(&mut case, &hex_plan(), &limited)?;

    assert!(outcome.omissions.iter().any(|omission| {
        matches!(
            omission,
            RecoveryOmission::ResourceExhausted {
                resource: RecoveryResource::CandidateCount,
                ..
            }
        )
    }));
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn finish_rolls_back_partial_context_links_at_edge_quota() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_origin = source(&mut case, "http_body", b"first origin")?;
    let second_origin = source(&mut case, "udp_payload", b"second origin")?;
    let receipt = case.add_bytes_node(
        "recovery_test_receipt",
        b"operation receipt",
        Vec::new(),
        json!({}),
    )?;
    fill_edges_to_quota(&mut case, first_origin, MAX_EDGES - 1)?;

    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id = queued(coordinator.enqueue_nodes(
        &case,
        &[first_origin, second_origin],
        RecoveryTask::StructuralValidation,
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.finish(
        candidate_id,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    );

    assert!(result.is_err(), "the second context link exceeds MAX_EDGES");
    assert!(
        *executor.case == before,
        "no partial context link is retained (edges: {} vs {})",
        executor.case.edges().len(),
        before.edges().len()
    );
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Running(
            RecoveryStage::StructuralValidation
        )),
        "a failed evidence commit leaves the candidate running"
    );
    Ok(())
}

#[test]
fn late_context_link_batch_rolls_back_at_edge_quota() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_origin = source(&mut case, "http_body", b"shared context")?;
    let second_origin = source(&mut case, "udp_payload", b"shared context")?;
    let third_origin = source(&mut case, "ftp_data_candidate", b"shared context")?;
    fill_edges_to_quota(&mut case, first_origin, MAX_EDGES - 2)?;

    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let task = RecoveryTask::Transform(hex_recipe());
    let candidate_id = queued(coordinator.enqueue(&case, first_origin, task.clone())?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    finish_derived(&mut case, &mut coordinator, candidate_id, first_origin)?;
    assert_eq!(case.edges().len(), MAX_EDGES - 1);

    let second_merge = coordinator.enqueue(&case, second_origin, task.clone())?;
    let third_merge = coordinator.enqueue(&case, third_origin, task.clone())?;
    assert!(matches!(
        &second_merge,
        l2_workbench::recovery::EnqueueOutcome::MergedNeedsContext(id) if *id == candidate_id
    ));
    assert!(matches!(
        &third_merge,
        l2_workbench::recovery::EnqueueOutcome::MergedNeedsContext(id) if *id == candidate_id
    ));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.record_enqueue(third_merge, &task, &[third_origin]);

    assert!(
        result.is_err(),
        "the second late context link exceeds MAX_EDGES"
    );
    assert!(
        *executor.case == before,
        "the first late context link is rolled back with the failing link"
    );
    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or("the merged context candidate is missing")?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::ContextPending { .. }
    ));
    assert_eq!(
        candidate
            .pending_origin_node_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([second_origin, third_origin]),
        "a failed context link batch does not mark late origins complete"
    );
    Ok(())
}

#[test]
fn validation_receipt_and_links_roll_back_at_edge_quota() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_origin = source(&mut case, "http_body", b"first validation input")?;
    let second_origin = source(&mut case, "udp_payload", b"second validation input")?;
    fill_edges_to_quota(&mut case, first_origin, MAX_EDGES - 1)?;

    let mut execution_policy = policy();
    execution_policy.resources.max_inputs_per_candidate = 2;
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id = queued(coordinator.enqueue_nodes(
        &case,
        &[first_origin, second_origin],
        RecoveryTask::StructuralValidation,
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.run_validation(
        candidate_id,
        &[first_origin, second_origin],
        first_origin,
        b"first validation input".len(),
        ValidationDecision::Rejected {
            format: l2_workbench::artifact::ArtifactValidationFormat::Png,
            input_range: l2_workbench::artifact::FileRange {
                offset: 0,
                length: b"first validation input".len(),
            },
            reason: "injected rejection for transactional commit coverage".to_owned(),
        },
    );

    assert!(
        result.is_err(),
        "the second validation link exceeds MAX_EDGES"
    );
    assert!(
        *executor.case == before,
        "validation receipt and first link are rolled back together"
    );
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Running(
            RecoveryStage::StructuralValidation
        )),
        "failed validation evidence cannot finish the candidate"
    );
    Ok(())
}

#[test]
fn automatic_recovery_stops_cleanly_when_the_evidence_graph_is_full() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"not a recognized file")?;
    fill_edges_to_quota(&mut case, input_node, MAX_EDGES)?;
    let nodes_before = case.nodes().len();
    let plan = RecoveryPlan::default();

    let outcome = execute(&mut case, &plan, &policy())?;

    assert_eq!(case.edges().len(), MAX_EDGES);
    assert_eq!(case.nodes().len(), nodes_before);
    assert_eq!(
        outcome
            .omissions
            .iter()
            .filter(|omission| matches!(
                omission,
                RecoveryOmission::ResourceExhausted {
                    resource: RecoveryResource::EvidenceEdges,
                    ..
                }
            ))
            .count(),
        1,
        "one capture-wide omission explains the terminal graph limit"
    );
    assert!(outcome.candidates.iter().all(|candidate| matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceEdges,
                limit: MAX_EDGES,
                used: MAX_EDGES,
                requested: 1,
            },
            ..
        }
    )));
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn embedded_receipt_children_and_finish_roll_back_at_edge_quota() -> Result<(), Box<dyn Error>> {
    let object = tiny_png()?;
    let mut containing_bytes = b"prefix".to_vec();
    containing_bytes.extend_from_slice(&object);
    let mut case = Case::new();
    let first_origin = source(&mut case, "http_body", &containing_bytes)?;
    let second_origin = source(&mut case, "udp_payload", &containing_bytes)?;
    fill_edges_to_quota(&mut case, first_origin, MAX_EDGES - 5)?;

    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, first_origin, RecoveryTask::EmbeddedDiscovery)?)?;
    assert_eq!(
        coordinator.enqueue(&case, second_origin, RecoveryTask::EmbeddedDiscovery)?,
        l2_workbench::recovery::EnqueueOutcome::Merged(candidate_id)
    );
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.run_embedded(candidate_id, &[first_origin, second_origin]);

    assert!(
        result.is_ok(),
        "an automatic evidence edge quota must finish as a typed omission: {result:?}"
    );
    assert!(
        *executor.case == before,
        "the receipt, child node, and earlier links are rolled back together"
    );
    assert!(executor.case.nodes().iter().all(|node| {
        node.kind != "embedded_discovery_receipt" && node.kind != "embedded_artifact"
    }));
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::EmbeddedDiscovery,
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceEdges,
                limit: MAX_EDGES,
                used: MAX_EDGES - 5,
                requested: 1,
            },
        }),
        "the candidate records why its speculative evidence was omitted"
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::EmbeddedDiscovery,
            input_node_ids,
            resource: RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used,
            requested: 1,
        } if input_node_ids == &[first_origin, second_origin] && *used == MAX_EDGES - 5
    )));
    Ok(())
}

#[test]
fn framing_edge_quota_is_recorded_as_a_typed_omission() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = mapped_tcp_run(&mut case, b"abcd", b"framing edge quota capture")?;
    fill_edges_to_quota(&mut case, input_node, MAX_EDGES - 6)?;

    let rule = FramingKind::FixedSize { bytes: 2 };
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id = queued(coordinator.enqueue(
        &case,
        input_node,
        RecoveryTask::MaterializeFraming(rule.clone()),
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.run_framing(
        candidate_id,
        input_node,
        &[input_node],
        &rule,
        FramingSelectionBasis::CallerSupplied {},
    );

    assert!(
        result.is_ok(),
        "edge quota must become a typed omission: {result:?}"
    );
    assert!(
        *executor.case == before,
        "receipt, frame nodes, limitation, and links roll back together"
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 }),
            input_node_ids,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used: MAX_EDGES,
            requested: 1,
        } if input_node_ids == &[input_node]
    )));
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::MaterializeFraming,
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
                limit: MAX_EDGES,
                used: MAX_EDGES,
                requested: 1,
            },
        }),
        "the candidate records its exact Case edge quota failure"
    );
    Ok(())
}

#[test]
fn framing_node_quota_is_recorded_as_a_typed_omission() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = mapped_tcp_run(&mut case, b"abcd", b"framing node quota capture")?;
    while case.nodes().len() < MAX_NODES {
        case.add_node("quota_filler", None, Vec::new(), json!({}))?;
    }

    let rule = FramingKind::FixedSize { bytes: 2 };
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id = queued(coordinator.enqueue(
        &case,
        input_node,
        RecoveryTask::MaterializeFraming(rule.clone()),
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.run_framing(
        candidate_id,
        input_node,
        &[input_node],
        &rule,
        FramingSelectionBasis::CallerSupplied {},
    );

    assert!(
        result.is_ok(),
        "node quota must become a typed omission: {result:?}"
    );
    assert!(*executor.case == before, "failed frame evidence rolls back");
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 }),
            input_node_ids,
            resource: RecoveryResource::EvidenceNodes,
            limit: MAX_NODES,
            used: MAX_NODES,
            requested: 1,
        } if input_node_ids == &[input_node]
    )));
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::MaterializeFraming,
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceNodes,
                limit: MAX_NODES,
                used: MAX_NODES,
                requested: 1,
            },
        })
    );
    Ok(())
}

#[test]
fn transform_receipt_and_output_roll_back_when_final_link_hits_edge_quota()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"4142")?;
    let proposal_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"proposal report",
        Vec::new(),
        json!({}),
    )?;
    fill_edges_to_quota(&mut case, input_node, MAX_EDGES - 4)?;

    let recipe = hex_recipe();
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe.clone()))?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        ..RecoveryPlan::default()
    };
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let mut proposal_receipts = super::discovery::OrderedProposalReceipts::default();
    proposal_receipts.try_insert(proposal_report)?;
    executor
        .transform_proposal_receipts
        .insert(candidate_id, proposal_receipts);
    let before = executor.case.clone();

    let result = executor.run_transform(candidate_id, input_node, &recipe);

    assert!(
        result.is_err(),
        "an exact caller-selected transform remains fatal even when the same recipe was proposed"
    );
    assert!(
        *executor.case == before,
        "decode receipt, output node, limitation, and earlier links roll back together"
    );
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Running(RecoveryStage::Transform)),
        "failed transform evidence cannot finish the candidate"
    );
    Ok(())
}

#[test]
fn transform_case_quota_classifier_leaves_invariant_and_io_failures_unmapped() {
    let io_failure = RecoveryExecutionError::Operational {
        stage: RecoveryStage::Transform,
        source: Box::new(std::io::Error::other("fixture write failure")),
    };
    let invariant_failure = RecoveryExecutionError::Coordinator(RecoveryError::InvariantFailure);
    let unsupported_quota = RecoveryExecutionError::Evidence(EvidenceError::QuotaExceeded {
        field: "node source ranges",
        maximum: l2_workbench::evidence::MAX_NODE_RANGES,
    });
    let wrapped_node_quota = RecoveryExecutionError::Operational {
        stage: RecoveryStage::Transform,
        source: Box::new(EvidenceError::QuotaExceeded {
            field: "nodes",
            maximum: MAX_NODES,
        }),
    };

    let case = Case::new();
    assert_eq!(
        super::transform::transform_case_quota(&case, &io_failure),
        None
    );
    assert_eq!(
        super::transform::transform_case_quota(&case, &invariant_failure),
        None
    );
    assert_eq!(
        super::transform::transform_case_quota(&case, &unsupported_quota),
        None
    );
    assert_eq!(
        super::transform::transform_case_quota(&case, &wrapped_node_quota),
        Some((RecoveryResource::EvidenceNodes, MAX_NODES, 0))
    );
}

#[test]
fn speculative_transform_edge_quota_is_typed_and_later_candidate_completes()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"4142")?;
    let later_input_node = source(&mut case, "http_body", b"41")?;
    let proposal_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"proposal report",
        Vec::new(),
        json!({}),
    )?;
    fill_edges_to_quota(&mut case, input_node, MAX_EDGES - 4)?;

    let recipe = hex_recipe();
    let later_recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: vec![Constraint::Length { bytes: 2 }],
    };
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe.clone()))?)?;
    let later_candidate_id = queued(coordinator.enqueue(
        &case,
        later_input_node,
        RecoveryTask::Transform(later_recipe.clone()),
    )?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));

    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let mut proposal_receipts = super::discovery::OrderedProposalReceipts::default();
    proposal_receipts.try_insert(proposal_report)?;
    executor
        .transform_proposal_receipts
        .insert(candidate_id, proposal_receipts);
    let before = executor.case.clone();

    let result = executor.run_transform(candidate_id, input_node, &recipe);

    assert!(
        result.is_ok(),
        "a speculative transform edge quota must be recorded as an omission: {result:?}"
    );
    assert_eq!(
        *executor.case, before,
        "the receipt, output, and partial edge fanout roll back together"
    );
    assert_speculative_transform_quota(
        &executor,
        candidate_id,
        &recipe,
        input_node,
        RecoveryResource::EvidenceEdges,
        MAX_EDGES,
        MAX_EDGES - 4,
    );

    assert_eq!(executor.coordinator.pop_next()?, Some(later_candidate_id));
    executor.run_transform(later_candidate_id, later_input_node, &later_recipe)?;
    assert!(matches!(
        executor
            .coordinator
            .candidate(later_candidate_id)
            .map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            stage: RecoveryStage::Transform,
            result: RecoveryResult::Rejected { .. },
        })
    ));
    assert_eq!(executor.case.edges().len(), MAX_EDGES);
    Ok(())
}

#[test]
fn speculative_transform_node_quota_is_a_typed_omission_with_atomic_rollback()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"4142")?;
    while case.nodes().len() < MAX_NODES - 2 {
        case.add_node("quota_filler", None, Vec::new(), json!({}))?;
    }
    let proposal_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"proposal report",
        Vec::new(),
        json!({}),
    )?;

    let recipe = hex_recipe();
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe.clone()))?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));

    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let mut proposal_receipts = super::discovery::OrderedProposalReceipts::default();
    proposal_receipts.try_insert(proposal_report)?;
    executor
        .transform_proposal_receipts
        .insert(candidate_id, proposal_receipts);
    let before = executor.case.clone();

    let result = executor.run_transform(candidate_id, input_node, &recipe);

    assert!(
        result.is_ok(),
        "a speculative transform node quota must be recorded as an omission: {result:?}"
    );
    assert_eq!(
        *executor.case, before,
        "the partially created receipt and output nodes roll back together"
    );
    assert_speculative_transform_quota(
        &executor,
        candidate_id,
        &recipe,
        input_node,
        RecoveryResource::EvidenceNodes,
        MAX_NODES,
        MAX_NODES - 1,
    );
    Ok(())
}

#[test]
fn expansion_probe_child_mutations_roll_back_at_node_quota() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", &png(&[])?)?;
    while case.nodes().len() < MAX_NODES - 1 {
        case.add_node("quota_filler", None, Vec::new(), json!({}))?;
    }

    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::RecursiveExpansion)?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    let result = executor.run_expansion(candidate_id, &[input_node], input_node);

    assert!(
        result.is_ok(),
        "automatic expansion evidence quota must finish as a typed omission: {result:?}"
    );
    assert!(
        *executor.case == before,
        "probe incompleteness marks and all staged evidence are rolled back"
    );
    assert!(
        executor.case.nodes().iter().all(|node| {
            node.kind != "png_structure" && node.kind != "artifact_expansion_receipt"
        })
    );
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::RecursiveExpansion,
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::EvidenceNodes,
                limit: MAX_NODES,
                used: MAX_NODES - 1,
                requested: 1,
            },
        }),
        "the candidate records why its speculative evidence was omitted"
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecursiveExpansion,
            input_node_ids,
            resource: RecoveryResource::EvidenceNodes,
            limit: MAX_NODES,
            used,
            requested: 1,
        } if input_node_ids == &[input_node] && *used == MAX_NODES - 1
    )));
    Ok(())
}

#[test]
fn late_shallow_context_is_separate() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_node = source(&mut case, "http_body", b"root")?;
    let shallow_node = source(&mut case, "udp_payload", b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy().resources);
    let task = RecoveryTask::transform(Operation::Reverse {});
    let root = queued(coordinator.enqueue(&case, root_node, RecoveryTask::RecursiveExpansion)?)?;
    coordinator.pop_next()?;
    let root_result = finish_derived(&mut case, &mut coordinator, root, root_node)?;

    let middle = source(&mut case, "archive_member", b"middle")?;
    derived_from(&mut case, middle, root_result)?;
    let middle_work = queued(coordinator.enqueue_derived(root, &case, &[middle], task.clone())?)?;
    assert_eq!(coordinator.pop_next()?, Some(middle_work));
    let middle_result = finish_derived(&mut case, &mut coordinator, middle_work, middle)?;

    let deep_node = source(&mut case, "archive_member", b"same bytes")?;
    derived_from(&mut case, deep_node, middle_result)?;
    let deep_work =
        queued(coordinator.enqueue_derived(middle_work, &case, &[deep_node], task.clone())?)?;
    assert_eq!(coordinator.pop_next()?, Some(deep_work));
    finish_derived(&mut case, &mut coordinator, deep_work, deep_node)?;

    let shallow_work = queued(coordinator.enqueue(&case, shallow_node, task)?)?;
    assert_ne!(deep_work, shallow_work);
    assert_eq!(
        coordinator
            .candidate(deep_work)
            .map(RecoveryCandidate::depth),
        Some(2)
    );
    assert_eq!(
        coordinator
            .candidate(shallow_work)
            .map(RecoveryCandidate::depth),
        Some(0)
    );
    Ok(())
}

type RecoveredSnapshot = (Vec<Vec<u8>>, Vec<String>);

fn recover_in_order(nodes: &[(&str, &[u8])]) -> Result<RecoveredSnapshot, Box<dyn Error>> {
    let mut case = Case::new();
    for (kind, bytes) in nodes {
        source(&mut case, kind, bytes)?;
    }
    let outcome = execute(&mut case, &hex_plan(), &policy())?;
    let mut artifacts = validated_input_bytes(&case, &outcome.candidates);
    artifacts.sort();

    let node_keys = semantic_node_keys(&case)?;
    let mut edges = case
        .edges()
        .iter()
        .filter_map(|edge| {
            Some(format!(
                "{}>{}:{}:{:?}",
                node_keys.get(&edge.from)?,
                node_keys.get(&edge.to)?,
                edge.relation,
                edge.status
            ))
        })
        .collect::<Vec<_>>();
    edges.sort();
    Ok((artifacts, edges))
}

fn semantic_node_keys(case: &Case) -> Result<HashMap<u64, String>, Box<dyn Error>> {
    let blobs = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect::<HashMap<_, _>>();
    let mut labels = HashMap::new();
    for node in case.nodes() {
        let is_receipt = node.kind.ends_with("_receipt")
            || node.kind.ends_with("_rejected")
            || node.kind == "artifact_parse_rejection";
        let label = if is_receipt {
            let value = node
                .blob
                .as_deref()
                .and_then(|blob_id| blobs.get(blob_id).copied())
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .unwrap_or_else(|| node.details.clone());
            let mut value = value;
            normalize_node_references(&mut value, &labels);
            format!("{}:{}", node.kind, serde_json::to_string(&value)?)
        } else {
            format!("{}:{}", node.kind, node.blob.as_deref().unwrap_or(""))
        };
        labels.insert(node.id, label);
    }
    Ok(labels)
}

fn normalize_node_references(value: &mut serde_json::Value, labels: &HashMap<u64, String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (field, value) in fields {
                if let Some(label) = value
                    .as_u64()
                    .and_then(|id| labels.get(&id))
                    .filter(|_| field.ends_with("_node") || field == "node")
                {
                    *value = serde_json::Value::String(label.clone());
                    continue;
                }
                normalize_node_references(value, labels);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_node_references(value, labels);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

fn source(case: &mut Case, kind: &str, bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node(kind, bytes, Vec::new(), json!({}))?)
}

fn mapped_tcp_run(
    case: &mut Case,
    bytes: &[u8],
    capture_fingerprint: &[u8],
) -> Result<u64, Box<dyn Error>> {
    let source_length = bytes.len().max(capture_fingerprint.len());
    let source_id = case.add_source(
        "synthetic.pcap",
        "capture",
        u64::try_from(source_length)?,
        &l2_workbench::sha256(capture_fingerprint),
        None,
    )?;
    let mapping = ByteMapping {
        offset: 0,
        range: SourceRange {
            source: source_id,
            packet: Some(1),
            offset: 0,
            length: u64::try_from(bytes.len())?,
        },
    };
    Ok(case.add_mapped_bytes_node("tcp_byte_run", bytes, &[mapping], json!({}))?)
}

fn framed_record_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (sequence, payload) in [(0_u16, b'x'), (1_u16, b'y')] {
        bytes.push(1);
        bytes.extend_from_slice(b"A1");
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(payload);
    }
    bytes
}

fn base64_hex_framed_record_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    use base64::Engine as _;

    let mut bytes = Vec::new();
    for record_part in framed_record_bytes().chunks_exact(8) {
        let hexadecimal = hexadecimal_bytes(record_part)?;
        bytes.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(hexadecimal)
                .as_bytes(),
        );
    }
    Ok(bytes)
}

fn hexadecimal_bytes(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or("hexadecimal fixture length overflowed")?;
    let mut hexadecimal = Vec::with_capacity(capacity);
    for byte in bytes {
        hexadecimal.push(
            *HEX_DIGITS
                .get(usize::from(byte >> 4))
                .ok_or("high hexadecimal digit is out of range")?,
        );
        hexadecimal.push(
            *HEX_DIGITS
                .get(usize::from(byte & 0x0f))
                .ok_or("low hexadecimal digit is out of range")?,
        );
    }
    Ok(hexadecimal)
}

fn framed_record_schema() -> Result<l2_workbench::protocol::RecordSchema, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "records_offset":1,
        "count":{"kind":"field","field":{"offset":0,"width":1,"byte_order":"big_endian"}},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":1
    }))?)
}

fn candidate_record_schema() -> Result<l2_workbench::protocol::RecordSchema, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":1},
        "sequence":{"offset":1,"width":1,"byte_order":"big_endian"},
        "length":{"offset":2,"width":1,"byte_order":"big_endian"},
        "data_offset":3,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":null
    }))?)
}

fn framing_receipt_for_view(case: &Case, view_id: u64) -> Option<u64> {
    let source_input = case
        .nodes()
        .iter()
        .find(|node| node.id == view_id)?
        .details
        .get("source_input_node")?
        .as_u64()?;
    case.edges()
        .iter()
        .filter(|edge| edge.from == source_input && edge.relation == "derived_from")
        .find_map(|edge| {
            case.nodes()
                .iter()
                .find(|node| node.id == edge.to)
                .filter(|node| node.kind == "custom_protocol_framing_receipt")
                .map(|_| edge.to)
        })
}

fn stored_zip(name: &[u8], content: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    stored_zip_entries(&[(name, content)])
}

fn stored_zip_entries(entries: &[(&[u8], &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let entry_count = u16::try_from(entries.len())?;
    let mut archive = Vec::new();
    let mut central_directory = Vec::new();
    for (name, content) in entries {
        let name_length = u16::try_from(name.len())?;
        let content_length = u32::try_from(content.len())?;
        let checksum = crc32fast::hash(content);
        let local_offset = u32::try_from(archive.len())?;

        push_u32_le(&mut archive, 0x0403_4b50);
        push_u16_le(&mut archive, 20);
        push_u16_le(&mut archive, 0);
        push_u16_le(&mut archive, 0);
        push_u16_le(&mut archive, 0);
        push_u16_le(&mut archive, 0);
        push_u32_le(&mut archive, checksum);
        push_u32_le(&mut archive, content_length);
        push_u32_le(&mut archive, content_length);
        push_u16_le(&mut archive, name_length);
        push_u16_le(&mut archive, 0);
        archive.extend_from_slice(name);
        archive.extend_from_slice(content);

        push_u32_le(&mut central_directory, 0x0201_4b50);
        push_u16_le(&mut central_directory, 20);
        push_u16_le(&mut central_directory, 20);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u32_le(&mut central_directory, checksum);
        push_u32_le(&mut central_directory, content_length);
        push_u32_le(&mut central_directory, content_length);
        push_u16_le(&mut central_directory, name_length);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u16_le(&mut central_directory, 0);
        push_u32_le(&mut central_directory, 0);
        push_u32_le(&mut central_directory, local_offset);
        central_directory.extend_from_slice(name);
    }

    let central_offset = u32::try_from(archive.len())?;
    let central_size = u32::try_from(central_directory.len())?;
    archive.extend_from_slice(&central_directory);
    push_u32_le(&mut archive, 0x0605_4b50);
    push_u16_le(&mut archive, 0);
    push_u16_le(&mut archive, 0);
    push_u16_le(&mut archive, entry_count);
    push_u16_le(&mut archive, entry_count);
    push_u32_le(&mut archive, central_size);
    push_u32_le(&mut archive, central_offset);
    push_u16_le(&mut archive, 0);
    Ok(archive)
}

fn push_u16_le(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn hex_plan() -> RecoveryPlan {
    RecoveryPlan {
        recipes: vec![hex_recipe()],
        ..RecoveryPlan::default()
    }
}

fn hex_recipe() -> Recipe {
    Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: Vec::new(),
    }
}

fn base64_decode_recipe() -> Recipe {
    Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    }
}

fn only_transform<'a>(
    candidates: &'a [RecoveryCandidate],
    recipe: &Recipe,
    input_blob_id: &str,
) -> Result<&'a RecoveryCandidate, Box<dyn Error>> {
    let mut matches = candidates.iter().filter(|candidate| {
        candidate.task() == &RecoveryTask::Transform(recipe.clone())
            && candidate
                .inputs()
                .first()
                .is_some_and(|input| input.blob_id() == input_blob_id)
    });
    let candidate = matches.next().ok_or("transform candidate is missing")?;
    if matches.next().is_some() {
        return Err("transform candidate was executed more than once".into());
    }
    Ok(candidate)
}

fn is_terminal(candidate: &RecoveryCandidate) -> bool {
    matches!(candidate.state(), RecoveryCandidateState::Finished { .. })
}

fn validated_input_bytes(case: &Case, candidates: &[RecoveryCandidate]) -> Vec<Vec<u8>> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let RecoveryCandidateState::Finished {
                result: RecoveryResult::ObservedValidation { .. },
                ..
            } = candidate.state()
            else {
                return None;
            };
            let input = candidate.inputs().first()?;
            case.blobs()
                .iter()
                .find(|blob| blob.id == input.blob_id())
                .map(|blob| blob.bytes.clone())
        })
        .collect()
}

fn policy() -> RecoveryExecutionPolicy {
    let derivation = DerivationLimits::default();
    RecoveryExecutionPolicy {
        resources: RecoveryResourcePolicy {
            max_candidates: 256,
            max_frontier: 256,
            max_inputs_per_candidate: 1,
            max_origins_per_candidate: 8,
            max_input_bytes_per_item: 1024 * 1024,
            max_total_input_bytes_per_candidate: 1024 * 1024,
            max_depth: 6,
            max_output_bytes: 1024 * 1024,
            max_work_bytes: 32 * 1024 * 1024,
            max_candidate_task_identity_bytes: 16 * 1024 * 1024,
            max_transform_proposal_identity_bytes: 1024 * 1024,
            max_transform_proposal_associations: 1024,
            max_parent_links: 1024,
            max_lineage_work: 16 * 1024,
            max_context_aliases: 2048,
            max_pending_origin_links: 1024,
        },
        derivation_limits: derivation,
        decode_batch_limits: DecodeBatchLimits {
            items: 1,
            total_input_bytes: 1024 * 1024,
            total_work_bytes: derivation.max_work_bytes,
            total_output_bytes: derivation.max_output_bytes,
            total_report_bytes: 1024 * 1024,
        },
        record_limits: l2_workbench::protocol::RecordLimits {
            max_output_bytes: 1024 * 1024,
            ..l2_workbench::protocol::RecordLimits::default()
        },
        expansion_limits: ExpansionLimits {
            depth: 6,
            objects: 128,
            input_bytes: 1024 * 1024,
            archive_entries: 128,
            member_bytes: 1024 * 1024,
            zip_work_bytes: 16 * 1024 * 1024,
            retained_bytes: 1024 * 1024,
        },
        embedded_limits: l2_workbench::artifact::EmbeddedDiscoveryLimits {
            max_scan_bytes: 1024 * 1024,
            max_validation_attempts: 128,
            max_candidates: 128,
            png_limits: l2_workbench::artifact::PngLimits::default(),
            zip_limits: l2_workbench::artifact::zip::ZipArtifactLimits::default(),
            max_zip_operation_expanded_bytes: 16 * 1024 * 1024,
        },
        artifact_validation_policy: l2_workbench::artifact::ArtifactValidationPolicy::default(),
        record_schema_proposal_limits: l2_workbench::protocol::RecordSchemaProposalLimits::default(
        ),
        relational_transform_plan: l2_workbench::protocol::RelationalTransformPlan::default(),
        transform_exploration: TransformExplorationBudget {
            proposal_budget: TransformProposalBudget {
                max_candidates: 7,
                max_reports: 7,
            },
            max_scan_work_bytes_per_input: 7 * 1024 * 1024,
        },
        framing_discovery_plan: None,
        record_discovery_snapshot: None,
        record_phase_work_limit: 32 * 1024 * 1024,
    }
}

fn queued(
    outcome: l2_workbench::recovery::EnqueueOutcome,
) -> Result<l2_workbench::recovery::RecoveryCandidateId, Box<dyn Error>> {
    match outcome {
        l2_workbench::recovery::EnqueueOutcome::Queued(id) => Ok(id),
        _ => Err("expected a new recovery candidate".into()),
    }
}

fn assert_speculative_transform_quota(
    executor: &Executor<'_>,
    candidate_id: RecoveryCandidateId,
    recipe: &Recipe,
    input_node: u64,
    resource: RecoveryResource,
    limit: usize,
    used: usize,
) {
    let state = RecoveryCandidateState::Finished {
        stage: RecoveryStage::Transform,
        result: RecoveryResult::ResourceExhausted {
            resource,
            limit,
            used,
            requested: 1,
        },
    };
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&state)
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(task_recipe),
            input_node_ids,
            resource: omitted_resource,
            limit: omitted_limit,
            used: omitted_used,
            requested: 1,
        } if task_recipe == recipe
            && input_node_ids == &[input_node]
            && *omitted_resource == resource
            && *omitted_limit == limit
            && *omitted_used == used
    )));
}

fn finish_derived(
    case: &mut Case,
    coordinator: &mut RecoveryCoordinator,
    candidate: l2_workbench::recovery::RecoveryCandidateId,
    input: u64,
) -> Result<u64, Box<dyn Error>> {
    let receipt = case.add_bytes_node(
        "recovery_test_receipt",
        b"operation receipt",
        Vec::new(),
        json!({}),
    )?;
    case.add_edge(Edge {
        from: receipt,
        to: input,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The receipt records one exact operation result".to_owned(),
    })?;
    coordinator.finish(
        case,
        candidate,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    )?;
    Ok(receipt)
}

fn running_executor<'a>(
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
) -> Result<Executor<'a>, RecoveryExecutionError> {
    let case_index = CaseIndex::new(case)?;
    Ok(Executor {
        case,
        plan,
        policy: policy.clone(),
        coordinator,
        case_index,
        candidate_ids: Vec::new(),
        candidate_index: HashSet::new(),
        snapshot_candidates: false,
        job: None,
        validated_artifacts: HashSet::new(),
        transform_cohorts: Vec::new(),
        derived_discovery: super::derived_discovery::DerivedDiscovery::default(),
        transform_discoveries: HashMap::new(),
        framing_selection_bases: HashMap::new(),
        transform_proposal_receipts: HashMap::new(),
        framing_discoveries: HashMap::new(),
        record_discoveries: HashMap::new(),
        record_discovery_context_by_report: HashMap::new(),
        deferred_record_discovery_plan: None,
        record_schema_report_links: HashMap::new(),
        record_schema_associations_charged: 0,
        record_phase_work_charged: 0,
        pending_record_assemblies: std::collections::VecDeque::new(),
        pending_record_assembly_count: 0,
        relational_samples: super::RelationalSampleCollections::default(),
        relational_discoveries: HashMap::new(),
        omissions: Vec::new(),
        complete_negative_transform_searches: 0,
        cycle_skips: 0,
    })
}

fn fill_edges_to_quota(
    case: &mut Case,
    node_id: u64,
    edge_count: usize,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..edge_count {
        case.add_edge(Edge {
            from: node_id,
            to: node_id,
            relation: "existing_relation".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "Existing evidence fills the retained edge budget".to_owned(),
        })?;
    }
    Ok(())
}

fn derived_from(case: &mut Case, child: u64, parent_result: u64) -> Result<(), Box<dyn Error>> {
    case.add_edge(Edge {
        from: child,
        to: parent_result,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The parent operation retained these exact child bytes".to_owned(),
    })?;
    Ok(())
}

fn blob_id(bytes: &[u8]) -> String {
    format!("sha256:{}", l2_workbench::sha256(bytes))
}

fn xor(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if key.is_empty() {
        return Err("XOR fixture key cannot be empty".into());
    }
    bytes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, byte)| {
            key.get(index % key.len())
                .copied()
                .map(|key_byte| byte ^ key_byte)
                .ok_or_else(|| "XOR fixture key index is missing".into())
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes.iter().copied() {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        encoded.push(char::from(
            DIGITS.get(high).copied().ok_or("high nibble is invalid")?,
        ));
        encoded.push(char::from(
            DIGITS.get(low).copied().ok_or("low nibble is invalid")?,
        ));
    }
    Ok(encoded)
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex fixture has an odd length".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(value.len() / 2)?;
    for pair in value.as_bytes().chunks_exact(2) {
        let high = pair
            .first()
            .and_then(|byte| char::from(*byte).to_digit(16))
            .ok_or("hex fixture has an invalid digit")?;
        let low = pair
            .get(1)
            .and_then(|byte| char::from(*byte).to_digit(16))
            .ok_or("hex fixture has an invalid digit")?;
        bytes.push(u8::try_from((high << 4) | low)?);
    }
    Ok(bytes)
}

fn png(chunks: &[([u8; 4], &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let header = [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
    add_png_chunk(&mut bytes, *b"IHDR", &header)?;
    for (kind, payload) in chunks {
        add_png_chunk(&mut bytes, *kind, payload)?;
    }
    add_png_chunk(&mut bytes, *b"IEND", &[])?;
    Ok(bytes)
}

fn tiny_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header()?.write_image_data(&[1, 2, 3])?;
    }
    Ok(bytes)
}

fn add_png_chunk(bytes: &mut Vec<u8>, kind: [u8; 4], payload: &[u8]) -> Result<(), Box<dyn Error>> {
    bytes.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&kind);
    bytes.extend_from_slice(payload);
    let mut checksum = crc32fast::Hasher::new();
    checksum.update(&kind);
    checksum.update(payload);
    bytes.extend_from_slice(&checksum.finalize().to_be_bytes());
    Ok(())
}

#[path = "recovery_transform_discovery.rs"]
mod transform_discovery;

#[path = "recovery_case_quota.rs"]
mod case_quota;

#[path = "recovery_derived_discovery.rs"]
mod derived_discovery;
