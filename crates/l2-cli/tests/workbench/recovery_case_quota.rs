use super::*;
use l2_workbench::{
    evidence::{Case, MAX_BLOB_TOTAL_BYTES},
    recovery::RecoveryResource,
};

#[test]
fn embedded_aliases_reach_child_through_one_canonical_origin_and_receipt()
-> Result<(), Box<dyn Error>> {
    let object = tiny_png()?;
    let mut input_bytes = b"prefix".to_vec();
    input_bytes.extend_from_slice(&object);
    let mut case = Case::new();
    let first_origin = source(&mut case, "http_body", &input_bytes)?;
    let alias_origin = source(&mut case, "udp_payload", &input_bytes)?;
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, first_origin, RecoveryTask::EmbeddedDiscovery)?)?;
    assert_eq!(
        coordinator.enqueue(&case, alias_origin, RecoveryTask::EmbeddedDiscovery)?,
        l2_workbench::recovery::EnqueueOutcome::Merged(candidate_id)
    );
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;

    executor.run_embedded(candidate_id, &[first_origin, alias_origin])?;

    let child = executor
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "embedded_artifact")
        .ok_or("the validated embedded child was not retained")?;
    let receipt = executor
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "embedded_discovery_receipt")
        .ok_or("the embedded discovery receipt was not retained")?;
    assert!(executor.case.edges().iter().any(|edge| {
        edge.from == first_origin
            && edge.to == child.id
            && edge.relation == "contains_embedded_candidate"
            && edge.status == EvidenceStatus::Observed
    }));
    assert!(
        !executor.case.edges().iter().any(|edge| {
            edge.from == alias_origin
                && edge.to == child.id
                && edge.relation == "contains_embedded_candidate"
        }),
        "same-byte aliases are linked through the receipt without duplicating child edges"
    );
    assert!(executor.case.edges().iter().any(|edge| {
        edge.from == child.id && edge.to == receipt.id && edge.relation == "derived_from"
    }));
    for origin in [first_origin, alias_origin] {
        assert!(executor.case.edges().iter().any(|edge| {
            edge.from == receipt.id
                && edge.to == origin
                && edge.relation == "derived_from"
                && edge.status == EvidenceStatus::Observed
        }));
    }
    assert_eq!(
        executor
            .case
            .edges()
            .iter()
            .filter(|edge| {
                edge.to == child.id && edge.relation == "contains_embedded_candidate"
            })
            .count(),
        1
    );
    Ok(())
}

#[test]
fn embedded_blob_byte_quota_rolls_back_receipt_and_continues_independent_work()
-> Result<(), Box<dyn Error>> {
    let object = tiny_png()?;
    let mut input_bytes = b"prefix".to_vec();
    input_bytes.extend_from_slice(&object);
    let plain_bytes = b"independent plain input";
    let receipt_bytes = embedded_receipt_blob_bytes(&input_bytes)?;
    let baseline_blob_bytes = input_bytes
        .len()
        .checked_add(plain_bytes.len())
        .ok_or("the fixture blob size overflowed")?;
    let blob_limit = baseline_blob_bytes
        .checked_add(receipt_bytes)
        .ok_or("the fixture quota overflowed")?;
    assert!(blob_limit < MAX_BLOB_TOTAL_BYTES);

    let execution_policy = policy();
    let plan = RecoveryPlan::default();
    let mut case = Case::with_blob_limit(blob_limit)?;
    let input_node = source(&mut case, "http_body", &input_bytes)?;
    let plain_node = source(&mut case, "udp_payload", plain_bytes)?;
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::EmbeddedDiscovery)?)?;
    let independent_id =
        queued(coordinator.enqueue(&case, plain_node, RecoveryTask::EmbeddedDiscovery)?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let before = executor.case.clone();

    executor.run_embedded(candidate_id, &[input_node])?;

    assert_eq!(
        *executor.case, before,
        "the committed receipt is rolled back with the child whose blob exceeded the aggregate limit"
    );
    assert!(executor.case.nodes().iter().all(|node| {
        node.kind != "embedded_discovery_receipt" && node.kind != "embedded_artifact"
    }));
    assert_case_quota_outcome(
        &executor,
        candidate_id,
        &RecoveryTask::EmbeddedDiscovery,
        &[input_node],
        RecoveryResource::EvidenceBlobBytes,
        blob_limit,
        baseline_blob_bytes,
    )?;
    assert_eq!(executor.coordinator.pop_next()?, Some(independent_id));
    executor.run_embedded(independent_id, &[plain_node])?;
    assert!(matches!(
        executor
            .coordinator
            .candidate(independent_id)
            .map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            stage: RecoveryStage::EmbeddedDiscovery,
            result: RecoveryResult::Unsupported,
        })
    ));
    Ok(())
}

#[test]
fn discovery_report_evidence_quota_keeps_search_complete_but_details_incomplete() {
    let resources = [
        RecoveryResource::OutputBytes,
        RecoveryResource::EvidenceNodes,
        RecoveryResource::EvidenceEdges,
        RecoveryResource::EvidenceBlobs,
        RecoveryResource::EvidenceBlobBytes,
        RecoveryResource::EvidenceTotalDetailsBytes,
        RecoveryResource::EvidenceSourceRanges,
        RecoveryResource::EvidenceLimitations,
    ];

    for task in [
        RecoveryTask::TransformDiscovery,
        RecoveryTask::FramingDiscovery,
        RecoveryTask::RecordDiscovery,
    ] {
        for resource in resources {
            let omission = RecoveryOmission::ResourceExhausted {
                task: task.clone(),
                input_node_ids: vec![7],
                resource,
                limit: 1,
                used: 1,
                requested: 1,
            };
            assert!(discovery_input_coverage_complete(std::slice::from_ref(
                &omission
            )));
            assert!(search_exhaustive_within_plan(std::slice::from_ref(
                &omission
            )));
            assert!(!report_details_complete(std::slice::from_ref(&omission)));
        }
    }
}

#[test]
fn case_evidence_quota_helper_reports_current_usage_and_ignores_nonquota_errors()
-> Result<(), Box<dyn Error>> {
    use super::super::evidence::case_evidence_quota;
    use l2_workbench::evidence::{MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES};

    let mut case = Case::with_blob_limit(32)?;
    source(&mut case, "http_body", b"initial bytes")?;
    let details = b"details";
    let source = case.add_source(
        "quota.bin",
        "file",
        details.len() as u64,
        &l2_workbench::sha256(details),
        None,
    )?;
    case.add_bytes_node(
        "quota_detail",
        details,
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 1,
        }],
        json!({"a": 1}),
    )?;

    let blob_quota_error = EvidenceError::QuotaExceeded {
        field: "blob bytes",
        maximum: 32,
    };
    let details_quota_error = EvidenceError::TotalDetailsTooLarge {
        length: MAX_TOTAL_DETAILS_BYTES + 1,
        maximum: MAX_TOTAL_DETAILS_BYTES,
    };
    let ranges_quota_error = EvidenceError::QuotaExceeded {
        field: "source ranges",
        maximum: MAX_TOTAL_SOURCE_RANGES,
    };
    let before = case.clone();
    assert_eq!(
        case_evidence_quota(&case, &blob_quota_error),
        Some((RecoveryResource::EvidenceBlobBytes, 32, 20))
    );
    assert_eq!(
        case_evidence_quota(&case, &details_quota_error),
        Some((
            RecoveryResource::EvidenceTotalDetailsBytes,
            MAX_TOTAL_DETAILS_BYTES,
            9
        ))
    );
    assert_eq!(
        case_evidence_quota(&case, &ranges_quota_error),
        Some((
            RecoveryResource::EvidenceSourceRanges,
            MAX_TOTAL_SOURCE_RANGES,
            1
        ))
    );
    assert_eq!(case, before);

    for error in [
        EvidenceError::NodeDetailsTooLarge {
            length: 1,
            maximum: 0,
        },
        EvidenceError::QuotaExceeded {
            field: "node details",
            maximum: 32,
        },
        EvidenceError::AllocationFailed { field: "nodes" },
        EvidenceError::InvalidText { field: "node kind" },
    ] {
        assert_eq!(case_evidence_quota(&case, &error), None);
    }
    Ok(())
}

fn embedded_receipt_blob_bytes(input_bytes: &[u8]) -> Result<usize, Box<dyn Error>> {
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", input_bytes)?;
    let mut coordinator = RecoveryCoordinator::new(policy().resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::EmbeddedDiscovery)?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let execution_policy = policy();
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    executor.run_embedded(candidate_id, &[input_node])?;
    let receipt_blob_id = executor
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "embedded_discovery_receipt")
        .and_then(|node| node.blob.as_deref())
        .ok_or("the baseline receipt has no retained blob")?;
    let receipt_bytes = executor
        .case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .ok_or("the baseline receipt blob was not retained")?
        .bytes
        .len();
    Ok(receipt_bytes)
}

#[test]
fn speculative_transform_blob_quota_rolls_back() -> Result<(), Box<dyn Error>> {
    let (blob_limit, used_before_transform) = transform_blob_quota_limit()?;
    let recipe = hex_recipe();
    let mut case = Case::with_blob_limit(blob_limit)?;
    let input_node = source(&mut case, "http_body", b"4142")?;
    let proposal_report = case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"proposal report",
        Vec::new(),
        json!({}),
    )?;
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe.clone()))?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;
    let mut proposal_receipts = super::super::discovery::OrderedProposalReceipts::default();
    proposal_receipts.try_insert(proposal_report)?;
    executor
        .transform_proposal_receipts
        .insert(candidate_id, proposal_receipts);
    let before = executor.case.clone();

    executor.run_transform(candidate_id, input_node, &recipe)?;

    assert_eq!(
        *executor.case, before,
        "receipt and output blobs roll back when the output exceeds the aggregate Case limit"
    );
    assert!(
        executor
            .case
            .nodes()
            .iter()
            .all(|node| { node.kind != "decoding_receipt" && node.kind != "decoding_output" })
    );
    assert_case_quota_outcome(
        &executor,
        candidate_id,
        &RecoveryTask::Transform(recipe.clone()),
        &[input_node],
        RecoveryResource::EvidenceBlobBytes,
        blob_limit,
        used_before_transform,
    )?;
    Ok(())
}

#[test]
fn exact_transform_blob_quota_remains_fatal() -> Result<(), Box<dyn Error>> {
    let (blob_limit, _) = transform_blob_quota_limit()?;
    let recipe = hex_recipe();
    let execution_policy = policy();
    let mut exact_case = Case::with_blob_limit(blob_limit)?;
    let exact_input = source(&mut exact_case, "http_body", b"4142")?;
    let exact_proposal = exact_case.add_bytes_node(
        "recovery_transform_proposal_report",
        b"proposal report",
        Vec::new(),
        json!({}),
    )?;
    let mut exact_coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let exact_candidate = queued(exact_coordinator.enqueue(
        &exact_case,
        exact_input,
        RecoveryTask::Transform(recipe.clone()),
    )?)?;
    assert_eq!(exact_coordinator.pop_next()?, Some(exact_candidate));
    let exact_plan = RecoveryPlan {
        recipes: vec![recipe.clone()],
        ..RecoveryPlan::default()
    };
    let mut exact_executor = running_executor(
        &mut exact_case,
        &exact_plan,
        &execution_policy,
        exact_coordinator,
    )?;
    let mut exact_receipts = super::super::discovery::OrderedProposalReceipts::default();
    exact_receipts.try_insert(exact_proposal)?;
    exact_executor
        .transform_proposal_receipts
        .insert(exact_candidate, exact_receipts);
    let before_exact = exact_executor.case.clone();

    let result = exact_executor.run_transform(exact_candidate, exact_input, &recipe);

    assert!(
        result.is_err(),
        "an exact caller-selected transform remains fatal on the same aggregate Case quota"
    );
    assert_eq!(*exact_executor.case, before_exact);
    assert!(exact_executor.omissions.is_empty());
    assert!(matches!(
        exact_executor
            .coordinator
            .candidate(exact_candidate)
            .map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Running(RecoveryStage::Transform))
    ));
    Ok(())
}

fn transform_blob_quota_limit() -> Result<(usize, usize), Box<dyn Error>> {
    let recipe = hex_recipe();
    let proposal_bytes = b"proposal report";
    let mut case = Case::new();
    let input_node = source(&mut case, "http_body", b"4142")?;
    case.add_bytes_node(
        "recovery_transform_proposal_report",
        proposal_bytes,
        Vec::new(),
        json!({}),
    )?;
    let execution_policy = policy();
    let mut coordinator = RecoveryCoordinator::new(execution_policy.resources);
    let candidate_id =
        queued(coordinator.enqueue(&case, input_node, RecoveryTask::Transform(recipe.clone()))?)?;
    assert_eq!(coordinator.pop_next()?, Some(candidate_id));
    let plan = RecoveryPlan::default();
    let mut executor = running_executor(&mut case, &plan, &execution_policy, coordinator)?;

    executor.run_transform(candidate_id, input_node, &recipe)?;

    let receipt_node_id = match executor
        .coordinator
        .candidate(candidate_id)
        .map(RecoveryCandidate::state)
    {
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        }) => *evidence_node_id,
        _ => return Err("baseline transform did not retain its receipt".into()),
    };
    let receipt_blob_id = executor
        .case
        .nodes()
        .iter()
        .find(|node| node.id == receipt_node_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("baseline transform receipt has no blob")?;
    let receipt_bytes = executor
        .case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .ok_or("baseline transform receipt blob is missing")?
        .bytes
        .len();
    let used_before_transform = b"4142".len() + proposal_bytes.len();
    let blob_limit = used_before_transform
        .checked_add(receipt_bytes)
        .ok_or("transform Case blob quota overflowed")?;
    Ok((blob_limit, used_before_transform))
}

fn assert_case_quota_outcome(
    executor: &Executor<'_>,
    candidate_id: RecoveryCandidateId,
    task: &RecoveryTask,
    origins: &[u64],
    resource: RecoveryResource,
    limit: usize,
    used: usize,
) -> Result<(), Box<dyn Error>> {
    let stage = match task {
        RecoveryTask::Transform(_) => RecoveryStage::Transform,
        RecoveryTask::EmbeddedDiscovery => RecoveryStage::EmbeddedDiscovery,
        RecoveryTask::RecursiveExpansion => RecoveryStage::RecursiveExpansion,
        _ => return Err("quota assertion received an unsupported task".into()),
    };
    assert_eq!(
        executor
            .coordinator
            .candidate(candidate_id)
            .map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage,
            result: RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested: 1,
            },
        })
    );
    assert!(executor.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::ResourceExhausted {
            task: omitted_task,
            input_node_ids,
            resource: omitted_resource,
            limit: omitted_limit,
            used: omitted_used,
            requested: 1,
        } if omitted_task == task
            && input_node_ids == origins
            && *omitted_resource == resource
            && *omitted_limit == limit
            && *omitted_used == used
    )));
    Ok(())
}
