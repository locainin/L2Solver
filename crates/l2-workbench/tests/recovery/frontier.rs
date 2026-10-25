use l2_workbench::{
    derivation::{
        Constraint, CounterByteOrder, CounterWidth, DerivationError, DerivationLimits, OperandRef,
        Operation, Recipe, SeedCounterOrder,
    },
    evidence::{Case, Edge, EvidenceStatus, SourceRange},
    protocol::{
        ByteField, ByteOrder, FramingKind, IntegerField, RecordCount, RecordLengthMeaning,
        RecordSchema,
    },
    recovery::{
        BudgetCheck, ContextRegistration, EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId,
        RecoveryCandidateState, RecoveryCoordinator, RecoveryError, RecoveryResource,
        RecoveryResourcePolicy, RecoveryResult, RecoveryStage, RecoveryTask,
    },
};
use std::error::Error;

const fn policy() -> RecoveryResourcePolicy {
    RecoveryResourcePolicy {
        max_candidates: 16,
        max_frontier: 16,
        max_inputs_per_candidate: 8,
        max_origins_per_candidate: 16,
        max_input_bytes_per_item: 32,
        max_total_input_bytes_per_candidate: 128,
        max_depth: 4,
        max_output_bytes: 32,
        max_work_bytes: 128,
        max_candidate_task_identity_bytes: 16 * 1024 * 1024,
        max_transform_proposal_identity_bytes: 16 * 1024 * 1024,
        max_transform_proposal_associations: 64,
        max_parent_links: 256,
        max_lineage_work: 4096,
        max_context_aliases: 4096,
        max_pending_origin_links: 4096,
    }
}

fn node(case: &mut Case, bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node("recovery_input", bytes, Vec::new(), serde_json::json!({}))?)
}

fn mapped_duplicate_nodes(case: &mut Case) -> Result<(u64, u64), Box<dyn Error>> {
    let backing = b"same bytes|same bytes";
    let source = case.add_source(
        "mapped.bin",
        "file",
        u64::try_from(backing.len())?,
        &l2_workbench::sha256(backing),
        None,
    )?;
    let first = case.add_bytes_node(
        "mapped_input",
        b"same bytes",
        vec![SourceRange {
            source: source.clone(),
            packet: None,
            offset: 0,
            length: 10,
        }],
        serde_json::json!({}),
    )?;
    let second = case.add_bytes_node(
        "mapped_input",
        b"same bytes",
        vec![SourceRange {
            source,
            packet: None,
            offset: 11,
            length: 10,
        }],
        serde_json::json!({}),
    )?;
    Ok((first, second))
}

const fn sha256_xor(seed: OperandRef) -> Operation {
    Operation::Sha256CounterXor {
        seed,
        initial_counter: 0,
        counter_width: CounterWidth::FourBytes,
        counter_byte_order: CounterByteOrder::BigEndian,
        seed_order: SeedCounterOrder::SeedThenCounter,
    }
}

fn queue(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    node_id: u64,
    task: RecoveryTask,
) -> Result<RecoveryCandidateId, Box<dyn Error>> {
    queued_id(coordinator.enqueue(case, node_id, task)?)
}

fn queue_nodes(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    node_ids: &[u64],
    task: RecoveryTask,
) -> Result<RecoveryCandidateId, Box<dyn Error>> {
    queued_id(coordinator.enqueue_nodes(case, node_ids, task)?)
}

fn finished_parent(
    coordinator: &mut RecoveryCoordinator,
    case: &mut Case,
    input_bytes: &[u8],
    receipt_bytes: &[u8],
    child_bytes: &[u8],
) -> Result<(RecoveryCandidateId, u64), Box<dyn Error>> {
    let input = node(case, input_bytes)?;
    let receipt = node(case, receipt_bytes)?;
    let child = node(case, child_bytes)?;
    derived_link(case, receipt, input)?;
    derived_link(case, child, receipt)?;
    let parent = queue(coordinator, case, input, RecoveryTask::RecursiveExpansion)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    )?;
    Ok((parent, child))
}

type TwoParentFixture = (Case, RecoveryCoordinator, [(RecoveryCandidateId, u64); 2]);

fn two_parent_fixture(
    resources: RecoveryResourcePolicy,
    first_child_bytes: &[u8],
    second_child_bytes: &[u8],
) -> Result<TwoParentFixture, Box<dyn Error>> {
    let mut case = Case::new();
    let mut coordinator = RecoveryCoordinator::new(resources);
    let first = finished_parent(&mut coordinator, &mut case, b"1", b"r1", first_child_bytes)?;
    let second = finished_parent(&mut coordinator, &mut case, b"2", b"r2", second_child_bytes)?;
    Ok((case, coordinator, [first, second]))
}

fn assert_batch_budget(
    resources: RecoveryResourcePolicy,
    first_child_bytes: &[u8],
    second_child_bytes: &[u8],
    expected: EnqueueOutcome,
) -> Result<(), Box<dyn Error>> {
    let (case, mut coordinator, parents) =
        two_parent_fixture(resources, first_child_bytes, second_child_bytes)?;
    let [(first_parent, first_child), (second_parent, second_child)] = parents;
    let count_before = coordinator.candidate_count();

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Ok(expected)
    );
    assert_eq!(coordinator.candidate_count(), count_before);
    assert_eq!(coordinator.pop_next(), Ok(None));
    Ok(())
}

fn queued_id(outcome: EnqueueOutcome) -> Result<RecoveryCandidateId, Box<dyn Error>> {
    match outcome {
        EnqueueOutcome::Queued(id) => Ok(id),
        other => Err(std::io::Error::other(format!("unexpected enqueue result: {other:?}")).into()),
    }
}

fn candidate(
    coordinator: &RecoveryCoordinator,
    id: RecoveryCandidateId,
) -> Result<&RecoveryCandidate, Box<dyn Error>> {
    coordinator
        .candidate(id)
        .ok_or_else(|| std::io::Error::other("candidate should exist").into())
}

fn transform(operation: Operation) -> RecoveryTask {
    RecoveryTask::Transform(Recipe {
        steps: vec![operation],
        constraints: Vec::new(),
    })
}

fn xor_task(key: Vec<u8>, offset: usize) -> RecoveryTask {
    transform(Operation::XorRepeat { key, offset })
}

fn link(case: &mut Case, from: u64, to: u64, status: EvidenceStatus) -> Result<(), Box<dyn Error>> {
    edge(case, from, to, "recovery_result", status)
}

fn edge(
    case: &mut Case,
    from: u64,
    to: u64,
    relation: &str,
    status: EvidenceStatus,
) -> Result<(), Box<dyn Error>> {
    case.add_edge(Edge {
        from,
        to,
        relation: relation.to_owned(),
        status,
        reason: "The recovery result is linked to its supporting input node".to_owned(),
    })?;
    Ok(())
}

fn derived_link(case: &mut Case, output: u64, parent: u64) -> Result<(), Box<dyn Error>> {
    case.add_edge(Edge {
        from: output,
        to: parent,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The output node records its immediate derivation input".to_owned(),
    })?;
    Ok(())
}

const fn record_schema(sequence_offset: usize) -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: sequence_offset,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

#[test]
fn fifo_preserves_task_order() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"source")?;
    let tasks = [
        (transform(Operation::Reverse {}), RecoveryStage::Transform),
        (
            RecoveryTask::TransformDiscovery,
            RecoveryStage::TransformDiscovery,
        ),
        (
            RecoveryTask::FramingDiscovery,
            RecoveryStage::FramingDiscovery,
        ),
        (
            RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 }),
            RecoveryStage::MaterializeFraming,
        ),
        (
            RecoveryTask::RecordDiscovery,
            RecoveryStage::RecordDiscovery,
        ),
        (
            RecoveryTask::AssembleRecords(record_schema(1)),
            RecoveryStage::AssembleRecords,
        ),
        (
            RecoveryTask::EmbeddedDiscovery,
            RecoveryStage::EmbeddedDiscovery,
        ),
        (
            RecoveryTask::StructuralValidation,
            RecoveryStage::StructuralValidation,
        ),
        (
            RecoveryTask::RecursiveExpansion,
            RecoveryStage::RecursiveExpansion,
        ),
    ];
    let mut coordinator = RecoveryCoordinator::new(policy());
    let mut ids = Vec::with_capacity(tasks.len());
    for (task, _) in &tasks {
        ids.push(queue(&mut coordinator, &case, origin, task.clone())?);
    }

    for ((_, stage), expected_id) in tasks.into_iter().zip(ids) {
        assert_eq!(coordinator.pop_next(), Ok(Some(expected_id)));
        assert_eq!(
            coordinator
                .candidate(expected_id)
                .map(RecoveryCandidate::state),
            Some(&RecoveryCandidateState::Running(stage))
        );
    }
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

#[test]
fn duplicate_merges_origins() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same bytes")?;
    let second = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first_id = queue(
        &mut coordinator,
        &case,
        first,
        transform(Operation::Reverse {}),
    )?;

    assert_eq!(
        coordinator.enqueue(&case, second, transform(Operation::Reverse {}),)?,
        EnqueueOutcome::Merged(first_id)
    );
    let candidate = candidate(&coordinator, first_id)?;
    let [input] = candidate.inputs() else {
        return Err(std::io::Error::other("expected one candidate input").into());
    };
    assert_eq!(input.origin_node_ids(), &[first, second]);

    Ok(())
}

#[test]
fn input_blob_reuses_case_storage() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"retained input")?;
    let expected = case
        .blobs()
        .first()
        .ok_or_else(|| std::io::Error::other("retained test blob should exist"))?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;

    let actual = coordinator.input_blob(&case, id)?;
    assert!(std::ptr::eq(actual, expected));

    Ok(())
}

#[test]
fn coordinator_rejects_case_switch_with_different_blob_positions() -> Result<(), Box<dyn Error>> {
    let mut original = Case::new();
    let origin = node(&mut original, b"retained input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &original,
        origin,
        transform(Operation::Reverse {}),
    )?;

    let mut replacement = Case::new();
    replacement.add_blob(b"unreferenced first blob")?;
    let replacement_origin = node(&mut replacement, b"retained input")?;
    assert_eq!(replacement_origin, origin);
    let _additional_node = node(&mut replacement, b"additional blob")?;

    assert_eq!(
        coordinator.input_blob(&replacement, id),
        Err(RecoveryError::DifferentCase)
    );

    Ok(())
}

#[test]
fn coordinator_rejects_cloned_case() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"retained input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;
    let clone = case.clone();

    assert_eq!(
        coordinator.input_blob(&clone, id),
        Err(RecoveryError::DifferentCase)
    );

    Ok(())
}

#[test]
fn completed_result_cannot_merge_with_candidate_from_another_case() -> Result<(), Box<dyn Error>> {
    let mut original = Case::new();
    let origin = node(&mut original, b"same input")?;
    let output = node(&mut original, b"derived output")?;
    derived_link(&mut original, output, origin)?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let task = transform(Operation::Reverse {});
    let id = queue(&mut coordinator, &original, origin, task.clone())?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(
        &original,
        id,
        RecoveryResult::Derived {
            evidence_node_id: output,
        },
    )?;

    let mut replacement = Case::new();
    let replacement_origin = node(&mut replacement, b"same input")?;
    let _unrelated_node = node(&mut replacement, b"unrelated node two")?;
    assert_eq!(replacement_origin, origin);

    assert_eq!(
        coordinator.enqueue(&replacement, replacement_origin, task),
        Err(RecoveryError::DifferentCase)
    );
    assert_eq!(coordinator.candidate_count(), 1);
    assert!(matches!(
        candidate(&coordinator, id)?.state(),
        RecoveryCandidateState::Finished { .. }
    ));

    Ok(())
}

#[test]
fn result_validation_rejects_a_different_case() -> Result<(), Box<dyn Error>> {
    let mut original = Case::new();
    let origin = node(&mut original, b"same retained input")?;
    let result = node(&mut original, b"result")?;
    edge(
        &mut original,
        result,
        origin,
        "recovery_result",
        EvidenceStatus::ConstraintSatisfied,
    )?;

    let mut replacement = Case::new();
    let replacement_origin = node(&mut replacement, b"same retained input")?;
    let replacement_result = node(&mut replacement, b"result")?;
    edge(
        &mut replacement,
        replacement_origin,
        replacement_result,
        "unrelated",
        EvidenceStatus::ConstraintSatisfied,
    )?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &original,
        origin,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.finish(
            &replacement,
            id,
            RecoveryResult::ObservedValidation {
                node_id: replacement_result,
            },
        ),
        Err(RecoveryError::DifferentCase)
    );

    Ok(())
}

#[test]
fn edge_index_keeps_preexisting_link_after_transaction_rollback() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"input")?;
    let result = node(&mut case, b"validated result")?;
    edge(
        &mut case,
        result,
        origin,
        "recovery_result",
        EvidenceStatus::ConstraintSatisfied,
    )?;

    let rollback: Result<(), Box<dyn Error>> = case.transaction(|case| {
        edge(
            case,
            result,
            origin,
            "recovery_result",
            EvidenceStatus::ConstraintSatisfied,
        )?;
        Err(std::io::Error::other("rollback duplicate relation").into())
    });
    assert!(rollback.is_err());

    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::ObservedValidation { node_id: result },
        ),
        Ok(())
    );

    Ok(())
}

#[test]
fn distinct_tasks_keep_work() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::HexDecode {}),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::RecordDiscovery,
    )?;

    assert_eq!(coordinator.candidate_count(), 3);

    Ok(())
}

#[test]
fn candidate_task_identity_bytes_use_exact_budget_and_reject_atomically()
-> Result<(), Box<dyn Error>> {
    let task = transform(Operation::XorRepeat {
        key: vec![0xa5; 256],
        offset: 0,
    });
    let task_identity_bytes = serde_json::to_vec(&task)?.len();
    let mut resources = policy();
    resources.max_candidate_task_identity_bytes = task_identity_bytes;
    let mut first_case = Case::new();
    let first_input = node(&mut first_case, b"first")?;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert!(matches!(
        coordinator.enqueue(&first_case, first_input, task.clone())?,
        EnqueueOutcome::Queued(_)
    ));
    assert_eq!(
        coordinator.candidate_task_identity_bytes_charged(),
        task_identity_bytes
    );
    assert_eq!(coordinator.remaining_candidate_task_identity_bytes(), 0);

    let second_input = node(&mut first_case, b"second")?;
    assert_eq!(
        coordinator.enqueue(&first_case, second_input, task)?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateTaskIdentityBytes,
            limit: task_identity_bytes,
            used: task_identity_bytes,
            requested: task_identity_bytes,
        }
    );
    assert_eq!(coordinator.candidate_count(), 1);
    assert_eq!(
        coordinator.candidate_task_identity_bytes_charged(),
        task_identity_bytes
    );

    Ok(())
}

#[test]
fn oversized_transform_task_is_rejected_before_case_binding() -> Result<(), Box<dyn Error>> {
    let mut first_case = Case::new();
    let first_input = node(&mut first_case, b"first")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let limits = DerivationLimits::default();
    let oversized_steps = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}; limits.max_steps + 1],
        constraints: Vec::new(),
    });

    assert_eq!(
        coordinator.enqueue(&first_case, first_input, oversized_steps),
        Err(RecoveryError::InvalidTaskIdentity(
            DerivationError::TooManySteps {
                count: limits.max_steps + 1,
                limit: limits.max_steps,
            }
        ))
    );
    assert_eq!(coordinator.candidate_count(), 0);

    let oversized_constraints = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Length { bytes: 1 }; limits.max_constraints + 1],
    });
    assert_eq!(
        coordinator.enqueue(&first_case, first_input, oversized_constraints),
        Err(RecoveryError::InvalidTaskIdentity(
            DerivationError::TooManyConstraints {
                count: limits.max_constraints + 1,
                limit: limits.max_constraints,
            }
        ))
    );

    let oversized_parameter = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::XorRepeat {
            key: vec![0; limits.max_recipe_parameter_bytes + 1],
            offset: 0,
        }],
        constraints: Vec::new(),
    });
    assert_eq!(
        coordinator.enqueue(&first_case, first_input, oversized_parameter),
        Err(RecoveryError::InvalidTaskIdentity(
            DerivationError::RecipeParametersTooLarge {
                limit: limits.max_recipe_parameter_bytes,
            }
        ))
    );
    assert_eq!(coordinator.candidate_count(), 0);

    let mut second_case = Case::new();
    let second_input = node(&mut second_case, b"second")?;
    assert!(matches!(
        coordinator.enqueue(&second_case, second_input, transform(Operation::Reverse {}))?,
        EnqueueOutcome::Queued(_)
    ));

    Ok(())
}

#[test]
fn recipe_checks_change_identity() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let first = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Length { bytes: 2 }],
    });
    let second = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Length { bytes: 3 }],
    });
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first_id = queue(&mut coordinator, &case, origin, first)?;
    let second_id = queue(&mut coordinator, &case, origin, second)?;

    assert_ne!(first_id, second_id);
    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn rotate_counts_normalize() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::RotateBits { count: 9 }),
    )?;

    assert_eq!(
        coordinator.enqueue(&case, origin, transform(Operation::RotateBits { count: 1 }),)?,
        EnqueueOutcome::Merged(first)
    );
    assert_eq!(
        candidate(&coordinator, first)?.task(),
        &transform(Operation::RotateBits { count: 9 })
    );

    Ok(())
}

#[test]
fn xor_offsets_normalize() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::XorRepeat {
            key: vec![1, 2, 3, 4],
            offset: 5,
        }),
    )?;

    assert_eq!(
        coordinator.enqueue(
            &case,
            origin,
            transform(Operation::XorRepeat {
                key: vec![1, 2, 3, 4],
                offset: 1,
            }),
        )?,
        EnqueueOutcome::Merged(first)
    );
    assert_eq!(coordinator.candidate_count(), 1);
    assert_eq!(
        candidate(&coordinator, first)?.task(),
        &transform(Operation::XorRepeat {
            key: vec![1, 2, 3, 4],
            offset: 5,
        })
    );

    Ok(())
}

#[test]
fn repeating_xor_primitive_period_and_phase_define_identity() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());

    let first = queue(&mut coordinator, &case, origin, xor_task(vec![1, 2], 0))?;
    assert_eq!(
        coordinator.enqueue(&case, origin, xor_task(vec![1, 2, 1, 2], 0))?,
        EnqueueOutcome::Merged(first)
    );
    assert_eq!(
        coordinator.enqueue(&case, origin, xor_task(vec![1, 2, 1, 2], 2))?,
        EnqueueOutcome::Merged(first)
    );

    let rotated = queue(&mut coordinator, &case, origin, xor_task(vec![1, 2, 3], 1))?;
    assert_eq!(
        coordinator.enqueue(&case, origin, xor_task(vec![2, 3, 1], 0))?,
        EnqueueOutcome::Merged(rotated)
    );

    let shifted = queue(&mut coordinator, &case, origin, xor_task(vec![1, 2], 1))?;
    let longer_primitive = queue(&mut coordinator, &case, origin, xor_task(vec![1, 2, 1], 0))?;

    assert_ne!(first, shifted);
    assert_ne!(first, longer_primitive);
    assert_eq!(coordinator.candidate_count(), 4);
    assert_eq!(
        candidate(&coordinator, first)?.task(),
        &xor_task(vec![1, 2], 0)
    );

    Ok(())
}

#[test]
fn repeating_xor_equivalent_cycle_representation_is_suppressed() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_input = node(&mut case, b"same bytes")?;
    let root_receipt = node(&mut case, b"receipt")?;
    let child_input = node(&mut case, b"same bytes")?;
    derived_link(&mut case, root_receipt, root_input)?;
    derived_link(&mut case, child_input, root_receipt)?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let root = queue(
        &mut coordinator,
        &case,
        root_input,
        transform(Operation::XorRepeat {
            key: vec![1, 2],
            offset: 0,
        }),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(root)));
    coordinator.finish(
        &case,
        root,
        RecoveryResult::Derived {
            evidence_node_id: root_receipt,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(
            root,
            &case,
            &[child_input],
            transform(Operation::XorRepeat {
                key: vec![1, 2, 1, 2],
                offset: 0,
            }),
        )?,
        EnqueueOutcome::CycleSkipped { candidate_id: root }
    );
    assert_eq!(coordinator.candidate_count(), 1);

    Ok(())
}

#[test]
fn distinct_parameters_stay_separate() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::RotateBits { count: 1 }),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::RotateBits { count: 2 }),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::XorRepeat {
            key: vec![1, 2, 3, 4],
            offset: 1,
        }),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::XorRepeat {
            key: vec![1, 2, 3, 4],
            offset: 2,
        }),
    )?;

    assert_eq!(coordinator.candidate_count(), 4);

    Ok(())
}

#[test]
fn step_order_stays_exact() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let second = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::RotateBits { count: 1 }, Operation::Reverse {}],
        constraints: Vec::new(),
    });
    let third = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}, Operation::RotateBits { count: 1 }],
        constraints: Vec::new(),
    });
    let mut coordinator = RecoveryCoordinator::new(policy());

    queue(&mut coordinator, &case, origin, second)?;
    queue(&mut coordinator, &case, origin, third)?;

    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn constraint_order_stays_exact() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let first = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Length { bytes: 10 }, Constraint::Utf8 {}],
    });
    let second = RecoveryTask::Transform(Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Utf8 {}, Constraint::Length { bytes: 10 }],
    });
    let mut coordinator = RecoveryCoordinator::new(policy());

    queue(&mut coordinator, &case, origin, first)?;
    queue(&mut coordinator, &case, origin, second)?;

    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn empty_xor_keys_do_not_panic() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());

    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::XorRepeat {
            key: Vec::new(),
            offset: 0,
        }),
    )?;
    queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::XorRepeat {
            key: Vec::new(),
            offset: 1,
        }),
    )?;

    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn mapped_origins_keep_tasks_separate() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let backing = b"same bytes|same bytes";
    let source = case.add_source(
        "mapped.bin",
        "file",
        u64::try_from(backing.len())?,
        &l2_workbench::sha256(backing),
        None,
    )?;
    let first = case.add_bytes_node(
        "mapped_input",
        b"same bytes",
        vec![SourceRange {
            source: source.clone(),
            packet: None,
            offset: 0,
            length: 10,
        }],
        serde_json::json!({}),
    )?;
    let second = case.add_bytes_node(
        "mapped_input",
        b"same bytes",
        vec![SourceRange {
            source,
            packet: None,
            offset: 11,
            length: 10,
        }],
        serde_json::json!({}),
    )?;
    let tasks = [
        RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 }),
        RecoveryTask::AssembleRecords(record_schema(1)),
    ];

    for task in tasks {
        let mut coordinator = RecoveryCoordinator::new(policy());
        queue(&mut coordinator, &case, first, task.clone())?;

        assert!(matches!(
            coordinator.enqueue(&case, second, task)?,
            EnqueueOutcome::Queued(_)
        ));
        assert_eq!(coordinator.candidate_count(), 2);
    }

    Ok(())
}

#[test]
fn selected_input_operand_steps_and_constraints_keep_origin_context() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let (first, second) = mapped_duplicate_nodes(&mut case)?;
    let selected = OperandRef::SelectedInputRange {
        offset: 0,
        length: 4,
    };
    let mut step_coordinator = RecoveryCoordinator::new(policy());
    queue(
        &mut step_coordinator,
        &case,
        first,
        transform(sha256_xor(selected.clone())),
    )?;
    assert!(matches!(
        step_coordinator.enqueue(&case, second, transform(sha256_xor(selected.clone())),)?,
        EnqueueOutcome::Queued(_)
    ));
    assert_eq!(step_coordinator.candidate_count(), 2);

    let constraint_recipe = |key| {
        RecoveryTask::Transform(Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: vec![Constraint::AesGcm {
                key,
                nonce: vec![0; 12].into(),
                associated_data: Vec::new().into(),
            }],
        })
    };
    let mut constraint_coordinator = RecoveryCoordinator::new(policy());
    queue(
        &mut constraint_coordinator,
        &case,
        first,
        constraint_recipe(selected.clone()),
    )?;
    assert!(matches!(
        constraint_coordinator.enqueue(&case, second, constraint_recipe(selected),)?,
        EnqueueOutcome::Queued(_)
    ));
    assert_eq!(constraint_coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn literal_and_fixed_node_operands_merge_across_origins() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let (first, second) = mapped_duplicate_nodes(&mut case)?;
    let mut literal_coordinator = RecoveryCoordinator::new(policy());
    let literal_recipe = || transform(sha256_xor(b"seed".to_vec().into()));
    let literal_candidate = queue(&mut literal_coordinator, &case, first, literal_recipe())?;
    assert_eq!(
        literal_coordinator.enqueue(&case, second, literal_recipe())?,
        EnqueueOutcome::Merged(literal_candidate)
    );

    let fixed_node_recipe = || {
        transform(sha256_xor(OperandRef::NodeRange {
            node_id: first,
            offset: 0,
            length: 4,
        }))
    };
    let fixed_node_candidate = queue(&mut literal_coordinator, &case, first, fixed_node_recipe())?;
    assert_eq!(
        literal_coordinator.enqueue(&case, second, fixed_node_recipe())?,
        EnqueueOutcome::Merged(fixed_node_candidate)
    );
    assert_eq!(literal_coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn input_order_changes_identity() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first")?;
    let second = node(&mut case, b"second")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let ordered = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::FramingDiscovery,
    )?;
    let reversed = queue_nodes(
        &mut coordinator,
        &case,
        &[second, first],
        RecoveryTask::FramingDiscovery,
    )?;

    assert_ne!(ordered, reversed);
    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn framing_rules_change_identity() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 2 }),
    )?;
    let second = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: 3 }),
    )?;

    assert_ne!(first, second);
    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn record_schemas_change_identity() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"same bytes")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::AssembleRecords(record_schema(1)),
    )?;
    let second = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::AssembleRecords(record_schema(2)),
    )?;

    assert_ne!(first, second);
    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn repeated_inputs_keep_positions() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same message")?;
    let second = node(&mut case, b"same message")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::RecordDiscovery,
    )?;

    let candidate = candidate(&coordinator, id)?;
    assert_eq!(candidate.inputs().len(), 2);
    let [first_input, second_input] = candidate.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_input.blob_id(), second_input.blob_id());
    assert_eq!(first_input.origin_node_ids(), &[first]);
    assert_eq!(second_input.origin_node_ids(), &[second]);
    assert_eq!(coordinator.input_blobs(&case, id)?.len(), 2);

    Ok(())
}

#[test]
fn batch_origins_merge_by_position() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first message")?;
    let second = node(&mut case, b"second message")?;
    let first_origin = node(&mut case, b"first message")?;
    let second_origin = node(&mut case, b"second message")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::EmbeddedDiscovery,
    )?;

    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[first_origin, second_origin],
            RecoveryTask::EmbeddedDiscovery,
        )?,
        EnqueueOutcome::Merged(id)
    );
    let candidate = candidate(&coordinator, id)?;
    let [first_input, second_input] = candidate.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_input.origin_node_ids(), &[first, first_origin]);
    assert_eq!(second_input.origin_node_ids(), &[second, second_origin]);

    Ok(())
}

#[test]
fn discovery_contexts_stay_distinct() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same sample")?;
    let second = node(&mut case, b"same sample")?;
    let mut coordinator = RecoveryCoordinator::new(policy());

    let framing_first = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::FramingDiscovery,
    )?;
    let framing_second = queue(
        &mut coordinator,
        &case,
        second,
        RecoveryTask::FramingDiscovery,
    )?;
    let records_first = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::RecordDiscovery,
    )?;
    let records_second = queue(
        &mut coordinator,
        &case,
        second,
        RecoveryTask::RecordDiscovery,
    )?;

    assert_ne!(framing_first, framing_second);
    assert_ne!(records_first, records_second);
    assert_eq!(
        coordinator.enqueue(&case, first, RecoveryTask::FramingDiscovery)?,
        EnqueueOutcome::Merged(framing_first)
    );
    assert_eq!(
        coordinator.enqueue(&case, second, RecoveryTask::RecordDiscovery)?,
        EnqueueOutcome::Merged(records_second)
    );
    let transform_first = queue(
        &mut coordinator,
        &case,
        first,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(
        coordinator.enqueue(&case, second, transform(Operation::Reverse {}))?,
        EnqueueOutcome::Merged(transform_first)
    );
    assert_eq!(coordinator.candidate_count(), 5);

    Ok(())
}

#[test]
fn per_input_budget_is_typed() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"three")?;
    let mut resources = policy();
    resources.max_input_bytes_per_item = 2;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.enqueue(&case, origin, RecoveryTask::EmbeddedDiscovery),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputBytesPerItem,
            limit: 2,
            used: 0,
            requested: 5,
        })
    );

    Ok(())
}

#[test]
fn input_count_budget_is_typed() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first")?;
    let second = node(&mut case, b"second")?;
    let mut resources = policy();
    resources.max_inputs_per_candidate = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[first, second], RecoveryTask::RecordDiscovery,),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputCount,
            limit: 1,
            used: 0,
            requested: 2,
        })
    );

    Ok(())
}

#[test]
fn aggregate_input_budget_is_typed() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"123")?;
    let second = node(&mut case, b"456")?;
    let mut resources = policy();
    resources.max_input_bytes_per_item = 8;
    resources.max_total_input_bytes_per_candidate = 5;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[first, second], RecoveryTask::RecordDiscovery,),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::TotalInputBytes,
            limit: 5,
            used: 3,
            requested: 3,
        })
    );

    Ok(())
}

#[test]
fn empty_batches_are_rejected() {
    let case = Case::new();
    let mut coordinator = RecoveryCoordinator::new(policy());

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[], RecoveryTask::RecursiveExpansion),
        Err(RecoveryError::EmptyInputBatch)
    );
}

#[test]
fn roots_start_at_zero() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"root")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        RecoveryTask::RecordDiscovery,
    )?;

    assert_eq!(
        coordinator.candidate(id).map(RecoveryCandidate::depth),
        Some(0)
    );

    Ok(())
}

#[test]
fn derived_depth_increments() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_node = node(&mut case, b"root")?;
    let parent_output = node(&mut case, b"parent output")?;
    let derived_node = node(&mut case, b"derived")?;
    derived_link(&mut case, parent_output, root_node)?;
    derived_link(&mut case, derived_node, parent_output)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let root = queue(
        &mut coordinator,
        &case,
        root_node,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(root)));
    coordinator.finish(
        &case,
        root,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;
    let derived = queued_id(coordinator.enqueue_derived(
        root,
        &case,
        &[derived_node],
        RecoveryTask::RecordDiscovery,
    )?)?;

    assert_eq!(
        coordinator.candidate(derived).map(RecoveryCandidate::depth),
        Some(1)
    );

    Ok(())
}

#[test]
fn derived_batches_keep_positions_and_parents() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_input = node(&mut case, b"first parent")?;
    let first_receipt = node(&mut case, b"first receipt")?;
    let first_child = node(&mut case, b"first child")?;
    let second_input = node(&mut case, b"second parent")?;
    let second_receipt = node(&mut case, b"second receipt")?;
    let second_child = node(&mut case, b"second child")?;
    derived_link(&mut case, first_receipt, first_input)?;
    derived_link(&mut case, first_child, first_receipt)?;
    derived_link(&mut case, second_receipt, second_input)?;
    derived_link(&mut case, second_child, second_receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first_parent = queue(
        &mut coordinator,
        &case,
        first_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    let second_parent = queue(
        &mut coordinator,
        &case,
        second_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(first_parent)));
    coordinator.finish(
        &case,
        first_parent,
        RecoveryResult::Derived {
            evidence_node_id: first_receipt,
        },
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(second_parent)));
    coordinator.finish(
        &case,
        second_parent,
        RecoveryResult::Derived {
            evidence_node_id: second_receipt,
        },
    )?;

    let batch = queued_id(coordinator.enqueue_derived_many(
        &case,
        &[
            (first_parent, first_child),
            (second_parent, second_child),
            (first_parent, first_child),
        ],
        RecoveryTask::RecordDiscovery,
    )?)?;

    let batch_candidate = candidate(&coordinator, batch)?;
    let [first, second, repeated] = batch_candidate.inputs() else {
        return Err(std::io::Error::other("expected three ordered batch inputs").into());
    };
    assert_eq!(first.origin_node_ids(), &[first_child]);
    assert_eq!(second.origin_node_ids(), &[second_child]);
    assert_eq!(repeated.origin_node_ids(), &[first_child]);
    assert_eq!(batch_candidate.parent_ids(), &[first_parent, second_parent]);
    assert_eq!(batch_candidate.depth(), 1);
    Ok(())
}

#[test]
fn derived_batch_rejects_mismatched_depths() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_input = node(&mut case, b"first parent")?;
    let first_receipt = node(&mut case, b"first receipt")?;
    let first_child = node(&mut case, b"first child")?;
    let second_root_input = node(&mut case, b"second root")?;
    let second_root_receipt = node(&mut case, b"second root receipt")?;
    let second_input = node(&mut case, b"second parent")?;
    let second_receipt = node(&mut case, b"second receipt")?;
    let second_child = node(&mut case, b"second child")?;
    derived_link(&mut case, first_receipt, first_input)?;
    derived_link(&mut case, first_child, first_receipt)?;
    derived_link(&mut case, second_root_receipt, second_root_input)?;
    derived_link(&mut case, second_input, second_root_receipt)?;
    derived_link(&mut case, second_receipt, second_input)?;
    derived_link(&mut case, second_child, second_receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first_parent = queue(
        &mut coordinator,
        &case,
        first_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    let second_root = queue(
        &mut coordinator,
        &case,
        second_root_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(first_parent)));
    coordinator.finish(
        &case,
        first_parent,
        RecoveryResult::Derived {
            evidence_node_id: first_receipt,
        },
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(second_root)));
    coordinator.finish(
        &case,
        second_root,
        RecoveryResult::Derived {
            evidence_node_id: second_root_receipt,
        },
    )?;
    let second_parent = queued_id(coordinator.enqueue_derived(
        second_root,
        &case,
        &[second_input],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(second_parent)));
    coordinator.finish(
        &case,
        second_parent,
        RecoveryResult::Derived {
            evidence_node_id: second_receipt,
        },
    )?;
    let candidate_count = coordinator.candidate_count();

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Err(RecoveryError::ParentDepthMismatch {
            first: 0,
            second: 1,
        })
    );
    assert_eq!(coordinator.candidate_count(), candidate_count);
    assert_eq!(coordinator.pop_next(), Ok(None));
    Ok(())
}

#[test]
fn derived_batch_requires_every_parent() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_input = node(&mut case, b"first parent")?;
    let first_receipt = node(&mut case, b"first receipt")?;
    let first_child = node(&mut case, b"first child")?;
    let second_input = node(&mut case, b"second parent")?;
    let second_child = node(&mut case, b"second child")?;
    derived_link(&mut case, first_receipt, first_input)?;
    derived_link(&mut case, first_child, first_receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first_parent = queue(
        &mut coordinator,
        &case,
        first_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    let second_parent = queue(
        &mut coordinator,
        &case,
        second_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(first_parent)));
    coordinator.finish(
        &case,
        first_parent,
        RecoveryResult::Derived {
            evidence_node_id: first_receipt,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Err(RecoveryError::ParentNotDerived { id: second_parent })
    );
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(coordinator.pop_next(), Ok(Some(second_parent)));
    Ok(())
}

#[test]
fn derived_batch_requires_children() {
    let case = Case::new();
    let mut coordinator = RecoveryCoordinator::new(policy());

    assert_eq!(
        coordinator.enqueue_derived_many(&case, &[], RecoveryTask::RecordDiscovery),
        Err(RecoveryError::EmptyInputBatch)
    );
    assert_eq!(coordinator.candidate_count(), 0);
}

#[test]
fn derived_batch_count_budget_precedes_parent_checks() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_input = node(&mut case, b"first")?;
    let first_child = node(&mut case, b"first child")?;
    let second_input = node(&mut case, b"second")?;
    let second_child = node(&mut case, b"second child")?;
    let mut resources = policy();
    resources.max_inputs_per_candidate = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let first_parent = queue(
        &mut coordinator,
        &case,
        first_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    let second_parent = queue(
        &mut coordinator,
        &case,
        second_input,
        RecoveryTask::RecursiveExpansion,
    )?;

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputCount,
            limit: 1,
            used: 0,
            requested: 2,
        })
    );
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(coordinator.pop_next(), Ok(Some(first_parent)));
    Ok(())
}

#[test]
fn derived_batch_rejects_unlinked_child() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut coordinator = RecoveryCoordinator::new(policy());
    let (first_parent, first_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent 1",
        b"receipt 1",
        b"child 1",
    )?;
    let (second_parent, _) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent 2",
        b"receipt 2",
        b"child 2",
    )?;
    let unlinked_child = node(&mut case, b"unlinked child")?;

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, unlinked_child),],
            RecoveryTask::RecordDiscovery,
        ),
        Err(RecoveryError::UnlinkedDerivedInput {
            parent_candidate_id: second_parent,
            child_node_id: unlinked_child,
        })
    );
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(coordinator.pop_next(), Ok(None));
    Ok(())
}

#[test]
fn derived_batch_limits_fail_atomically() -> Result<(), Box<dyn Error>> {
    let mut resources = policy();
    resources.max_inputs_per_candidate = 1;
    assert_batch_budget(
        resources,
        b"a",
        b"b",
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputCount,
            limit: 1,
            used: 0,
            requested: 2,
        },
    )?;

    let mut resources = policy();
    resources.max_total_input_bytes_per_candidate = 5;
    assert_batch_budget(
        resources,
        b"123",
        b"456",
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::TotalInputBytes,
            limit: 5,
            used: 3,
            requested: 3,
        },
    )?;

    let mut resources = policy();
    resources.max_origins_per_candidate = 1;
    assert_batch_budget(
        resources,
        b"a",
        b"b",
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::OriginCount,
            limit: 1,
            used: 0,
            requested: 2,
        },
    )?;

    let mut resources = policy();
    resources.max_depth = 0;
    assert_batch_budget(
        resources,
        b"a",
        b"b",
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::RecursionDepth,
            limit: 0,
            used: 0,
            requested: 1,
        },
    )?;

    let mut resources = policy();
    resources.max_candidates = 2;
    assert_batch_budget(
        resources,
        b"a",
        b"b",
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateCount,
            limit: 2,
            used: 2,
            requested: 1,
        },
    )?;
    Ok(())
}

#[test]
fn derived_batch_frontier_limit_is_atomic() -> Result<(), Box<dyn Error>> {
    let mut resources = policy();
    resources.max_frontier = 1;
    let (mut case, mut coordinator, parents) = two_parent_fixture(resources, b"a", b"b")?;
    let [(first_parent, first_child), (second_parent, second_child)] = parents;
    let first_pending = node(&mut case, b"pending first")?;
    let pending_id = queue(
        &mut coordinator,
        &case,
        first_pending,
        RecoveryTask::EmbeddedDiscovery,
    )?;
    let count_before = coordinator.candidate_count();

    assert_eq!(
        coordinator.enqueue_derived_many(
            &case,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::FrontierCount,
            limit: 1,
            used: 1,
            requested: 1,
        })
    );
    assert_eq!(coordinator.candidate_count(), count_before);
    assert_eq!(coordinator.pop_next(), Ok(Some(pending_id)));
    Ok(())
}

#[test]
fn derived_batch_rejects_case_switch() -> Result<(), Box<dyn Error>> {
    let (_, mut coordinator, parents) = two_parent_fixture(policy(), b"a", b"b")?;
    let [(first_parent, first_child), (second_parent, second_child)] = parents;
    let replacement = Case::new();

    assert_eq!(
        coordinator.enqueue_derived_many(
            &replacement,
            &[(first_parent, first_child), (second_parent, second_child)],
            RecoveryTask::RecordDiscovery,
        ),
        Err(RecoveryError::DifferentCase)
    );
    assert_eq!(coordinator.candidate_count(), 2);
    Ok(())
}

fn finish_derived_candidate(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    candidate: RecoveryCandidateId,
    evidence_node_id: u64,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(coordinator.pop_next(), Ok(Some(candidate)));
    coordinator.finish(
        case,
        candidate,
        RecoveryResult::Derived { evidence_node_id },
    )?;
    Ok(())
}

#[test]
fn derived_batch_preserves_clean_cycle_path() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let ancestor_first = node(&mut case, b"target first")?;
    let ancestor_second = node(&mut case, b"target second")?;
    let ancestor_receipt = node(&mut case, b"ancestor receipt")?;
    let cyclic_parent_input = node(&mut case, b"cyclic parent")?;
    let cyclic_parent_receipt = node(&mut case, b"cyclic parent receipt")?;
    let clean_root_input = node(&mut case, b"clean root")?;
    let clean_root_receipt = node(&mut case, b"clean root receipt")?;
    let clean_parent_input = node(&mut case, b"clean parent")?;
    let clean_parent_receipt = node(&mut case, b"clean parent receipt")?;
    let cycle_child = node(&mut case, b"target first")?;
    let clean_child = node(&mut case, b"target second")?;
    derived_link(&mut case, ancestor_receipt, ancestor_first)?;
    derived_link(&mut case, ancestor_receipt, ancestor_second)?;
    derived_link(&mut case, cyclic_parent_input, ancestor_receipt)?;
    derived_link(&mut case, cyclic_parent_receipt, cyclic_parent_input)?;
    derived_link(&mut case, clean_root_receipt, clean_root_input)?;
    derived_link(&mut case, clean_parent_input, clean_root_receipt)?;
    derived_link(&mut case, clean_parent_receipt, clean_parent_input)?;
    derived_link(&mut case, cycle_child, cyclic_parent_receipt)?;
    derived_link(&mut case, clean_child, clean_parent_receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let matching_ancestor = queued_id(coordinator.enqueue_nodes(
        &case,
        &[ancestor_first, ancestor_second],
        transform(Operation::Reverse {}),
    )?)?;
    finish_derived_candidate(&mut coordinator, &case, matching_ancestor, ancestor_receipt)?;
    let cyclic_parent = queued_id(coordinator.enqueue_derived(
        matching_ancestor,
        &case,
        &[cyclic_parent_input],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    finish_derived_candidate(
        &mut coordinator,
        &case,
        cyclic_parent,
        cyclic_parent_receipt,
    )?;
    let clean_root = queue(
        &mut coordinator,
        &case,
        clean_root_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    finish_derived_candidate(&mut coordinator, &case, clean_root, clean_root_receipt)?;
    let clean_parent = queued_id(coordinator.enqueue_derived(
        clean_root,
        &case,
        &[clean_parent_input],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    finish_derived_candidate(&mut coordinator, &case, clean_parent, clean_parent_receipt)?;

    let candidate = queued_id(coordinator.enqueue_derived_many(
        &case,
        &[(cyclic_parent, cycle_child), (clean_parent, clean_child)],
        transform(Operation::Reverse {}),
    )?)?;

    assert_eq!(
        coordinator
            .candidate(candidate)
            .map(RecoveryCandidate::depth),
        Some(2)
    );
    Ok(())
}

#[test]
fn derived_depth_is_bounded() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_node = node(&mut case, b"root")?;
    let parent_output = node(&mut case, b"parent output")?;
    let derived_node = node(&mut case, b"derived")?;
    derived_link(&mut case, parent_output, root_node)?;
    derived_link(&mut case, derived_node, parent_output)?;
    let mut resources = policy();
    resources.max_depth = 0;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let root = queue(
        &mut coordinator,
        &case,
        root_node,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(root)));
    coordinator.finish(
        &case,
        root,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(root, &case, &[derived_node], RecoveryTask::RecordDiscovery,),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::RecursionDepth,
            limit: 0,
            used: 0,
            requested: 1,
        })
    );

    Ok(())
}

#[test]
fn derived_requires_terminal_parent() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let parent_input = node(&mut case, b"parent")?;
    let child_input = node(&mut case, b"child")?;
    derived_link(&mut case, child_input, parent_input)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        parent_input,
        RecoveryTask::RecursiveExpansion,
    )?;

    assert_eq!(
        coordinator.enqueue_derived(parent, &case, &[child_input], RecoveryTask::RecordDiscovery,),
        Err(RecoveryError::ParentNotDerived { id: parent })
    );
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(&case, parent, RecoveryResult::Unsupported)?;
    assert_eq!(
        coordinator.enqueue_derived(parent, &case, &[child_input], RecoveryTask::RecordDiscovery,),
        Err(RecoveryError::ParentNotDerived { id: parent })
    );

    Ok(())
}

#[test]
fn validated_parent_enqueues_exact_bytes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"artifact")?;
    let equivalent_input = node(&mut case, b"artifact")?;
    let validation = node(&mut case, b"validation receipt")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[equivalent_input],
            RecoveryTask::StructuralValidation,
        )?,
        EnqueueOutcome::Merged(parent)
    );
    link(
        &mut case,
        validation,
        input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    link(
        &mut case,
        validation,
        equivalent_input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    edge(
        &mut case,
        input,
        validation,
        "validated_range",
        EvidenceStatus::Observed,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    let child = queued_id(coordinator.enqueue_validated(
        parent,
        &case,
        &[input],
        RecoveryTask::RecursiveExpansion,
    )?)?;

    let child = candidate(&coordinator, child)?;
    assert_eq!(child.depth(), 0);
    assert_eq!(child.parent_ids(), &[parent]);
    let [child_input] = child.inputs() else {
        return Err("validated child must have one input".into());
    };
    assert_eq!(child_input.origin_node_ids(), &[input, equivalent_input]);
    assert_eq!(coordinator.context_aliases_retained(), 4);
    Ok(())
}

#[test]
fn validated_parent_respects_context_alias_budget() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"artifact")?;
    let equivalent_input = node(&mut case, b"artifact")?;
    let validation = node(&mut case, b"validation receipt")?;
    let mut resources = policy();
    resources.max_context_aliases = 3;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let parent = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::StructuralValidation,
    )?;
    let _ = coordinator.enqueue_nodes(
        &case,
        &[equivalent_input],
        RecoveryTask::StructuralValidation,
    )?;
    link(
        &mut case,
        validation,
        input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    link(
        &mut case,
        validation,
        equivalent_input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    edge(
        &mut case,
        input,
        validation,
        "validated_range",
        EvidenceStatus::Observed,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_validated(parent, &case, &[input], RecoveryTask::RecursiveExpansion,)?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ContextAliases,
            limit: 3,
            used: 2,
            requested: 2,
        }
    );
    Ok(())
}

#[test]
fn validated_parent_requires_exact_range_link() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let validation = node(&mut case, b"validation receipt")?;
    let unrelated = node(&mut case, b"unrelated")?;
    link(
        &mut case,
        validation,
        input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_validated(
            parent,
            &case,
            &[unrelated],
            RecoveryTask::RecursiveExpansion,
        ),
        Err(RecoveryError::UnlinkedValidatedInput {
            parent_candidate_id: parent,
            child_node_id: unrelated,
        })
    );
    Ok(())
}

#[test]
fn derived_uses_parent_output() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let parent_input = node(&mut case, b"parent")?;
    let parent_output = node(&mut case, b"parent output")?;
    let child_input = node(&mut case, b"child")?;
    derived_link(&mut case, parent_output, parent_input)?;
    derived_link(&mut case, child_input, parent_input)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        parent_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(parent, &case, &[child_input], RecoveryTask::RecordDiscovery,),
        Err(RecoveryError::UnlinkedDerivedInput {
            parent_candidate_id: parent,
            child_node_id: child_input,
        })
    );

    Ok(())
}

#[test]
fn derived_child_edges_require_contract() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let parent_input = node(&mut case, b"parent")?;
    let parent_output = node(&mut case, b"parent output")?;
    let child_input = node(&mut case, b"child")?;
    derived_link(&mut case, parent_output, parent_input)?;
    edge(
        &mut case,
        child_input,
        parent_output,
        "same_value",
        EvidenceStatus::Observed,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        parent_input,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(parent, &case, &[child_input], RecoveryTask::RecordDiscovery,),
        Err(RecoveryError::UnlinkedDerivedInput {
            parent_candidate_id: parent,
            child_node_id: child_input,
        })
    );

    Ok(())
}

#[test]
fn derived_results_require_bytes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"candidate")?;
    let output = case.add_node("metadata_only", None, Vec::new(), serde_json::json!({}))?;
    derived_link(&mut case, output, input)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        input,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::Derived {
                evidence_node_id: output
            }
        ),
        Err(RecoveryError::InputBlobMissing { node_id: output })
    );

    Ok(())
}

#[test]
fn depth_identity_prevents_suppression() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let parent_node = node(&mut case, b"parent")?;
    let parent_output = node(&mut case, b"parent output")?;
    let deep_input = node(&mut case, b"same content")?;
    let root_input = node(&mut case, b"same content")?;
    derived_link(&mut case, parent_output, parent_node)?;
    derived_link(&mut case, deep_input, parent_output)?;
    let mut resources = policy();
    resources.max_depth = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let parent = queue(
        &mut coordinator,
        &case,
        parent_node,
        RecoveryTask::RecursiveExpansion,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;
    let child = queued_id(coordinator.enqueue_derived(
        parent,
        &case,
        &[deep_input],
        RecoveryTask::RecordDiscovery,
    )?)?;
    assert_eq!(
        coordinator.candidate(child).map(RecoveryCandidate::depth),
        Some(1)
    );
    assert_eq!(coordinator.pop_next(), Ok(Some(child)));
    coordinator.finish(&case, child, RecoveryResult::Unsupported)?;

    let shallow = queue(
        &mut coordinator,
        &case,
        root_input,
        RecoveryTask::RecordDiscovery,
    )?;
    assert_ne!(child, shallow);
    assert_eq!(coordinator.candidate_count(), 3);
    assert_eq!(
        coordinator.candidate(shallow).map(RecoveryCandidate::depth),
        Some(0)
    );
    assert_eq!(coordinator.pop_next(), Ok(Some(shallow)));

    Ok(())
}

#[test]
fn blobless_nodes_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = case.add_node("metadata_only", None, Vec::new(), serde_json::json!({}))?;
    let mut coordinator = RecoveryCoordinator::new(policy());

    assert!(matches!(
        coordinator.enqueue(&case, origin, RecoveryTask::RecordDiscovery),
        Err(RecoveryError::InputBlobMissing { node_id }) if node_id == origin
    ));

    Ok(())
}

#[test]
fn input_limit_reports_exhaustion() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"two")?;
    let mut resources = policy();
    resources.max_input_bytes_per_item = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.enqueue(&case, origin, RecoveryTask::RecordDiscovery),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputBytesPerItem,
            limit: 1,
            used: 0,
            requested: 3,
        })
    );

    Ok(())
}

#[test]
fn observed_validation_finishes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"candidate")?;
    let validation = node(&mut case, b"validated result")?;
    link(
        &mut case,
        validation,
        input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::Derived {
                evidence_node_id: validation
            }
        ),
        Err(RecoveryError::InvalidResultStage)
    );
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::StructuralValidation,
            result: RecoveryResult::ObservedValidation {
                node_id: validation,
            },
        })
    );

    Ok(())
}

#[test]
fn validation_covers_each_input_origin() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first input")?;
    let second = node(&mut case, b"second input")?;
    let validation = node(&mut case, b"validated output")?;
    link(
        &mut case,
        validation,
        first,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::ObservedValidation {
                node_id: validation,
            },
        ),
        Err(RecoveryError::UnlinkedResultEvidence {
            candidate_id: id,
            evidence_node_id: validation,
            origin_node_id: second,
        })
    );
    link(
        &mut case,
        validation,
        second,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    Ok(())
}

#[test]
fn validation_covers_merged_origins() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first input")?;
    let second = node(&mut case, b"second input")?;
    let first_alias = node(&mut case, b"first input")?;
    let second_alias = node(&mut case, b"second input")?;
    let validation = node(&mut case, b"validated output")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[first_alias, second_alias],
            RecoveryTask::StructuralValidation,
        )?,
        EnqueueOutcome::Merged(id)
    );
    for origin in [first, second] {
        link(
            &mut case,
            validation,
            origin,
            EvidenceStatus::ConstraintSatisfied,
        )?;
    }
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::ObservedValidation {
                node_id: validation,
            },
        ),
        Err(RecoveryError::UnlinkedResultEvidence {
            candidate_id: id,
            evidence_node_id: validation,
            origin_node_id: first_alias,
        })
    );
    for origin in [first_alias, second_alias] {
        link(
            &mut case,
            validation,
            origin,
            EvidenceStatus::ConstraintSatisfied,
        )?;
    }
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    Ok(())
}

#[test]
fn unlinked_result_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"candidate")?;
    let validation = node(&mut case, b"unrelated validation")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.finish(
            &case,
            id,
            RecoveryResult::ObservedValidation {
                node_id: validation
            }
        ),
        Err(RecoveryError::UnlinkedResultEvidence {
            candidate_id: id,
            evidence_node_id: validation,
            origin_node_id: input,
        })
    );
    assert_eq!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Running(
            RecoveryStage::StructuralValidation
        ))
    );

    Ok(())
}

#[test]
fn hypothesis_requires_origin_link() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"record candidate")?;
    let hypothesis = node(&mut case, b"record schema hypothesis")?;
    link(&mut case, hypothesis, input, EvidenceStatus::Hypothesis)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        input,
        RecoveryTask::RecordDiscovery,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    coordinator.finish(
        &case,
        id,
        RecoveryResult::Hypothesis {
            node_id: hypothesis,
        },
    )?;
    assert!(matches!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            stage: RecoveryStage::RecordDiscovery,
            result: RecoveryResult::Hypothesis { node_id },
        }) if *node_id == hypothesis
    ));

    Ok(())
}

#[test]
fn transform_discovery_keeps_origins_separate_and_cannot_produce_child_work()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_origin = node(&mut case, b"same discovery input")?;
    let second_origin = node(&mut case, b"same discovery input")?;
    let hypothesis = node(&mut case, b"proposal report")?;
    link(
        &mut case,
        hypothesis,
        first_origin,
        EvidenceStatus::Hypothesis,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queue(
        &mut coordinator,
        &case,
        first_origin,
        RecoveryTask::TransformDiscovery,
    )?;
    let second = queue(
        &mut coordinator,
        &case,
        second_origin,
        RecoveryTask::TransformDiscovery,
    )?;
    assert_ne!(first, second);
    assert_eq!(coordinator.pop_next(), Ok(Some(first)));
    coordinator.finish(
        &case,
        first,
        RecoveryResult::Hypothesis {
            node_id: hypothesis,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(
            first,
            &case,
            &[first_origin],
            RecoveryTask::transform(Operation::Reverse {}),
        ),
        Err(RecoveryError::ParentNotDerived { id: first })
    );
    Ok(())
}

fn assert_unlinked(
    case: &Case,
    input: u64,
    result_node: u64,
    task: RecoveryTask,
    result: RecoveryResult,
) -> Result<(), Box<dyn Error>> {
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(&mut coordinator, case, input, task)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    assert_eq!(
        coordinator.finish(case, id, result),
        Err(RecoveryError::UnlinkedResultEvidence {
            candidate_id: id,
            evidence_node_id: result_node,
            origin_node_id: input,
        })
    );
    Ok(())
}

#[test]
fn result_edges_require_contracts() -> Result<(), Box<dyn Error>> {
    let mut observed_case = Case::new();
    let observed_input = node(&mut observed_case, b"observed input")?;
    let observed = node(&mut observed_case, b"observed result")?;
    edge(
        &mut observed_case,
        observed_input,
        observed,
        "recovery_result",
        EvidenceStatus::ConstraintSatisfied,
    )?;
    assert_unlinked(
        &observed_case,
        observed_input,
        observed,
        RecoveryTask::StructuralValidation,
        RecoveryResult::ObservedValidation { node_id: observed },
    )?;

    let mut derived_case = Case::new();
    let derived_input = node(&mut derived_case, b"derived input")?;
    let derived = node(&mut derived_case, b"derived result")?;
    edge(
        &mut derived_case,
        derived,
        derived_input,
        "recovery_result",
        EvidenceStatus::Observed,
    )?;
    assert_unlinked(
        &derived_case,
        derived_input,
        derived,
        transform(Operation::Reverse {}),
        RecoveryResult::Derived {
            evidence_node_id: derived,
        },
    )?;

    let mut hypothesis_case = Case::new();
    let hypothesis_input = node(&mut hypothesis_case, b"hypothesis input")?;
    let hypothesis = node(&mut hypothesis_case, b"hypothesis result")?;
    edge(
        &mut hypothesis_case,
        hypothesis_input,
        hypothesis,
        "recovery_result",
        EvidenceStatus::Hypothesis,
    )?;
    assert_unlinked(
        &hypothesis_case,
        hypothesis_input,
        hypothesis,
        RecoveryTask::RecordDiscovery,
        RecoveryResult::Hypothesis {
            node_id: hypothesis,
        },
    )?;

    let mut rejected_case = Case::new();
    let rejected_input = node(&mut rejected_case, b"rejected input")?;
    let rejected = node(&mut rejected_case, b"rejected result")?;
    edge(
        &mut rejected_case,
        rejected,
        rejected_input,
        "recovery_result",
        EvidenceStatus::Observed,
    )?;
    assert_unlinked(
        &rejected_case,
        rejected_input,
        rejected,
        RecoveryTask::RecordDiscovery,
        RecoveryResult::Rejected { node_id: rejected },
    )?;

    Ok(())
}

#[test]
fn derived_results_keep_late_context() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same transform input")?;
    let later = node(&mut case, b"same transform input")?;
    let output = node(&mut case, b"transformed output")?;
    derived_link(&mut case, output, first)?;
    let mut resources = policy();
    resources.max_candidates = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue(
        &mut coordinator,
        &case,
        first,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    coordinator.finish(
        &case,
        id,
        RecoveryResult::Derived {
            evidence_node_id: output,
        },
    )?;
    assert_eq!(
        coordinator.enqueue(&case, later, transform(Operation::Reverse {}))?,
        EnqueueOutcome::MergedNeedsContext(id)
    );
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Pending { origins: 1 })
    );

    derived_link(&mut case, output, later)?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Complete)
    );
    assert_eq!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::Transform,
            result: RecoveryResult::Derived {
                evidence_node_id: output
            },
        })
    );
    Ok(())
}

#[test]
fn reversible_cycles_stop_early() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_input = node(&mut case, b"abc")?;
    let root_receipt = node(&mut case, b"root receipt")?;
    let first_input = node(&mut case, b"cba")?;
    let child_receipt = node(&mut case, b"child receipt")?;
    let cycle_input = node(&mut case, b"abc")?;
    derived_link(&mut case, root_receipt, root_input)?;
    derived_link(&mut case, first_input, root_receipt)?;
    derived_link(&mut case, child_receipt, first_input)?;
    derived_link(&mut case, cycle_input, child_receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let root = queue(
        &mut coordinator,
        &case,
        root_input,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(root)));
    coordinator.finish(
        &case,
        root,
        RecoveryResult::Derived {
            evidence_node_id: root_receipt,
        },
    )?;

    let reverse_child = queued_id(coordinator.enqueue_derived(
        root,
        &case,
        &[first_input],
        transform(Operation::Reverse {}),
    )?)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(reverse_child)));
    coordinator.finish(
        &case,
        reverse_child,
        RecoveryResult::Derived {
            evidence_node_id: child_receipt,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(
            reverse_child,
            &case,
            &[cycle_input],
            transform(Operation::Reverse {}),
        ),
        Ok(EnqueueOutcome::CycleSkipped { candidate_id: root })
    );
    assert_eq!(coordinator.lineage_work_charged(), 8);
    assert!(coordinator.remaining_lineage_work() > 0);
    assert_eq!(coordinator.candidate_count(), 2);
    assert_eq!(
        coordinator
            .candidate(root)
            .map(RecoveryCandidate::pending_origin_node_ids),
        Some(&[cycle_input][..])
    );
    assert!(matches!(
        coordinator.candidate(root).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::ContextPending {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        }) if *evidence_node_id == root_receipt
    ));

    derived_link(&mut case, root_receipt, cycle_input)?;
    assert_eq!(
        coordinator.refresh_context(&case, root),
        Ok(ContextRegistration::Complete)
    );
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

#[test]
fn validated_same_depth_lineage_keeps_cycle_analysis_topological() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let validation_input = node(&mut case, b"same bytes")?;
    let validation_receipt = node(&mut case, b"validation receipt")?;
    let validated_child = node(&mut case, b"same bytes")?;
    let transform_receipt = node(&mut case, b"transform receipt")?;
    let cycle_child = node(&mut case, b"same bytes")?;

    link(
        &mut case,
        validation_receipt,
        validation_input,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    edge(
        &mut case,
        validated_child,
        validation_receipt,
        "validated_range",
        EvidenceStatus::Observed,
    )?;
    derived_link(&mut case, transform_receipt, validation_input)?;
    derived_link(&mut case, transform_receipt, validated_child)?;
    derived_link(&mut case, cycle_child, transform_receipt)?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let validated_root = queue(
        &mut coordinator,
        &case,
        validation_input,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(validated_root)));
    coordinator.finish(
        &case,
        validated_root,
        RecoveryResult::ObservedValidation {
            node_id: validation_receipt,
        },
    )?;

    let same_depth_child = queued_id(coordinator.enqueue_validated(
        validated_root,
        &case,
        &[validated_child],
        transform(Operation::Reverse {}),
    )?)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(same_depth_child)));
    coordinator.finish(
        &case,
        same_depth_child,
        RecoveryResult::Derived {
            evidence_node_id: transform_receipt,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(
            same_depth_child,
            &case,
            &[cycle_child],
            RecoveryTask::StructuralValidation,
        ),
        Ok(EnqueueOutcome::CycleSkipped {
            candidate_id: validated_root,
        })
    );
    assert_eq!(coordinator.candidate_count(), 2);

    Ok(())
}

#[test]
fn merged_validated_parents_keep_cycle_analysis_topological() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_input = node(&mut case, b"root")?;
    let root_validation = node(&mut case, b"root validation")?;
    let validated_input = node(&mut case, b"validated")?;
    let child_receipt = node(&mut case, b"child receipt")?;
    let second_root_input = node(&mut case, b"second root")?;
    let second_root_validation = node(&mut case, b"second root validation")?;
    let child_output = node(&mut case, b"child output")?;
    let descendant_receipt = node(&mut case, b"descendant receipt")?;
    let cycle_input = node(&mut case, b"root")?;

    validation_link(&mut case, root_validation, root_input, validated_input)?;
    derived_link(&mut case, child_receipt, validated_input)?;
    validation_link(
        &mut case,
        second_root_validation,
        second_root_input,
        validated_input,
    )?;
    derived_link(&mut case, child_output, child_receipt)?;
    derived_link(&mut case, descendant_receipt, child_output)?;
    derived_link(&mut case, cycle_input, descendant_receipt)?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let root = finish_validation_next(&mut coordinator, &case, root_input, root_validation)?;

    let child = queued_id(coordinator.enqueue_validated(
        root,
        &case,
        &[validated_input],
        transform(Operation::Reverse {}),
    )?)?;
    finish_derived_next(&mut coordinator, &case, child, child_receipt)?;

    let second_root = finish_validation_next(
        &mut coordinator,
        &case,
        second_root_input,
        second_root_validation,
    )?;
    assert_eq!(
        coordinator.enqueue_validated(
            second_root,
            &case,
            &[validated_input],
            transform(Operation::Reverse {}),
        ),
        Ok(EnqueueOutcome::Merged(child))
    );

    let descendant = queued_id(coordinator.enqueue_derived(
        child,
        &case,
        &[child_output],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    finish_derived_next(&mut coordinator, &case, descendant, descendant_receipt)?;

    let cycle_child = queued_id(coordinator.enqueue_derived(
        descendant,
        &case,
        &[cycle_input],
        RecoveryTask::StructuralValidation,
    )?)?;
    assert_eq!(
        coordinator
            .candidate(cycle_child)
            .map(RecoveryCandidate::depth),
        Some(2)
    );

    Ok(())
}

#[test]
fn cyclic_merged_lineage_keeps_clean_alternate_parent() -> Result<(), Box<dyn Error>> {
    let CyclicLineageFixture {
        case,
        root_input,
        root_validation,
        joined_input,
        joined_validation,
        cycle_input,
        cycle_validation,
        alternate_root_input,
        alternate_root_validation,
        derived_receipt,
        descendant_input,
        descendant_receipt,
        repeated_root,
    } = cyclic_lineage_fixture()?;

    let mut coordinator = RecoveryCoordinator::new(policy());
    let root = finish_validation_next(&mut coordinator, &case, root_input, root_validation)?;
    let joined = queued_id(coordinator.enqueue_validated(
        root,
        &case,
        &[joined_input],
        RecoveryTask::StructuralValidation,
    )?)?;
    finish_validation_candidate(&mut coordinator, &case, joined, joined_validation)?;
    let cycle = queued_id(coordinator.enqueue_validated(
        joined,
        &case,
        &[cycle_input],
        RecoveryTask::StructuralValidation,
    )?)?;
    finish_validation_candidate(&mut coordinator, &case, cycle, cycle_validation)?;

    let alternate_root = finish_validation_next(
        &mut coordinator,
        &case,
        alternate_root_input,
        alternate_root_validation,
    )?;
    assert_eq!(
        coordinator.enqueue_validated(
            cycle,
            &case,
            &[joined_input],
            RecoveryTask::StructuralValidation,
        ),
        Ok(EnqueueOutcome::Merged(joined))
    );
    assert_eq!(
        coordinator.enqueue_validated(
            alternate_root,
            &case,
            &[joined_input],
            RecoveryTask::StructuralValidation,
        ),
        Ok(EnqueueOutcome::Merged(joined))
    );

    let transform_child = queued_id(coordinator.enqueue_validated(
        joined,
        &case,
        &[cycle_input],
        transform(Operation::Reverse {}),
    )?)?;
    finish_derived_next(&mut coordinator, &case, transform_child, derived_receipt)?;
    let descendant = queued_id(coordinator.enqueue_derived(
        transform_child,
        &case,
        &[descendant_input],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    finish_derived_next(&mut coordinator, &case, descendant, descendant_receipt)?;

    let child = queued_id(coordinator.enqueue_derived(
        descendant,
        &case,
        &[repeated_root],
        RecoveryTask::StructuralValidation,
    )?)?;
    assert_eq!(
        coordinator.candidate(child).map(RecoveryCandidate::depth),
        Some(2)
    );

    Ok(())
}

struct CyclicLineageFixture {
    case: Case,
    root_input: u64,
    root_validation: u64,
    joined_input: u64,
    joined_validation: u64,
    cycle_input: u64,
    cycle_validation: u64,
    alternate_root_input: u64,
    alternate_root_validation: u64,
    derived_receipt: u64,
    descendant_input: u64,
    descendant_receipt: u64,
    repeated_root: u64,
}

fn cyclic_lineage_fixture() -> Result<CyclicLineageFixture, Box<dyn Error>> {
    let mut case = Case::new();
    let root_input = node(&mut case, b"root")?;
    let root_validation = node(&mut case, b"root validation")?;
    let joined_input = node(&mut case, b"joined")?;
    let joined_validation = node(&mut case, b"joined validation")?;
    let cycle_input = node(&mut case, b"cycle")?;
    let cycle_validation = node(&mut case, b"cycle validation")?;
    let alternate_root_input = node(&mut case, b"alternate root")?;
    let alternate_root_validation = node(&mut case, b"alternate validation")?;
    let derived_receipt = node(&mut case, b"derived receipt")?;
    let descendant_input = node(&mut case, b"descendant")?;
    let descendant_receipt = node(&mut case, b"descendant receipt")?;
    let repeated_root = node(&mut case, b"root")?;

    validation_link(&mut case, root_validation, root_input, joined_input)?;
    validation_link(&mut case, joined_validation, joined_input, cycle_input)?;
    validation_link(&mut case, cycle_validation, cycle_input, joined_input)?;
    validation_link(
        &mut case,
        alternate_root_validation,
        alternate_root_input,
        joined_input,
    )?;
    derived_link(&mut case, derived_receipt, cycle_input)?;
    derived_link(&mut case, descendant_input, derived_receipt)?;
    derived_link(&mut case, descendant_receipt, descendant_input)?;
    derived_link(&mut case, repeated_root, descendant_receipt)?;

    Ok(CyclicLineageFixture {
        case,
        root_input,
        root_validation,
        joined_input,
        joined_validation,
        cycle_input,
        cycle_validation,
        alternate_root_input,
        alternate_root_validation,
        derived_receipt,
        descendant_input,
        descendant_receipt,
        repeated_root,
    })
}

#[test]
fn distinct_tasks_survive_cycles() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let parent_input = node(&mut case, b"same bytes")?;
    let parent_output = node(&mut case, b"same bytes")?;
    let child_input = node(&mut case, b"same bytes")?;
    derived_link(&mut case, parent_output, parent_input)?;
    derived_link(&mut case, child_input, parent_output)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queue(
        &mut coordinator,
        &case,
        parent_input,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(parent)));
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: parent_output,
        },
    )?;

    let child = queued_id(coordinator.enqueue_derived(
        parent,
        &case,
        &[child_input],
        RecoveryTask::Transform(Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: vec![Constraint::Length { bytes: 9 }],
        }),
    )?)?;
    assert_eq!(
        coordinator.candidate(child).map(RecoveryCandidate::depth),
        Some(1)
    );

    Ok(())
}

fn finish_derived_next(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    id: RecoveryCandidateId,
    evidence_node_id: u64,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(case, id, RecoveryResult::Derived { evidence_node_id })?;
    Ok(())
}

fn finish_validation_next(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    input_node_id: u64,
    validation_node_id: u64,
) -> Result<RecoveryCandidateId, Box<dyn Error>> {
    let candidate = queue(
        coordinator,
        case,
        input_node_id,
        RecoveryTask::StructuralValidation,
    )?;
    finish_validation_candidate(coordinator, case, candidate, validation_node_id)?;
    Ok(candidate)
}

fn finish_validation_candidate(
    coordinator: &mut RecoveryCoordinator,
    case: &Case,
    candidate: RecoveryCandidateId,
    validation_node_id: u64,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(coordinator.pop_next(), Ok(Some(candidate)));
    coordinator.finish(
        case,
        candidate,
        RecoveryResult::ObservedValidation {
            node_id: validation_node_id,
        },
    )?;
    Ok(())
}

fn validation_link(
    case: &mut Case,
    validation_node_id: u64,
    input_node_id: u64,
    validated_node_id: u64,
) -> Result<(), Box<dyn Error>> {
    link(
        case,
        validation_node_id,
        input_node_id,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    edge(
        case,
        validated_node_id,
        validation_node_id,
        "validated_range",
        EvidenceStatus::Observed,
    )
}

struct ConvergentLineage {
    case: Case,
    coordinator: RecoveryCoordinator,
    acyclic_parent: RecoveryCandidateId,
    joined: RecoveryCandidateId,
    cyclic_join_input: u64,
    acyclic_join_input: u64,
    cycle_child: u64,
    alternate_parent_input: u64,
    alternate_parent_output: u64,
    alternate_child: u64,
}

fn convergent_lineage() -> Result<ConvergentLineage, Box<dyn Error>> {
    let mut case = Case::new();
    let cyclic_input = node(&mut case, b"loop")?;
    let acyclic_input = node(&mut case, b"00")?;
    let cyclic_output = node(&mut case, b"p")?;
    let acyclic_output = node(&mut case, b"p")?;
    let cyclic_join_input = node(&mut case, b"p")?;
    let acyclic_join_input = node(&mut case, b"p")?;
    let joined_output = node(&mut case, b"joined")?;
    let cycle_child = node(&mut case, b"loop")?;
    let alternate_parent_input = node(&mut case, b"p")?;
    let alternate_parent_output = node(&mut case, b"alternate")?;
    let alternate_child = node(&mut case, b"loop")?;
    for (output, input) in [
        (cyclic_output, cyclic_input),
        (acyclic_output, acyclic_input),
        (cyclic_join_input, cyclic_output),
        (acyclic_join_input, acyclic_output),
        (alternate_parent_input, acyclic_output),
        (joined_output, cyclic_join_input),
        (joined_output, acyclic_join_input),
        (alternate_parent_output, alternate_parent_input),
        (cycle_child, joined_output),
        (alternate_child, alternate_parent_output),
    ] {
        derived_link(&mut case, output, input)?;
    }

    let mut coordinator = RecoveryCoordinator::new(policy());
    let cyclic_parent = queue(
        &mut coordinator,
        &case,
        cyclic_input,
        transform(Operation::Reverse {}),
    )?;
    let acyclic_parent = queue(
        &mut coordinator,
        &case,
        acyclic_input,
        transform(Operation::HexDecode {}),
    )?;
    finish_derived_next(&mut coordinator, &case, cyclic_parent, cyclic_output)?;
    finish_derived_next(&mut coordinator, &case, acyclic_parent, acyclic_output)?;

    let join_task = RecoveryTask::RecursiveExpansion;
    let joined = queued_id(coordinator.enqueue_derived(
        cyclic_parent,
        &case,
        &[cyclic_join_input],
        join_task.clone(),
    )?)?;
    assert_eq!(
        coordinator.enqueue_derived(acyclic_parent, &case, &[acyclic_join_input], join_task,)?,
        EnqueueOutcome::Merged(joined)
    );
    finish_derived_next(&mut coordinator, &case, joined, joined_output)?;

    Ok(ConvergentLineage {
        case,
        coordinator,
        acyclic_parent,
        joined,
        cyclic_join_input,
        acyclic_join_input,
        cycle_child,
        alternate_parent_input,
        alternate_parent_output,
        alternate_child,
    })
}

#[test]
fn convergent_lineages_keep_origins() -> Result<(), Box<dyn Error>> {
    let lineage = convergent_lineage()?;
    let [joined_input] = candidate(&lineage.coordinator, lineage.joined)?.inputs() else {
        return Err(std::io::Error::other("expected one convergent input").into());
    };
    assert_eq!(
        joined_input.origin_node_ids(),
        &[lineage.cyclic_join_input, lineage.acyclic_join_input]
    );

    Ok(())
}

#[test]
fn convergent_lineage_keeps_clean_path() -> Result<(), Box<dyn Error>> {
    let mut lineage = convergent_lineage()?;
    let child = queued_id(lineage.coordinator.enqueue_derived(
        lineage.joined,
        &lineage.case,
        &[lineage.cycle_child],
        transform(Operation::Reverse {}),
    )?)?;
    assert_eq!(
        lineage
            .coordinator
            .candidate(child)
            .map(RecoveryCandidate::depth),
        Some(2)
    );

    Ok(())
}

#[test]
fn same_depth_children_merge() -> Result<(), Box<dyn Error>> {
    let mut lineage = convergent_lineage()?;
    let alternate_parent = queued_id(lineage.coordinator.enqueue_derived(
        lineage.acyclic_parent,
        &lineage.case,
        &[lineage.alternate_parent_input],
        transform(Operation::HexDecode {}),
    )?)?;
    finish_derived_next(
        &mut lineage.coordinator,
        &lineage.case,
        alternate_parent,
        lineage.alternate_parent_output,
    )?;
    let preexisting_child = queued_id(lineage.coordinator.enqueue_derived(
        alternate_parent,
        &lineage.case,
        &[lineage.alternate_child],
        transform(Operation::Reverse {}),
    )?)?;

    assert_eq!(
        lineage.coordinator.enqueue_derived(
            lineage.joined,
            &lineage.case,
            &[lineage.cycle_child],
            transform(Operation::Reverse {}),
        )?,
        EnqueueOutcome::Merged(preexisting_child)
    );
    let [merged_input] = candidate(&lineage.coordinator, preexisting_child)?.inputs() else {
        return Err(std::io::Error::other("expected one converged input").into());
    };
    assert_eq!(
        merged_input.origin_node_ids(),
        &[lineage.alternate_child, lineage.cycle_child]
    );

    Ok(())
}

#[test]
fn rejections_require_failed_links() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same parser input")?;
    let later = node(&mut case, b"same parser input")?;
    let rejection = node(&mut case, b"parser rejection evidence")?;
    link(&mut case, rejection, first, EvidenceStatus::Observed)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        first,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    let result = RecoveryResult::Rejected { node_id: rejection };

    assert_eq!(
        coordinator.finish(&case, id, result.clone()),
        Err(RecoveryError::UnlinkedResultEvidence {
            candidate_id: id,
            evidence_node_id: rejection,
            origin_node_id: first,
        })
    );
    link(
        &mut case,
        rejection,
        first,
        EvidenceStatus::ConstraintFailed,
    )?;
    coordinator.finish(&case, id, result.clone())?;
    assert_eq!(
        coordinator.enqueue(&case, later, transform(Operation::Reverse {}))?,
        EnqueueOutcome::MergedNeedsContext(id)
    );

    link(
        &mut case,
        rejection,
        later,
        EvidenceStatus::ConstraintFailed,
    )?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Complete)
    );
    assert_eq!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(&RecoveryCandidateState::Finished {
            stage: RecoveryStage::Transform,
            result,
        })
    );
    Ok(())
}

#[test]
fn late_origin_needs_registration() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let later = node(&mut case, b"same input")?;
    let validation = node(&mut case, b"validated output")?;
    link(
        &mut case,
        validation,
        first,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.enqueue(&case, later, RecoveryTask::StructuralValidation,)?,
        EnqueueOutcome::MergedNeedsContext(id)
    );
    assert!(matches!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::ContextPending {
            stage: RecoveryStage::StructuralValidation,
            result: RecoveryResult::ObservedValidation {
                node_id,
            }
        }) if *node_id == validation
    ));
    assert_eq!(
        coordinator
            .candidate(id)
            .map(RecoveryCandidate::pending_origin_node_ids),
        Some(&[later][..])
    );
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Pending { origins: 1 })
    );

    link(
        &mut case,
        validation,
        later,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Complete)
    );
    assert!(matches!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            stage: RecoveryStage::StructuralValidation,
            result: RecoveryResult::ObservedValidation {
                node_id,
            }
        }) if *node_id == validation
    ));

    Ok(())
}

#[test]
fn failed_terminal_merge_after_case_rollback_is_atomic() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut coordinator = RecoveryCoordinator::new(policy());
    let (first_parent, first_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"first parent",
        b"first receipt",
        b"same child",
    )?;
    let (second_parent, second_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"second parent",
        b"second receipt",
        b"same child",
    )?;
    let task = RecoveryTask::RecursiveExpansion;
    let child = queued_id(coordinator.enqueue_derived(
        first_parent,
        &case,
        &[first_child],
        task.clone(),
    )?)?;
    assert_eq!(coordinator.pop_next(), Ok(Some(child)));

    let mut rolled_back_result = None;
    let rollback = case.transaction(|case| -> Result<(), Box<dyn Error>> {
        let result = node(case, b"child result")?;
        derived_link(case, result, first_child)?;
        coordinator.finish(
            case,
            child,
            RecoveryResult::Derived {
                evidence_node_id: result,
            },
        )?;
        rolled_back_result = Some(result);
        Err(std::io::Error::other("force Case rollback").into())
    });
    assert!(rollback.is_err());
    let rolled_back_result = rolled_back_result
        .ok_or_else(|| std::io::Error::other("transaction did not finish the candidate"))?;
    assert!(
        case.nodes()
            .iter()
            .all(|case_node| case_node.id != rolled_back_result)
    );

    let candidate_before = candidate(&coordinator, child)?.clone();
    let candidate_count_before = coordinator.candidate_count();
    let parent_links_before = coordinator.parent_links_retained();
    let lineage_work_before = coordinator.lineage_work_charged();

    assert_eq!(
        coordinator.enqueue_derived(second_parent, &case, &[second_child], task.clone(),),
        Err(RecoveryError::UnknownEvidenceNode {
            node_id: rolled_back_result,
        })
    );
    assert_eq!(candidate(&coordinator, child)?, &candidate_before);
    assert_eq!(coordinator.candidate_count(), candidate_count_before);
    assert_eq!(coordinator.parent_links_retained(), parent_links_before);
    assert_eq!(coordinator.lineage_work_charged(), lineage_work_before);
    assert_eq!(coordinator.pop_next(), Ok(None));

    let restored_result = node(&mut case, b"child result")?;
    assert_eq!(restored_result, rolled_back_result);
    derived_link(&mut case, restored_result, first_child)?;
    derived_link(&mut case, restored_result, second_child)?;
    assert_eq!(
        coordinator.enqueue_derived(second_parent, &case, &[second_child], task,)?,
        EnqueueOutcome::Merged(child)
    );
    assert_eq!(
        candidate(&coordinator, child)?.parent_ids(),
        &[first_parent, second_parent]
    );
    assert_eq!(coordinator.parent_links_retained(), parent_links_before + 1);

    Ok(())
}

#[test]
fn late_context_requires_contract() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let later = node(&mut case, b"same input")?;
    let validation = node(&mut case, b"validated output")?;
    link(
        &mut case,
        validation,
        first,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;
    assert_eq!(
        coordinator.enqueue(&case, later, RecoveryTask::StructuralValidation)?,
        EnqueueOutcome::MergedNeedsContext(id)
    );

    edge(
        &mut case,
        validation,
        later,
        "same_value",
        EvidenceStatus::ConstraintSatisfied,
    )?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Pending { origins: 1 })
    );
    link(
        &mut case,
        validation,
        later,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Complete)
    );

    Ok(())
}

#[test]
fn policy_budgets_stay_explicit() {
    let resources = RecoveryResourcePolicy {
        max_candidates: 11,
        max_frontier: 7,
        max_inputs_per_candidate: 13,
        max_origins_per_candidate: 17,
        max_input_bytes_per_item: 101,
        max_total_input_bytes_per_candidate: 307,
        max_depth: 5,
        max_output_bytes: 79,
        max_work_bytes: 503,
        max_candidate_task_identity_bytes: 509,
        max_transform_proposal_identity_bytes: 521,
        max_transform_proposal_associations: 541,
        max_parent_links: 19,
        max_lineage_work: 509,
        max_context_aliases: 521,
        max_pending_origin_links: 523,
    };
    let coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(coordinator.resources(), resources);
    assert_eq!(coordinator.parent_links_retained(), 0);
    assert_eq!(coordinator.lineage_work_charged(), 0);
    assert_eq!(coordinator.remaining_lineage_work(), 509);
    assert_eq!(coordinator.context_aliases_retained(), 0);
    assert_eq!(coordinator.pending_origin_links_retained(), 0);
}

#[test]
fn context_alias_limit_accepts_exact_boundary_and_keeps_position_order()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let alias = node(&mut case, b"same input")?;
    let mut resources = policy();
    resources.max_context_aliases = 3;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, first],
        RecoveryTask::EmbeddedDiscovery,
    )?;
    assert_eq!(coordinator.context_aliases_retained(), 2);

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[alias, first], RecoveryTask::EmbeddedDiscovery,)?,
        EnqueueOutcome::Merged(id)
    );
    assert_eq!(coordinator.context_aliases_retained(), 3);
    let [first_position, second_position] = candidate(&coordinator, id)?.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_position.origin_node_ids(), &[first, alias]);
    assert_eq!(second_position.origin_node_ids(), &[first]);

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[alias, first], RecoveryTask::EmbeddedDiscovery,)?,
        EnqueueOutcome::Merged(id)
    );
    assert_eq!(coordinator.context_aliases_retained(), 3);
    Ok(())
}

#[test]
fn context_alias_exhaustion_rejects_merge_without_mutating_candidate() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let first_alias = node(&mut case, b"same input")?;
    let second_alias = node(&mut case, b"same input")?;
    let mut resources = policy();
    resources.max_context_aliases = 3;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, first],
        RecoveryTask::EmbeddedDiscovery,
    )?;

    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[first_alias, second_alias],
            RecoveryTask::EmbeddedDiscovery,
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ContextAliases,
            limit: 3,
            used: 2,
            requested: 2,
        }
    );
    assert_eq!(coordinator.context_aliases_retained(), 2);
    let [first_position, second_position] = candidate(&coordinator, id)?.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_position.origin_node_ids(), &[first]);
    assert_eq!(second_position.origin_node_ids(), &[first]);
    assert_eq!(
        candidate(&coordinator, id)?.state(),
        &RecoveryCandidateState::Queued
    );
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    Ok(())
}

#[test]
fn repeated_positions_each_consume_a_context_alias() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"repeated position")?;
    let mut resources = policy();
    resources.max_context_aliases = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.enqueue_nodes(&case, &[input, input], RecoveryTask::EmbeddedDiscovery,)?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ContextAliases,
            limit: 1,
            used: 0,
            requested: 2,
        }
    );
    assert_eq!(coordinator.context_aliases_retained(), 0);
    assert_eq!(coordinator.candidate_count(), 0);
    Ok(())
}

#[test]
fn context_alias_limit_is_shared_across_candidates() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first input")?;
    let repeated = node(&mut case, b"second input")?;
    let mut resources = policy();
    resources.max_context_aliases = 2;
    let mut coordinator = RecoveryCoordinator::new(resources);
    queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::EmbeddedDiscovery,
    )?;

    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[repeated, repeated],
            RecoveryTask::EmbeddedDiscovery,
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ContextAliases,
            limit: 2,
            used: 1,
            requested: 2,
        }
    );
    assert_eq!(coordinator.context_aliases_retained(), 1);
    assert_eq!(coordinator.candidate_count(), 1);
    Ok(())
}

#[test]
fn late_terminal_context_obligations_are_metered_and_released_on_refresh()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let later = node(&mut case, b"same input")?;
    let validation = node(&mut case, b"validation")?;
    link(
        &mut case,
        validation,
        first,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut resources = policy();
    resources.max_context_aliases = 2;
    resources.max_pending_origin_links = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.enqueue(&case, later, RecoveryTask::StructuralValidation)?,
        EnqueueOutcome::MergedNeedsContext(id)
    );
    assert_eq!(coordinator.pending_origin_links_retained(), 1);
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Pending { origins: 1 })
    );
    assert_eq!(coordinator.pending_origin_links_retained(), 1);

    link(
        &mut case,
        validation,
        later,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    assert_eq!(
        coordinator.refresh_context(&case, id),
        Ok(ContextRegistration::Complete)
    );
    assert_eq!(coordinator.pending_origin_links_retained(), 0);
    Ok(())
}

#[test]
fn late_terminal_origins_append_linearly_and_respect_the_pending_link_boundary()
-> Result<(), Box<dyn Error>> {
    const LATE_ORIGIN_COUNT: usize = 64;
    let mut fixture = terminal_context_fixture(LATE_ORIGIN_COUNT)?;
    let late_origins = enqueue_late_terminal_origins(&mut fixture, LATE_ORIGIN_COUNT)?;
    assert_terminal_context(&fixture, &late_origins)?;

    let extra_origin = node(&mut fixture.case, b"same input")?;
    let aliases_before_failure = fixture.coordinator.context_aliases_retained();
    assert_eq!(
        fixture.coordinator.enqueue(
            &fixture.case,
            extra_origin,
            RecoveryTask::StructuralValidation,
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::PendingOriginLinks,
            limit: LATE_ORIGIN_COUNT,
            used: LATE_ORIGIN_COUNT,
            requested: 1,
        }
    );
    assert_eq!(
        fixture.coordinator.context_aliases_retained(),
        aliases_before_failure
    );
    assert_terminal_context(&fixture, &late_origins)?;

    for origin in &late_origins {
        link(
            &mut fixture.case,
            fixture.validation_node,
            *origin,
            EvidenceStatus::ConstraintSatisfied,
        )?;
    }
    assert_eq!(
        fixture
            .coordinator
            .refresh_context(&fixture.case, fixture.candidate_id),
        Ok(ContextRegistration::Complete)
    );
    assert_eq!(fixture.coordinator.pending_origin_links_retained(), 0);
    Ok(())
}

struct TerminalContextFixture {
    case: Case,
    coordinator: RecoveryCoordinator,
    candidate_id: RecoveryCandidateId,
    first_origin: u64,
    validation_node: u64,
}

fn terminal_context_fixture(
    max_pending_origins: usize,
) -> Result<TerminalContextFixture, Box<dyn Error>> {
    let mut case = Case::new();
    let first_origin = node(&mut case, b"same input")?;
    let validation_node = node(&mut case, b"validation")?;
    link(
        &mut case,
        validation_node,
        first_origin,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut resources = policy();
    resources.max_context_aliases = max_pending_origins + 2;
    resources.max_origins_per_candidate = max_pending_origins + 2;
    resources.max_pending_origin_links = max_pending_origins;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let candidate_id = queue(
        &mut coordinator,
        &case,
        first_origin,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(candidate_id)));
    coordinator.finish(
        &case,
        candidate_id,
        RecoveryResult::ObservedValidation {
            node_id: validation_node,
        },
    )?;
    Ok(TerminalContextFixture {
        case,
        coordinator,
        candidate_id,
        first_origin,
        validation_node,
    })
}

fn enqueue_late_terminal_origins(
    fixture: &mut TerminalContextFixture,
    count: usize,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut late_origins = Vec::new();
    for expected_pending in 1..=count {
        let origin = node(&mut fixture.case, b"same input")?;
        assert_eq!(
            fixture.coordinator.enqueue(
                &fixture.case,
                origin,
                RecoveryTask::StructuralValidation,
            )?,
            EnqueueOutcome::MergedNeedsContext(fixture.candidate_id)
        );
        late_origins.push(origin);
        assert_eq!(
            candidate(&fixture.coordinator, fixture.candidate_id)?.pending_origin_node_ids(),
            late_origins
        );
        assert_eq!(
            fixture.coordinator.pending_origin_links_retained(),
            expected_pending
        );
    }
    Ok(late_origins)
}

fn assert_terminal_context(
    fixture: &TerminalContextFixture,
    late_origins: &[u64],
) -> Result<(), Box<dyn Error>> {
    let terminal = candidate(&fixture.coordinator, fixture.candidate_id)?;
    let [input] = terminal.inputs() else {
        return Err(std::io::Error::other("expected one candidate input").into());
    };
    let retained_late_origins = input
        .origin_node_ids()
        .get(1..)
        .ok_or_else(|| std::io::Error::other("initial origin is missing"))?;
    assert_eq!(input.origin_node_ids().first(), Some(&fixture.first_origin));
    assert_eq!(retained_late_origins, late_origins);
    assert_eq!(terminal.pending_origin_node_ids(), late_origins);
    assert_eq!(
        terminal.state(),
        &RecoveryCandidateState::ContextPending {
            stage: RecoveryStage::StructuralValidation,
            result: RecoveryResult::ObservedValidation {
                node_id: fixture.validation_node,
            },
        }
    );
    Ok(())
}

#[test]
fn pending_link_exhaustion_rejects_terminal_merge_without_mutation() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"same input")?;
    let later = node(&mut case, b"same input")?;
    let validation = node(&mut case, b"validation")?;
    link(
        &mut case,
        validation,
        first,
        EvidenceStatus::ConstraintSatisfied,
    )?;
    let mut resources = policy();
    resources.max_context_aliases = 8;
    resources.max_pending_origin_links = 0;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue(
        &mut coordinator,
        &case,
        first,
        RecoveryTask::StructuralValidation,
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    coordinator.finish(
        &case,
        id,
        RecoveryResult::ObservedValidation {
            node_id: validation,
        },
    )?;

    assert_eq!(
        coordinator.enqueue(&case, later, RecoveryTask::StructuralValidation)?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::PendingOriginLinks,
            limit: 0,
            used: 0,
            requested: 1,
        }
    );
    assert_eq!(coordinator.context_aliases_retained(), 1);
    assert_eq!(coordinator.pending_origin_links_retained(), 0);
    let [input] = candidate(&coordinator, id)?.inputs() else {
        return Err(std::io::Error::other("expected one candidate input").into());
    };
    assert_eq!(input.origin_node_ids(), &[first]);
    assert_eq!(
        candidate(&coordinator, id)?.state(),
        &RecoveryCandidateState::Finished {
            stage: RecoveryStage::StructuralValidation,
            result: RecoveryResult::ObservedValidation {
                node_id: validation
            },
        }
    );
    Ok(())
}

#[test]
fn lineage_work_and_parent_links_accept_exact_boundaries() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root_input = node(&mut case, b"same input")?;
    let root_receipt = node(&mut case, b"root receipt")?;
    let middle_input = node(&mut case, b"middle input")?;
    let middle_receipt = node(&mut case, b"middle receipt")?;
    let cycle_input = node(&mut case, b"same input")?;
    derived_link(&mut case, root_receipt, root_input)?;
    derived_link(&mut case, middle_input, root_receipt)?;
    derived_link(&mut case, middle_receipt, middle_input)?;
    derived_link(&mut case, cycle_input, middle_receipt)?;
    let mut resources = policy();
    resources.max_parent_links = 1;
    resources.max_lineage_work = 8;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let root = queue(
        &mut coordinator,
        &case,
        root_input,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(root)));
    coordinator.finish(
        &case,
        root,
        RecoveryResult::Derived {
            evidence_node_id: root_receipt,
        },
    )?;

    let middle = queued_id(coordinator.enqueue_derived(
        root,
        &case,
        &[middle_input],
        RecoveryTask::RecursiveExpansion,
    )?)?;
    assert_eq!(coordinator.lineage_work_charged(), 2);
    assert_eq!(coordinator.parent_links_retained(), 1);
    assert_eq!(coordinator.pop_next(), Ok(Some(middle)));
    coordinator.finish(
        &case,
        middle,
        RecoveryResult::Derived {
            evidence_node_id: middle_receipt,
        },
    )?;

    assert_eq!(
        coordinator.enqueue_derived(
            middle,
            &case,
            &[cycle_input],
            transform(Operation::Reverse {}),
        )?,
        EnqueueOutcome::CycleSkipped { candidate_id: root }
    );
    assert_eq!(coordinator.lineage_work_charged(), 8);
    assert_eq!(coordinator.remaining_lineage_work(), 0);
    assert_eq!(coordinator.parent_links_retained(), 1);

    Ok(())
}

#[test]
fn parent_link_exhaustion_does_not_merge_origins_or_parents() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut resources = policy();
    resources.max_parent_links = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let (first_parent, first_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent one",
        b"receipt one",
        b"same child",
    )?;
    let (second_parent, second_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent two",
        b"receipt two",
        b"same child",
    )?;
    let child = queued_id(coordinator.enqueue_derived(
        first_parent,
        &case,
        &[first_child],
        transform(Operation::Reverse {}),
    )?)?;
    let work_before = coordinator.lineage_work_charged();

    assert_eq!(
        coordinator.enqueue_derived(
            second_parent,
            &case,
            &[second_child],
            transform(Operation::Reverse {}),
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ParentLinks,
            limit: 1,
            used: 1,
            requested: 1,
        }
    );
    assert_eq!(coordinator.candidate_count(), 3);
    assert_eq!(coordinator.parent_links_retained(), 1);
    assert_eq!(coordinator.lineage_work_charged(), work_before);
    assert_eq!(
        candidate(&coordinator, child)?.parent_ids(),
        &[first_parent]
    );
    let [child_input] = candidate(&coordinator, child)?.inputs() else {
        return Err(std::io::Error::other("expected one child input").into());
    };
    assert_eq!(child_input.origin_node_ids(), &[first_child]);
    assert_eq!(
        candidate(&coordinator, child)?.state(),
        &RecoveryCandidateState::Queued
    );

    Ok(())
}

#[test]
fn exact_identity_merge_at_candidate_capacity_does_not_scan_lineage() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let mut resources = policy();
    resources.max_candidates = 3;
    resources.max_parent_links = 2;
    resources.max_lineage_work = 2;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let (first_parent, first_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent one",
        b"receipt one",
        b"same child",
    )?;
    let (second_parent, second_child) = finished_parent(
        &mut coordinator,
        &mut case,
        b"parent two",
        b"receipt two",
        b"same child",
    )?;
    let child = queued_id(coordinator.enqueue_derived(
        first_parent,
        &case,
        &[first_child],
        transform(Operation::Reverse {}),
    )?)?;
    assert_eq!(coordinator.lineage_work_charged(), 2);
    assert_eq!(coordinator.candidate_count(), 3);

    assert_eq!(
        coordinator.enqueue_derived(
            second_parent,
            &case,
            &[second_child],
            transform(Operation::Reverse {}),
        )?,
        EnqueueOutcome::Merged(child)
    );
    assert_eq!(coordinator.lineage_work_charged(), 2);
    assert_eq!(coordinator.parent_links_retained(), 2);
    assert_eq!(
        candidate(&coordinator, child)?.parent_ids(),
        &[first_parent, second_parent]
    );

    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Derived { evidence_node_id },
        ..
    } = candidate(&coordinator, second_parent)?.state()
    else {
        return Err(std::io::Error::other("expected a finished derivation parent").into());
    };
    let extra_child = node(&mut case, b"extra child")?;
    derived_link(&mut case, extra_child, *evidence_node_id)?;
    assert_eq!(
        coordinator.enqueue_derived(
            second_parent,
            &case,
            &[extra_child],
            transform(Operation::ByteAdd { value: 1 }),
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateCount,
            limit: 3,
            used: 3,
            requested: 1,
        }
    );
    assert_eq!(coordinator.lineage_work_charged(), 2);

    Ok(())
}

#[test]
fn high_fan_in_lineage_exhaustion_is_stable_on_retry() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut resources = policy();
    resources.max_parent_links = 4;
    resources.max_lineage_work = 16;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let mut parents = Vec::new();
    for index in 0..4 {
        let input_bytes = format!("parent {index}");
        let receipt_bytes = format!("receipt {index}");
        let (parent, child) = finished_parent(
            &mut coordinator,
            &mut case,
            input_bytes.as_bytes(),
            receipt_bytes.as_bytes(),
            b"same batch child",
        )?;
        parents.push((parent, child));
    }
    let fan_in = queued_id(coordinator.enqueue_derived_many(
        &case,
        &parents,
        RecoveryTask::EmbeddedDiscovery,
    )?)?;
    assert_eq!(coordinator.lineage_work_charged(), 8);
    assert_eq!(coordinator.parent_links_retained(), 4);
    assert_eq!(coordinator.pop_next(), Ok(Some(fan_in)));
    let fan_in_receipt = node(&mut case, b"fan-in receipt")?;
    for (_, child) in &parents {
        derived_link(&mut case, fan_in_receipt, *child)?;
    }
    coordinator.finish(
        &case,
        fan_in,
        RecoveryResult::Derived {
            evidence_node_id: fan_in_receipt,
        },
    )?;
    let grandchild = node(&mut case, b"new grandchild")?;
    derived_link(&mut case, grandchild, fan_in_receipt)?;
    let parent_ids = candidate(&coordinator, fan_in)?.parent_ids().to_vec();
    let input_origins = candidate(&coordinator, fan_in)?
        .inputs()
        .iter()
        .map(|input| input.origin_node_ids().to_vec())
        .collect::<Vec<_>>();
    let state = candidate(&coordinator, fan_in)?.state().clone();
    let candidate_count = coordinator.candidate_count();
    let child_task = RecoveryTask::RecordDiscovery;

    for _ in 0..2 {
        assert_eq!(
            coordinator.enqueue_derived(fan_in, &case, &[grandchild], child_task.clone())?,
            EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::LineageWork,
                limit: 16,
                used: 16,
                requested: 1,
            }
        );
        assert_eq!(coordinator.lineage_work_charged(), 16);
        assert_eq!(coordinator.candidate_count(), candidate_count);
        assert_eq!(candidate(&coordinator, fan_in)?.parent_ids(), parent_ids);
        assert_eq!(
            candidate(&coordinator, fan_in)?
                .inputs()
                .iter()
                .map(|input| input.origin_node_ids().to_vec())
                .collect::<Vec<_>>(),
            input_origins
        );
        assert_eq!(candidate(&coordinator, fan_in)?.state(), &state);
    }
    assert_eq!(coordinator.pop_next(), Ok(None));

    Ok(())
}

#[test]
fn origin_limit_accepts_exact() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first")?;
    let second = node(&mut case, b"second")?;
    let first_alias = node(&mut case, b"first")?;
    let mut resources = policy();
    resources.max_origins_per_candidate = 3;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::EmbeddedDiscovery,
    )?;

    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[first_alias, second],
            RecoveryTask::EmbeddedDiscovery,
        )?,
        EnqueueOutcome::Merged(id)
    );
    let [first_input, second_input] = candidate(&coordinator, id)?.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_input.origin_node_ids(), &[first, first_alias]);
    assert_eq!(second_input.origin_node_ids(), &[second]);

    Ok(())
}

#[test]
fn origin_limit_rejects_atomically() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"first")?;
    let second = node(&mut case, b"second")?;
    let first_alias = node(&mut case, b"first")?;
    let second_alias = node(&mut case, b"second")?;
    let mut resources = policy();
    resources.max_origins_per_candidate = 2;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[first, second],
        RecoveryTask::EmbeddedDiscovery,
    )?;

    assert_eq!(
        coordinator.enqueue_nodes(
            &case,
            &[first_alias, second_alias],
            RecoveryTask::EmbeddedDiscovery,
        )?,
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::OriginCount,
            limit: 2,
            used: 2,
            requested: 2,
        }
    );
    let [first_input, second_input] = candidate(&coordinator, id)?.inputs() else {
        return Err(std::io::Error::other("expected two candidate inputs").into());
    };
    assert_eq!(first_input.origin_node_ids(), &[first]);
    assert_eq!(second_input.origin_node_ids(), &[second]);

    Ok(())
}

#[test]
fn repeated_origins_count_once() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = node(&mut case, b"repeated")?;
    let mut resources = policy();
    resources.max_origins_per_candidate = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);

    let id = queue_nodes(
        &mut coordinator,
        &case,
        &[input, input],
        RecoveryTask::EmbeddedDiscovery,
    )?;
    assert_eq!(candidate(&coordinator, id)?.inputs().len(), 2);

    Ok(())
}

#[test]
fn work_exhaustion_is_recorded() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"two bytes")?;
    let mut resources = policy();
    resources.max_work_bytes = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.charge_work(id, 2),
        Ok(BudgetCheck::Exhausted {
            resource: RecoveryResource::WorkBytes,
            limit: 1,
            used: 0,
            requested: 2,
        })
    );
    assert!(matches!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::WorkBytes,
                ..
            },
            ..
        })
    ));

    Ok(())
}

#[test]
fn work_remaining_tracks_charges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"work")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.remaining_work_bytes(), policy().max_work_bytes);
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));
    assert_eq!(
        coordinator.charge_work(id, 7),
        Ok(BudgetCheck::WithinBudget)
    );
    assert_eq!(
        coordinator.remaining_work_bytes(),
        policy().max_work_bytes - 7
    );
    assert_eq!(coordinator.work_bytes_charged(), 7);

    Ok(())
}

#[test]
fn output_exhaustion_finishes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"input")?;
    let mut resources = policy();
    resources.max_output_bytes = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    assert_eq!(
        coordinator.check_output(id, 2),
        Ok(BudgetCheck::Exhausted {
            resource: RecoveryResource::OutputBytes,
            limit: 1,
            used: 0,
            requested: 2,
        })
    );
    assert!(matches!(
        coordinator.candidate(id).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::OutputBytes,
                ..
            },
            ..
        })
    ));

    Ok(())
}

#[test]
fn candidate_limit_reports_exhaustion() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = node(&mut case, b"one")?;
    let second = node(&mut case, b"two")?;
    let mut resources = policy();
    resources.max_candidates = 1;
    let mut coordinator = RecoveryCoordinator::new(resources);
    queue(
        &mut coordinator,
        &case,
        first,
        transform(Operation::Reverse {}),
    )?;

    assert_eq!(
        coordinator.enqueue(&case, second, transform(Operation::Reverse {}),),
        Ok(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::CandidateCount,
            limit: 1,
            used: 1,
            requested: 1,
        })
    );

    Ok(())
}

#[test]
fn candidate_ids_are_stable() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let origin = node(&mut case, b"stable")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queue(
        &mut coordinator,
        &case,
        origin,
        transform(Operation::Reverse {}),
    )?;

    assert_eq!(id.index(), 0);
    assert_eq!(coordinator.pop_next(), Ok(Some(id)));

    Ok(())
}
