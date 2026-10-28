use l2_workbench::{
    derivation::{
        AesGcmTagLayout, Constraint, CounterByteOrder, CounterWidth, OperandRef, Operation, Recipe,
        SeedCounterOrder,
    },
    evidence::{Case, Edge, EvidenceStatus},
    recovery::{
        BudgetCheck, ContextRegistration, EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId,
        RecoveryCandidateState, RecoveryCoordinator, RecoveryResourcePolicy, RecoveryResult,
        RecoveryTask, TransformProposalAssociationOutcome,
    },
};
use serde_json::{Value, json};
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;

const fn policy() -> RecoveryResourcePolicy {
    RecoveryResourcePolicy {
        max_candidates: 20,
        max_frontier: 20,
        max_inputs_per_candidate: 4,
        max_origins_per_candidate: 8,
        max_input_bytes_per_item: 64,
        max_total_input_bytes_per_candidate: 128,
        max_depth: 5,
        max_output_bytes: 64,
        max_work_bytes: 512,
        max_candidate_task_identity_bytes: 16384,
        max_transform_proposal_identity_bytes: 16384,
        max_transform_proposal_associations: 10,
        max_parent_links: 30,
        max_lineage_work: 256,
        max_context_aliases: 100,
        max_pending_origin_links: 30,
    }
}

fn node(case: &mut Case, bytes: &[u8]) -> TestResult<u64> {
    Ok(case.add_bytes_node("checkpoint_input", bytes, Vec::new(), json!({}))?)
}

fn link(case: &mut Case, from: u64, to: u64) -> TestResult {
    case.add_edge(Edge {
        from,
        to,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "checkpoint fixture".to_owned(),
    })?;
    Ok(())
}

fn queued(outcome: EnqueueOutcome) -> TestResult<RecoveryCandidateId> {
    match outcome {
        EnqueueOutcome::Queued(id) => Ok(id),
        other => Err(format!("expected queued candidate, got {other:?}").into()),
    }
}

fn restore(
    case: &Case,
    encoded: &[u8],
) -> Result<RecoveryCoordinator, l2_workbench::recovery::RecoveryError> {
    RecoveryCoordinator::restore(case, policy(), encoded, MAX_CHECKPOINT_BYTES)
}

fn capture(
    coordinator: &RecoveryCoordinator,
    case: &Case,
) -> Result<Vec<u8>, l2_workbench::recovery::RecoveryError> {
    let mut bytes = Vec::new();
    coordinator.write_checkpoint(case, &mut bytes, MAX_CHECKPOINT_BYTES)?;
    Ok(bytes)
}

#[test]
fn checkpoint_stream_obeys_byte_limit_and_writes_no_secret_bytes() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let expected = capture(&coordinator, &case)?;
    let mut exact = Vec::new();
    assert_eq!(
        coordinator.write_checkpoint(&case, &mut exact, expected.len())?,
        expected.len()
    );
    assert_eq!(exact, expected);
    let mut short = Vec::new();
    assert!(
        coordinator
            .write_checkpoint(&case, &mut short, expected.len() - 1)
            .is_err()
    );
    assert!(short.len() < expected.len());
    let mut secret = RecoveryCoordinator::new(policy());
    queued(secret.enqueue(
        &case,
        input,
        RecoveryTask::transform(Operation::XorRepeat {
            key: b"sensitive-key".to_vec(),
            offset: 0,
        }),
    )?)?;
    let mut output = b"existing".to_vec();
    assert!(
        secret
            .write_checkpoint(&case, &mut output, MAX_CHECKPOINT_BYTES)
            .is_err()
    );
    assert_eq!(output, b"existing");
    Ok(())
}

#[test]
fn checkpoint_restores_fifo_pending_origins_lineage_and_charges() -> TestResult {
    let mut case = Case::new();
    let first_input = node(&mut case, b"input")?;
    let late_input = node(&mut case, b"input")?;
    let receipt = node(&mut case, b"receipt")?;
    let child_input = node(&mut case, b"child")?;
    link(&mut case, receipt, first_input)?;
    link(&mut case, child_input, receipt)?;
    let mut original = RecoveryCoordinator::new(policy());
    let parent = queued(original.enqueue(&case, first_input, RecoveryTask::EmbeddedDiscovery)?)?;
    assert_eq!(original.pop_next()?, Some(parent));
    assert_eq!(original.charge_work(parent, 23)?, BudgetCheck::WithinBudget);
    original.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    )?;
    let child_outcome = original.enqueue_derived(
        parent,
        &case,
        &[child_input],
        RecoveryTask::StructuralValidation,
    )?;
    let child = queued(child_outcome)?;
    let tail_outcome = original.enqueue(&case, first_input, RecoveryTask::RecordDiscovery)?;
    let tail = queued(tail_outcome)?;
    original.prioritize_newly_queued(&tail_outcome)?;
    assert_eq!(
        original.enqueue(&case, late_input, RecoveryTask::EmbeddedDiscovery)?,
        EnqueueOutcome::MergedNeedsContext(parent)
    );
    // A later Case update must not silently consume the saved pending origin
    link(&mut case, receipt, late_input)?;
    let recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: Vec::new(),
    };
    assert_eq!(
        original.admit_transform_proposal_association(receipt, &recipe)?,
        TransformProposalAssociationOutcome::Admitted
    );
    let encoded = capture(&original, &case)?;
    let restored_case = case.try_clone()?;
    let mut resumed = restore(&restored_case, &encoded)?;
    assert_saved_accounting(&original, &resumed);
    assert_eq!(resumed.candidate(parent), original.candidate(parent));
    assert_eq!(resumed.candidate(child), original.candidate(child));
    assert_eq!(resumed.candidate(tail), original.candidate(tail));
    assert!(matches!(
        resumed.candidate(parent).map(RecoveryCandidate::state),
        Some(RecoveryCandidateState::ContextPending { .. })
    ));
    assert_eq!(
        resumed
            .candidate(parent)
            .ok_or("missing parent")?
            .pending_origin_node_ids(),
        &[late_input]
    );
    assert_eq!(
        resumed.refresh_context(&restored_case, parent)?,
        ContextRegistration::Complete
    );
    assert_eq!(
        resumed.admit_transform_proposal_association(receipt, &recipe)?,
        TransformProposalAssociationOutcome::AlreadyRetained
    );
    assert_eq!(
        resumed.enqueue(&restored_case, first_input, RecoveryTask::RecordDiscovery)?,
        EnqueueOutcome::Merged(tail)
    );
    assert_eq!(resumed.pop_next()?, Some(tail));
    assert_eq!(resumed.pop_next()?, Some(child));
    assert_eq!(resumed.pop_next()?, None);
    Ok(())
}

fn assert_saved_accounting(original: &RecoveryCoordinator, resumed: &RecoveryCoordinator) {
    assert_eq!(resumed.resources(), original.resources());
    assert_eq!(resumed.candidate_count(), original.candidate_count());
    assert_eq!(resumed.work_bytes_charged(), 23);
    assert_eq!(
        resumed.lineage_work_charged(),
        original.lineage_work_charged()
    );
    assert_eq!(
        resumed.parent_links_retained(),
        original.parent_links_retained()
    );
    assert_eq!(
        resumed.context_aliases_retained(),
        original.context_aliases_retained()
    );
    assert_eq!(resumed.pending_origin_links_retained(), 1);
    assert_eq!(
        resumed.candidate_task_identity_bytes_charged(),
        original.candidate_task_identity_bytes_charged()
    );
    assert_eq!(
        resumed.transform_proposal_identity_bytes_charged(),
        original.transform_proposal_identity_bytes_charged()
    );
}

#[test]
fn restored_work_budget_cannot_be_reset_by_a_second_checkpoint() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let first = queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let next = queued(coordinator.enqueue(&case, input, RecoveryTask::RecordDiscovery)?)?;
    assert_eq!(coordinator.pop_next()?, Some(first));
    assert_eq!(
        coordinator.charge_work(first, 500)?,
        BudgetCheck::WithinBudget
    );
    coordinator.finish(&case, first, RecoveryResult::Unsupported)?;
    let saved = capture(&coordinator, &case)?;
    let case = case.try_clone()?;
    let mut restored = restore(&case, &saved)?;
    assert_eq!(restored.pop_next()?, Some(next));
    assert_eq!(restored.charge_work(next, 12)?, BudgetCheck::WithinBudget);
    assert_eq!(
        restored.charge_work(next, 1)?,
        BudgetCheck::Exhausted {
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit: 512,
            used: 512,
            requested: 1,
        }
    );
    // A rejected charge is terminal and the next save still carries all spent work
    let saved = capture(&restored, &case)?;
    let restored = restore(&case, &saved)?;
    assert_eq!(restored.work_bytes_charged(), 512);
    assert_eq!(restored.remaining_work_bytes(), 0);
    Ok(())
}

#[test]
fn checkpoint_rejects_running_candidate_and_foreign_case() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let id = queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    assert!(capture(&coordinator, &case.try_clone()?).is_err());
    assert_eq!(coordinator.pop_next()?, Some(id));
    assert!(capture(&coordinator, &case).is_err());
    Ok(())
}

#[test]
fn restored_pre_candidate_work_remains_bound_to_its_evidence_case() -> TestResult {
    for retain_association in [false, true] {
        let mut case = Case::new();
        let input = node(&mut case, b"input")?;
        let mut coordinator = RecoveryCoordinator::new(policy());
        assert_eq!(coordinator.charge_case_work(7), BudgetCheck::WithinBudget);
        if retain_association {
            coordinator.admit_transform_proposal_association(
                input,
                &Recipe {
                    steps: vec![Operation::HexDecode {}],
                    constraints: Vec::new(),
                },
            )?;
        }
        let encoded = capture(&coordinator, &case)?;
        let restored_case = case.try_clone()?;
        let mut restored = restore(&restored_case, &encoded)?;
        assert_eq!(restored.work_bytes_charged(), 7);
        // Equal bytes do not make two separate evidence Cases interchangeable
        assert_eq!(
            restored.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery),
            Err(l2_workbench::recovery::RecoveryError::DifferentCase)
        );
        assert_eq!(restored.candidate_count(), 0);
        queued(restored.enqueue(&restored_case, input, RecoveryTask::EmbeddedDiscovery)?)?;
        assert_eq!(restored.work_bytes_charged(), 7);
    }
    Ok(())
}

#[test]
fn restore_rejects_policy_size_version_case_and_corrupt_queue() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let encoded = capture(&coordinator, &case)?;
    let mut changed_case = case.try_clone()?;
    node(&mut changed_case, b"unrelated")?;
    assert!(restore(&changed_case, &encoded).is_err());
    assert!(RecoveryCoordinator::restore(&case, policy(), &encoded, encoded.len() - 1).is_err());
    let mut other_policy = policy();
    other_policy.max_work_bytes -= 1;
    assert!(
        RecoveryCoordinator::restore(&case, other_policy, &encoded, MAX_CHECKPOINT_BYTES).is_err()
    );
    for (field, replacement) in [
        ("version", json!(999)),
        ("frontier", json!([0, 0])),
        ("work_bytes", json!(513)),
    ] {
        let mut altered: Value = serde_json::from_slice(&encoded)?;
        *altered.get_mut(field).ok_or("missing checkpoint field")? = replacement;
        assert!(
            restore(&case, &serde_json::to_vec(&altered)?).is_err(),
            "accepted invalid {field}"
        );
    }
    Ok(())
}

#[test]
fn checkpoint_rejects_literal_secret_tasks_and_proposal_associations() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let literal = || OperandRef::from(vec![115, 101, 99, 114, 101, 116]);
    let selected = || OperandRef::SelectedInputRange {
        offset: 0,
        length: 1,
    };
    let recipes = [
        Recipe {
            steps: vec![Operation::XorRepeat {
                key: b"secret".to_vec(),
                offset: 0,
            }],
            constraints: Vec::new(),
        },
        Recipe {
            steps: vec![Operation::Sha256CounterXor {
                seed: literal(),
                initial_counter: 0,
                counter_width: CounterWidth::OneByte,
                counter_byte_order: CounterByteOrder::BigEndian,
                seed_order: SeedCounterOrder::SeedThenCounter,
            }],
            constraints: Vec::new(),
        },
        Recipe {
            steps: vec![Operation::AesGcmDecrypt {
                key: literal(),
                nonce: selected(),
                associated_data: selected(),
                tag_layout: AesGcmTagLayout::Appended,
            }],
            constraints: Vec::new(),
        },
        Recipe {
            steps: vec![Operation::ScryptDerive {
                salt: literal(),
                log_n: 1,
                r: 1,
                p: 1,
                output_length: 1,
            }],
            constraints: Vec::new(),
        },
        Recipe {
            steps: Vec::new(),
            constraints: vec![Constraint::AesGcm {
                key: literal(),
                nonce: selected(),
                associated_data: selected(),
            }],
        },
    ];
    for recipe in recipes {
        let mut candidate_coordinator = RecoveryCoordinator::new(policy());
        queued(candidate_coordinator.enqueue(
            &case,
            input,
            RecoveryTask::Transform(recipe.clone()),
        )?)?;
        assert!(
            capture(&candidate_coordinator, &case).is_err(),
            "literal candidate accepted"
        );
        let mut association_coordinator = RecoveryCoordinator::new(policy());
        association_coordinator.admit_transform_proposal_association(input, &recipe)?;
        let mut destination = b"existing".to_vec();
        assert!(
            association_coordinator
                .write_checkpoint(&case, &mut destination, MAX_CHECKPOINT_BYTES)
                .is_err(),
            "literal association accepted"
        );
        assert_eq!(destination, b"existing");
    }
    Ok(())
}

#[test]
fn checkpoint_restores_automatic_transforms_and_reference_operands() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut original = RecoveryCoordinator::new(policy());
    for operation in l2_workbench::recovery::proposals::transform_proposal_operations() {
        let recipe = Recipe {
            steps: vec![operation],
            constraints: Vec::new(),
        };
        queued(original.enqueue(&case, input, RecoveryTask::Transform(recipe.clone()))?)?;
        original.admit_transform_proposal_association(input, &recipe)?;
    }
    let recipe = Recipe {
        steps: vec![Operation::Sha256CounterXor {
            seed: OperandRef::SelectedInputRange {
                offset: 0,
                length: 1,
            },
            initial_counter: 0,
            counter_width: CounterWidth::OneByte,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }],
        constraints: Vec::new(),
    };
    queued(original.enqueue(&case, input, RecoveryTask::Transform(recipe.clone()))?)?;
    original.admit_transform_proposal_association(input, &recipe)?;
    let encoded = capture(&original, &case)?;
    let restored_case = case.try_clone()?;
    let mut resumed = restore(&restored_case, &encoded)?;
    assert_eq!(resumed.candidate_count(), original.candidate_count());
    assert_eq!(
        resumed.transform_proposal_associations_charged(),
        original.transform_proposal_associations_charged()
    );
    while let Some(id) = original.pop_next()? {
        assert_eq!(resumed.pop_next()?, Some(id));
        assert_eq!(resumed.candidate(id), original.candidate(id));
    }
    assert_eq!(resumed.pop_next()?, None);
    Ok(())
}

#[test]
fn restore_rejects_invalid_candidate_references_and_duplicate_identities() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let encoded = capture(&coordinator, &case)?;
    let original: Value = serde_json::from_slice(&encoded)?;
    for (pointer, value, reason) in [
        ("/frontier", json!([]), "missing FIFO entry"),
        ("/frontier", json!([7]), "unknown FIFO entry"),
        (
            "/candidates/0/inputs/0/origin_node_ids",
            json!([input, input]),
            "repeated origin",
        ),
        (
            "/candidates/0/inputs/0/origin_node_ids",
            json!([999]),
            "unknown origin",
        ),
        (
            "/candidates/0/inputs/0/blob_id",
            json!("sha256:wrong"),
            "wrong blob",
        ),
        ("/candidates/0/parent_ids", json!([42]), "unknown parent"),
        (
            "/candidates/0/task",
            json!({"task":"embedded_discovery","unknown_rule":true}),
            "unknown task field",
        ),
        (
            "/candidates/0/pending_origin_node_ids",
            json!([input]),
            "pending queued candidate",
        ),
        (
            "/candidates/0/task",
            json!({"task":"transform","operation":{"steps":[{"kind":"xor_repeat","key":[115,101,99,114,101,116],"offset":0}],"constraints":[]}}),
            "injected XOR key",
        ),
    ] {
        assert_invalid_checkpoint(&case, &original, &[(pointer, value)], reason)?;
    }
    assert_invalid_checkpoint(
        &case,
        &original,
        &[
            (
                "/candidates/0/state",
                json!({"Running": "EmbeddedDiscovery"}),
            ),
            ("/frontier", json!([])),
        ],
        "running candidate",
    )?;
    let mut duplicate = original;
    let candidate = duplicate
        .pointer("/candidates/0")
        .ok_or("missing candidate")?
        .clone();
    duplicate
        .get_mut("candidates")
        .and_then(Value::as_array_mut)
        .ok_or("missing candidates")?
        .push(candidate);
    *duplicate
        .pointer_mut("/frontier")
        .ok_or("missing frontier")? = json!([0, 1]);
    assert!(
        restore(&case, &serde_json::to_vec(&duplicate)?).is_err(),
        "duplicate candidate identity"
    );
    Ok(())
}

fn assert_invalid_checkpoint(
    case: &Case,
    original: &Value,
    changes: &[(&str, Value)],
    reason: &str,
) -> TestResult {
    let mut invalid = original.clone();
    for (pointer, value) in changes {
        *invalid
            .pointer_mut(pointer)
            .ok_or("missing checkpoint fixture field")? = value.clone();
    }
    assert!(
        restore(case, &serde_json::to_vec(&invalid)?).is_err(),
        "{reason}"
    );
    Ok(())
}

#[test]
fn restore_rejects_invalid_parent_links_and_result_evidence() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let receipt = node(&mut case, b"receipt")?;
    let child_input = node(&mut case, b"child")?;
    link(&mut case, receipt, input)?;
    link(&mut case, child_input, receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    coordinator.pop_next()?;
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    )?;
    queued(coordinator.enqueue_derived(
        parent,
        &case,
        &[child_input],
        RecoveryTask::StructuralValidation,
    )?)?;
    let encoded = capture(&coordinator, &case)?;
    let original: Value = serde_json::from_slice(&encoded)?;
    let mut invalid = original.clone();
    *invalid
        .pointer_mut("/candidates/0/state/Finished/result")
        .ok_or("missing checkpoint fixture field")? = json!({"Derived":{"evidence_node_id":999}});
    assert!(
        restore(&case, &serde_json::to_vec(&invalid)?).is_err(),
        "unknown result node"
    );
    invalid = original.clone();
    *invalid
        .pointer_mut("/candidates/0/state/Finished/stage")
        .ok_or("missing checkpoint fixture field")? = json!("RecordDiscovery");
    assert!(
        restore(&case, &serde_json::to_vec(&invalid)?).is_err(),
        "wrong terminal stage"
    );
    invalid = original.clone();
    *invalid
        .pointer_mut("/candidates/1/depth")
        .ok_or("missing checkpoint fixture field")? = json!(5);
    assert!(
        restore(&case, &serde_json::to_vec(&invalid)?).is_err(),
        "invalid parent depth"
    );
    invalid = original;
    *invalid
        .pointer_mut("/candidates/1/parent_ids")
        .ok_or("missing checkpoint fixture field")? = json!([0, 0]);
    assert!(
        restore(&case, &serde_json::to_vec(&invalid)?).is_err(),
        "duplicate parent"
    );
    Ok(())
}

#[test]
fn checkpoint_restores_with_case_snapshot_roundtrip() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let checkpoint = capture(&coordinator, &case)?;
    let limits = l2_workbench::evidence::CaseSnapshotLimits::new(1024 * 1024, 1024 * 1024);
    let mut graph = Vec::new();
    let mut blobs = Vec::new();
    case.write_snapshot(&mut graph, &mut blobs, limits)?;
    let (restored_case, _) = Case::from_snapshot(graph.as_slice(), blobs.as_slice(), limits)?;
    let mut restored = restore(&restored_case, &checkpoint)?;
    assert_eq!(
        restored.pop_next()?.map(RecoveryCandidateId::index),
        Some(0)
    );
    Ok(())
}

#[test]
fn checkpoint_rejects_secret_recipe_in_completed_ancestor() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let receipt = node(&mut case, b"receipt")?;
    let child = node(&mut case, b"child")?;
    link(&mut case, receipt, input)?;
    link(&mut case, child, receipt)?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    let parent = queued(coordinator.enqueue(
        &case,
        input,
        RecoveryTask::transform(Operation::XorRepeat {
            key: b"ancestor-secret".to_vec(),
            offset: 0,
        }),
    )?)?;
    coordinator.pop_next()?;
    coordinator.finish(
        &case,
        parent,
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        },
    )?;
    queued(coordinator.enqueue_derived(
        parent,
        &case,
        &[child],
        RecoveryTask::EmbeddedDiscovery,
    )?)?;
    assert!(capture(&coordinator, &case).is_err());
    Ok(())
}

#[test]
fn restore_rejects_invalid_proposal_associations_and_collection_limits() -> TestResult {
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: Vec::new(),
    };
    coordinator.admit_transform_proposal_association(input, &recipe)?;
    let encoded = capture(&coordinator, &case)?;
    let saved = String::from_utf8(encoded.clone())?;
    let report_field = format!("\"report_node_id\":{input}");
    let unknown_report = saved.replacen(&report_field, "\"report_node_id\":999", 1);
    assert!(
        restore(&case, unknown_report.as_bytes()).is_err(),
        "unknown report node"
    );
    let association = saved
        .split_once("\"associations\":[")
        .ok_or("missing associations")?
        .1
        .strip_suffix("]}")
        .ok_or("missing association end")?;
    let duplicated = saved.replacen(
        &format!("\"associations\":[{association}]"),
        &format!("\"associations\":[{association},{association}]"),
        1,
    );
    assert!(
        restore(&case, duplicated.as_bytes()).is_err(),
        "duplicate association"
    );
    let original: Value = serde_json::from_slice(&encoded)?;
    assert_invalid_checkpoint(
        &case,
        &original,
        &[(
            "/candidates/0/inputs/0/origin_node_ids",
            json!(vec![input; policy().max_origins_per_candidate + 1]),
        )],
        "too many origins",
    )?;
    let safe_identity = serde_json::to_string(&RecoveryTask::Transform(recipe))?;
    let secret_identity = serde_json::to_string(&RecoveryTask::transform(Operation::XorRepeat {
        key: vec![1, 2, 3],
        offset: 0,
    }))?;
    let injected = saved.replacen(
        &format!("\"identity\":{safe_identity}"),
        &format!("\"identity\":{secret_identity}"),
        1,
    );
    assert_ne!(injected, saved);
    assert!(
        matches!(
            restore(&case, injected.as_bytes()),
            Err(l2_workbench::recovery::RecoveryError::CheckpointSecret)
        ),
        "injected proposal key"
    );
    Ok(())
}

#[test]
fn checkpoint_stream_handles_partial_writes_and_destination_failure() -> TestResult {
    struct FragmentedWriter {
        bytes: Vec<u8>,
        remaining: Option<usize>,
    }
    impl std::io::Write for FragmentedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == Some(0) {
                return Err(std::io::Error::other("destination failed"));
            }
            let count = bytes.len().min(3).min(self.remaining.unwrap_or(usize::MAX));
            let part = bytes
                .get(..count)
                .ok_or_else(|| std::io::Error::other("invalid fragment"))?;
            self.bytes.extend_from_slice(part);
            if let Some(remaining) = &mut self.remaining {
                *remaining -= count;
            }
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut case = Case::new();
    let input = node(&mut case, b"input")?;
    let mut coordinator = RecoveryCoordinator::new(policy());
    queued(coordinator.enqueue(&case, input, RecoveryTask::EmbeddedDiscovery)?)?;
    let expected = capture(&coordinator, &case)?;
    let mut fragments = FragmentedWriter {
        bytes: Vec::new(),
        remaining: None,
    };
    assert_eq!(
        coordinator.write_checkpoint(&case, &mut fragments, expected.len())?,
        expected.len()
    );
    assert_eq!(fragments.bytes, expected);
    let mut failing = FragmentedWriter {
        bytes: Vec::new(),
        remaining: Some(17),
    };
    assert_eq!(
        coordinator.write_checkpoint(&case, &mut failing, MAX_CHECKPOINT_BYTES),
        Err(l2_workbench::recovery::RecoveryError::CheckpointWrite)
    );
    assert_eq!(failing.bytes.len(), 17);
    Ok(())
}
