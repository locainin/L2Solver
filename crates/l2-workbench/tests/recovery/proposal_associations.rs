use l2_workbench::{
    derivation::{
        Base64Alphabet, Base64Padding, DerivationError, DerivationLimits, Operation, Recipe,
    },
    recovery::{
        RecoveryCoordinator, RecoveryResource, RecoveryResourcePolicy,
        TransformProposalAssociationOutcome,
    },
};

const fn policy(max_transform_proposal_associations: usize) -> RecoveryResourcePolicy {
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
        max_candidate_task_identity_bytes: 1024 * 1024,
        max_transform_proposal_identity_bytes: 1024 * 1024,
        max_parent_links: 256,
        max_lineage_work: 4096,
        max_context_aliases: 4096,
        max_pending_origin_links: 4096,
        max_transform_proposal_associations,
    }
}

fn recipe(operation: Operation) -> Recipe {
    Recipe {
        steps: vec![operation],
        constraints: Vec::new(),
    }
}

#[test]
fn transform_proposal_associations_accept_exact_limit() {
    let mut coordinator = RecoveryCoordinator::new(policy(2));
    let hex = recipe(Operation::HexDecode {});
    let base64 = recipe(Operation::Base64Decode {
        alphabet: l2_workbench::derivation::Base64Alphabet::Standard,
        padding: l2_workbench::derivation::Base64Padding::Required,
    });

    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &hex),
        Ok(TransformProposalAssociationOutcome::Admitted)
    );
    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &base64),
        Ok(TransformProposalAssociationOutcome::Admitted)
    );
    assert_eq!(coordinator.transform_proposal_associations_charged(), 2);
    assert_eq!(coordinator.remaining_transform_proposal_associations(), 0);
}

#[test]
fn transform_proposal_identity_bytes_are_metered_and_exhaustion_is_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    let hex = recipe(Operation::HexDecode {});
    let base64 = recipe(Operation::Base64Decode {
        alphabet: Base64Alphabet::Standard,
        padding: Base64Padding::Required,
    });
    let hex_bytes = serde_json::to_vec(&l2_workbench::recovery::RecoveryTask::Transform(
        hex.clone(),
    ))?
    .len();
    let base64_bytes = serde_json::to_vec(&l2_workbench::recovery::RecoveryTask::Transform(
        base64.clone(),
    ))?
    .len();
    let mut resources = policy(8);
    resources.max_transform_proposal_identity_bytes = hex_bytes;
    let mut coordinator = RecoveryCoordinator::new(resources);

    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &hex)?,
        TransformProposalAssociationOutcome::Admitted
    );
    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &hex)?,
        TransformProposalAssociationOutcome::AlreadyRetained
    );
    assert_eq!(
        coordinator.transform_proposal_identity_bytes_charged(),
        hex_bytes
    );
    assert_eq!(coordinator.remaining_transform_proposal_identity_bytes(), 0);

    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &base64)?,
        TransformProposalAssociationOutcome::ResourceExhausted {
            resource: RecoveryResource::TransformProposalIdentityBytes,
            limit: hex_bytes,
            used: hex_bytes,
            requested: base64_bytes,
        }
    );
    assert_eq!(coordinator.transform_proposal_associations_charged(), 1);
    assert_eq!(
        coordinator.transform_proposal_identity_bytes_charged(),
        hex_bytes
    );

    Ok(())
}

#[test]
fn seven_canonical_transform_proposals_fit_the_exact_identity_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let recipes = l2_workbench::recovery::proposals::transform_proposal_operations()
        .map(recipe)
        .collect::<Vec<_>>();
    assert_eq!(
        recipes.len(),
        l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_OPERATION_COUNT
    );
    let mut identity_bytes = 0_usize;
    for recipe in &recipes {
        let serialized = serde_json::to_vec(&l2_workbench::recovery::RecoveryTask::Transform(
            recipe.clone(),
        ))?;
        identity_bytes = identity_bytes
            .checked_add(serialized.len())
            .ok_or_else(|| std::io::Error::other("seven proposal identity sizes overflowed"))?;
    }
    let mut resources = policy(recipes.len());
    resources.max_transform_proposal_identity_bytes = identity_bytes;
    let mut coordinator = RecoveryCoordinator::new(resources);

    for recipe in &recipes {
        assert_eq!(
            coordinator.admit_transform_proposal_association(10, recipe)?,
            TransformProposalAssociationOutcome::Admitted
        );
    }
    assert_eq!(
        coordinator.transform_proposal_associations_charged(),
        recipes.len()
    );
    assert_eq!(
        coordinator.transform_proposal_identity_bytes_charged(),
        identity_bytes
    );
    assert_eq!(coordinator.remaining_transform_proposal_identity_bytes(), 0);

    Ok(())
}

#[test]
fn oversized_transform_proposal_recipe_is_rejected_before_identity_encoding() {
    let limits = DerivationLimits::default();
    let oversized = Recipe {
        steps: vec![Operation::HexDecode {}; limits.max_steps + 1],
        constraints: Vec::new(),
    };
    let mut coordinator = RecoveryCoordinator::new(policy(8));

    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &oversized),
        Err(l2_workbench::recovery::RecoveryError::InvalidTaskIdentity(
            DerivationError::TooManySteps {
                count: limits.max_steps + 1,
                limit: limits.max_steps,
            }
        ))
    );
    assert_eq!(coordinator.transform_proposal_associations_charged(), 0);
    assert_eq!(coordinator.transform_proposal_identity_bytes_charged(), 0);
}

#[test]
fn exhausted_transform_proposal_association_does_not_increment_charge() {
    let mut coordinator = RecoveryCoordinator::new(policy(1));
    let hex = recipe(Operation::HexDecode {});
    let base64 = recipe(Operation::Base64Decode {
        alphabet: l2_workbench::derivation::Base64Alphabet::Standard,
        padding: l2_workbench::derivation::Base64Padding::Required,
    });
    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &hex),
        Ok(TransformProposalAssociationOutcome::Admitted)
    );

    assert_eq!(
        coordinator.admit_transform_proposal_association(10, &base64),
        Ok(TransformProposalAssociationOutcome::ResourceExhausted {
            resource: RecoveryResource::TransformProposalAssociations,
            limit: 1,
            used: 1,
            requested: 1,
        })
    );
    assert_eq!(coordinator.transform_proposal_associations_charged(), 1);
    assert_eq!(coordinator.remaining_transform_proposal_associations(), 0);
}

#[test]
fn transform_proposal_association_accounting_is_unique_and_deterministic() {
    let hex = recipe(Operation::HexDecode {});
    let other_hex = recipe(Operation::HexDecode {});
    let base64 = recipe(Operation::Base64Decode {
        alphabet: l2_workbench::derivation::Base64Alphabet::Standard,
        padding: l2_workbench::derivation::Base64Padding::Required,
    });
    let mut first = RecoveryCoordinator::new(policy(4));
    let mut second = RecoveryCoordinator::new(policy(4));

    for (coordinator, associations) in [
        (
            &mut first,
            [
                (10, &hex, TransformProposalAssociationOutcome::Admitted),
                (
                    10,
                    &other_hex,
                    TransformProposalAssociationOutcome::AlreadyRetained,
                ),
                (11, &hex, TransformProposalAssociationOutcome::Admitted),
                (10, &base64, TransformProposalAssociationOutcome::Admitted),
            ],
        ),
        (
            &mut second,
            [
                (10, &base64, TransformProposalAssociationOutcome::Admitted),
                (11, &hex, TransformProposalAssociationOutcome::Admitted),
                (10, &hex, TransformProposalAssociationOutcome::Admitted),
                (
                    10,
                    &other_hex,
                    TransformProposalAssociationOutcome::AlreadyRetained,
                ),
            ],
        ),
    ] {
        for (report_node_id, recipe, expected) in associations {
            assert_eq!(
                coordinator.admit_transform_proposal_association(report_node_id, recipe),
                Ok(expected)
            );
        }
    }

    assert_eq!(first.transform_proposal_associations_charged(), 3);
    assert_eq!(second.transform_proposal_associations_charged(), 3);
    assert_eq!(first.remaining_transform_proposal_associations(), 1);
    assert_eq!(second.remaining_transform_proposal_associations(), 1);
}
