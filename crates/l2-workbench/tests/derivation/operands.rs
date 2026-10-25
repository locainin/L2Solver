use l2_workbench::{
    derivation::{
        AesGcmTagLayout, Constraint, ConstraintStatus, CounterByteOrder, CounterWidth,
        DerivationError, DerivationLimits, OperandLocation, OperandRef, Operation, Recipe,
        SeedCounterOrder, run, run_with_case,
    },
    evidence::Case,
};
use serde_json::json;
use std::error::Error;

const fn node_range(node_id: u64, offset: u64, length: u64) -> OperandRef {
    OperandRef::NodeRange {
        node_id,
        offset,
        length,
    }
}

const fn sha256_counter_xor(seed: OperandRef) -> Operation {
    Operation::Sha256CounterXor {
        seed,
        initial_counter: 0,
        counter_width: CounterWidth::OneByte,
        counter_byte_order: CounterByteOrder::BigEndian,
        seed_order: SeedCounterOrder::SeedThenCounter,
    }
}

const fn zero_aes_gcm_ciphertext_and_tag() -> [u8; 32] {
    [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
        0xbd, 0xdf,
    ]
}

#[test]
fn without_case_operands_recipe_locations() {
    let operation_recipe = Recipe {
        steps: vec![sha256_counter_xor(node_range(42, 0, 4))],
        constraints: Vec::new(),
    };
    assert_eq!(
        run(b"input", &operation_recipe),
        Err(DerivationError::EvidenceCaseRequired {
            location: OperandLocation::Step { step_index: 0 },
        })
    );

    let constraint_recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![Constraint::AesGcm {
            key: node_range(42, 0, 16),
            nonce: vec![0; 12].into(),
            associated_data: Vec::new().into(),
        }],
    };
    assert_eq!(
        run(b"input", &constraint_recipe),
        Err(DerivationError::EvidenceCaseRequired {
            location: OperandLocation::Constraint {
                constraint_index: 0,
            },
        })
    );
}

#[test]
fn selected_input_execution_api() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate", b"head:body", Vec::new(), json!({}))?;
    let recipe = Recipe {
        steps: vec![sha256_counter_xor(OperandRef::SelectedInputRange {
            offset: 0,
            length: 4,
        })],
        constraints: Vec::new(),
    };

    assert_eq!(
        run(b"head:body", &recipe),
        Err(DerivationError::SelectedInputRequired {
            location: OperandLocation::Step { step_index: 0 },
        })
    );
    assert_eq!(
        run_with_case(b"head:body", &recipe, &case, DerivationLimits::default()),
        Err(DerivationError::SelectedInputRequired {
            location: OperandLocation::Step { step_index: 0 },
        })
    );

    let report = l2_workbench::derivation::run_with_selected_input(
        input,
        &recipe,
        &case,
        DerivationLimits::default(),
    )?;
    let provenance = report
        .steps
        .first()
        .ok_or("selected input step is missing")?
        .operand_provenance
        .first()
        .ok_or("selected input operand provenance is missing")?;
    let input_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == input)
        .and_then(|node| node.blob.as_deref())
        .ok_or("selected input blob reference is missing")?;
    assert_eq!(provenance.provider_node, input);
    assert_eq!(provenance.provider_blob, input_blob);
    assert_eq!(provenance.offset, 0);
    assert_eq!(provenance.length, 4);
    assert_eq!(provenance.sha256, l2_workbench::sha256(b"head"));
    let json = serde_json::to_value(&report)?;
    assert_eq!(
        json.pointer("/steps/0/operation/seed/source"),
        Some(&json!("selected_input_range"))
    );
    assert_eq!(
        json.pointer("/steps/0/operand_provenance/0/provider_node"),
        Some(&json!(input))
    );
    Ok(())
}

#[test]
fn selected_input_out_bounds_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let metadata = case.add_node("metadata_only", None, Vec::new(), json!({}))?;
    let retained = case.add_bytes_node("candidate", b"abc", Vec::new(), json!({}))?;
    let recipe = Recipe {
        steps: vec![sha256_counter_xor(OperandRef::SelectedInputRange {
            offset: 2,
            length: 2,
        })],
        constraints: Vec::new(),
    };

    assert!(matches!(
        l2_workbench::derivation::run_with_selected_input(
            metadata,
            &recipe,
            &case,
            DerivationLimits::default()
        ),
        Err(DerivationError::SelectedInputBlobMissing { node_id }) if node_id == metadata
    ));
    assert_eq!(
        l2_workbench::derivation::run_with_selected_input(
            retained,
            &recipe,
            &case,
            DerivationLimits::default()
        ),
        Err(DerivationError::OperandRangeOutOfBounds {
            location: OperandLocation::Step { step_index: 0 },
            offset: 2,
            length: 2,
            blob_length: 3,
        })
    );
    Ok(())
}

#[test]
fn case_operation_original_reference_provenance() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let provider = case.add_bytes_node("seed_source", b"xxseedyy", Vec::new(), json!({}))?;
    let provider_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == provider)
        .and_then(|node| node.blob.as_deref())
        .ok_or("seed provider has no retained blob")?;
    let recipe = Recipe {
        steps: vec![sha256_counter_xor(node_range(provider, 2, 4))],
        constraints: Vec::new(),
    };

    let report = run_with_case(
        b"candidate bytes",
        &recipe,
        &case,
        DerivationLimits::default(),
    )?;
    let literal_report = run(
        b"candidate bytes",
        &Recipe {
            steps: vec![sha256_counter_xor(b"seed".to_vec().into())],
            constraints: Vec::new(),
        },
    )?;

    assert_eq!(report.output, literal_report.output);
    let original_operation = recipe.steps.first().ok_or("recipe operation is missing")?;
    let step = report.steps.first().ok_or("operation report is missing")?;
    assert_eq!(&step.operation, original_operation);
    let provenance = step
        .operand_provenance
        .first()
        .ok_or("operation provenance is missing")?;
    assert_eq!(provenance.provider_node, provider);
    assert_eq!(provenance.provider_blob, provider_blob);
    assert_eq!(provenance.offset, 2);
    assert_eq!(provenance.length, 4);
    assert_eq!(provenance.sha256, l2_workbench::sha256(b"seed"));

    let report_json = serde_json::to_value(&report)?;
    assert_eq!(
        report_json.pointer("/steps/0/operation/seed/source"),
        Some(&json!("node_range"))
    );
    assert_eq!(
        report_json.pointer("/steps/0/operation/seed/node_id"),
        Some(&json!(provider))
    );
    Ok(())
}

#[test]
fn case_aes_gcm_operation_operands() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let key = case.add_bytes_node("key", &[0; 16], Vec::new(), json!({}))?;
    let nonce = case.add_bytes_node("nonce", &[0; 12], Vec::new(), json!({}))?;
    let aad = case.add_bytes_node("aad", b"unused AAD", Vec::new(), json!({}))?;
    let recipe = Recipe {
        steps: vec![Operation::AesGcmDecrypt {
            key: node_range(key, 0, 16),
            nonce: node_range(nonce, 0, 12),
            associated_data: node_range(aad, 0, 0),
            tag_layout: AesGcmTagLayout::Appended,
        }],
        constraints: Vec::new(),
    };
    let ciphertext_and_tag = zero_aes_gcm_ciphertext_and_tag();

    let report = run_with_case(
        &ciphertext_and_tag,
        &recipe,
        &case,
        DerivationLimits::default(),
    )?;

    assert_eq!(report.output, [0; 16]);
    let original_operation = recipe.steps.first().ok_or("recipe operation is missing")?;
    let step = report.steps.first().ok_or("operation report is missing")?;
    assert_eq!(&step.operation, original_operation);
    assert_eq!(step.operand_provenance.len(), 3);
    Ok(())
}

#[test]
fn case_aes_constraint_operands_provenance() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let key = case.add_bytes_node("key", &[0; 16], Vec::new(), json!({}))?;
    let nonce = case.add_bytes_node("nonce", &[0; 12], Vec::new(), json!({}))?;
    let aad = case.add_bytes_node("aad", b"unused AAD", Vec::new(), json!({}))?;
    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![Constraint::AesGcm {
            key: node_range(key, 0, 16),
            nonce: node_range(nonce, 0, 12),
            associated_data: node_range(aad, 0, 0),
        }],
    };
    let ciphertext_and_tag = zero_aes_gcm_ciphertext_and_tag();

    let report = run_with_case(
        &ciphertext_and_tag,
        &recipe,
        &case,
        DerivationLimits::default(),
    )?;

    let original_constraint = recipe
        .constraints
        .first()
        .ok_or("recipe constraint is missing")?;
    let constraint = report
        .constraints
        .first()
        .ok_or("constraint report is missing")?;
    assert_eq!(constraint.status, ConstraintStatus::Satisfied);
    assert_eq!(&constraint.constraint, original_constraint);
    assert_eq!(constraint.operand_provenance.len(), 3);
    let report_json = serde_json::to_value(&report)?;
    assert_eq!(
        report_json.pointer("/constraints/0/constraint/key/source"),
        Some(&json!("node_range"))
    );
    assert_eq!(
        report_json.pointer("/constraints/0/constraint/key/node_id"),
        Some(&json!(key))
    );
    assert_eq!(
        report_json.pointer("/constraints/0/operand_provenance/0/provider_node"),
        Some(&json!(key))
    );
    Ok(())
}

#[test]
fn case_missing_out_bounds_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let provider = case.add_bytes_node("provider", b"bytes", Vec::new(), json!({}))?;
    let missing = u64::MAX;
    for (node_id, offset, length, expected) in [
        (
            missing,
            0,
            1,
            DerivationError::OperandNodeMissing {
                location: OperandLocation::Step { step_index: 0 },
                node_id: missing,
            },
        ),
        (
            provider,
            u64::MAX,
            1,
            DerivationError::OperandRangeOverflow {
                location: OperandLocation::Step { step_index: 0 },
                offset: u64::MAX,
                length: 1,
            },
        ),
        (
            provider,
            4,
            2,
            DerivationError::OperandRangeOutOfBounds {
                location: OperandLocation::Step { step_index: 0 },
                offset: 4,
                length: 2,
                blob_length: 5,
            },
        ),
    ] {
        let recipe = Recipe {
            steps: vec![sha256_counter_xor(node_range(node_id, offset, length))],
            constraints: Vec::new(),
        };
        assert_eq!(
            run_with_case(b"input", &recipe, &case, DerivationLimits::default()),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn case_declared_budget_resolving_ranges() {
    let recipe = Recipe {
        steps: vec![sha256_counter_xor(node_range(u64::MAX, 0, 2))],
        constraints: Vec::new(),
    };
    let limits = DerivationLimits {
        max_recipe_parameter_bytes: 1,
        ..DerivationLimits::default()
    };
    assert_eq!(
        run_with_case(b"input", &recipe, &Case::new(), limits),
        Err(DerivationError::RecipeParametersTooLarge { limit: 1 })
    );
}
