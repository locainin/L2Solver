use l2_workbench::derivation::{
    AesGcmTagLayout, CounterByteOrder, CounterWidth, DerivationError, DerivationLimits,
    DerivationStatus, Operation, Recipe, SecretBytes, SeedCounterOrder, StepFailure, StepStatus,
    run, run_with_limits,
};
use serde_json::json;
use std::error::Error;

#[test]
fn sha256_counter_width_endian_vectors() -> Result<(), Box<dyn Error>> {
    let input: Vec<u8> = (0_u8..33).collect();
    let cases = [
        (
            CounterWidth::OneByte,
            CounterByteOrder::BigEndian,
            SeedCounterOrder::SeedThenCounter,
            9,
            "8db5dd78220dd4087ccebed9cae6ef1b65bf2fb5f24d45bcc8ed29499af957a0cd",
        ),
        (
            CounterWidth::TwoBytes,
            CounterByteOrder::LittleEndian,
            SeedCounterOrder::CounterThenSeed,
            0x1234,
            "c2b76aadff2872dba7e70f69becdace073e83911bafae0560f080013c92df1362a",
        ),
        (
            CounterWidth::FourBytes,
            CounterByteOrder::BigEndian,
            SeedCounterOrder::SeedThenCounter,
            0x0102_0304,
            "de7571252c8329b1765c729d7fe542585f4f8c7c47d2b864c4a3d74b592eb75805",
        ),
        (
            CounterWidth::EightBytes,
            CounterByteOrder::LittleEndian,
            SeedCounterOrder::CounterThenSeed,
            0x0102_0304_0506_0708,
            "a95e996462a2868c6fc86e130509fb1132473566e1256a8b2a2e3fee27874ed529",
        ),
    ];

    for (counter_width, counter_byte_order, seed_order, initial_counter, expected_hex) in cases {
        let report = run(
            &input,
            &Recipe {
                steps: vec![Operation::Sha256CounterXor {
                    seed: SecretBytes::new(b"abc".to_vec()).into(),
                    initial_counter,
                    counter_width,
                    counter_byte_order,
                    seed_order,
                }],
                constraints: Vec::new(),
            },
        )?;

        assert_eq!(report.output, decode_hex(expected_hex)?);
        assert_eq!(report.status, DerivationStatus::Completed);
    }
    Ok(())
}

#[test]
fn sha256_counter_without_replacing_input() -> Result<(), Box<dyn Error>> {
    let base = |initial_counter| Operation::Sha256CounterXor {
        seed: SecretBytes::new(b"seed".to_vec()).into(),
        initial_counter,
        counter_width: CounterWidth::OneByte,
        counter_byte_order: CounterByteOrder::BigEndian,
        seed_order: SeedCounterOrder::SeedThenCounter,
    };

    let out_of_range = run(
        b"prior bytes",
        &Recipe {
            steps: vec![base(256)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(out_of_range.output, b"prior bytes");
    assert_eq!(
        out_of_range.status,
        DerivationStatus::Failed { step_index: 0 }
    );
    assert!(matches!(
        out_of_range.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::CounterValueOutOfRange { .. }
        })
    ));

    let exhausted = run(
        &[7_u8; 33],
        &Recipe {
            steps: vec![base(255)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(exhausted.output, [7_u8; 33]);
    assert_eq!(exhausted.status, DerivationStatus::Failed { step_index: 0 });
    assert!(matches!(
        exhausted.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::CounterExhausted
        })
    ));

    let final_counter_is_usable = run(
        &[7_u8; 32],
        &Recipe {
            steps: vec![base(255)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(final_counter_is_usable.output.len(), 32);
    assert_eq!(final_counter_is_usable.status, DerivationStatus::Completed);
    Ok(())
}

#[test]
fn aes_gcm_detached_tag_offset() -> Result<(), Box<dyn Error>> {
    let aes_128_ciphertext_and_tag =
        decode_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")?;
    let aes_128 = run(
        &aes_128_ciphertext_and_tag,
        &Recipe {
            steps: vec![aes_gcm_operation(vec![0; 16], AesGcmTagLayout::Appended)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(aes_128.output, [0_u8; 16]);
    assert_eq!(aes_128.status, DerivationStatus::Completed);

    let aes_256_ciphertext_and_tag =
        decode_hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")?;
    let aes_256 = run(
        &aes_256_ciphertext_and_tag,
        &Recipe {
            steps: vec![aes_gcm_operation(vec![0; 32], AesGcmTagLayout::Appended)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(aes_256.output, [0_u8; 16]);
    assert_eq!(aes_256.status, DerivationStatus::Completed);

    let ciphertext = aes_128_ciphertext_and_tag
        .get(..16)
        .ok_or("AES-128 fixture has no ciphertext")?;
    let tag = aes_128_ciphertext_and_tag
        .get(16..)
        .ok_or("AES-128 fixture has no authentication tag")?;
    let mut detached = tag.to_vec();
    detached.extend_from_slice(ciphertext);
    let detached_report = run(
        &detached,
        &Recipe {
            steps: vec![aes_gcm_operation(
                vec![0; 16],
                AesGcmTagLayout::Detached { tag_offset: 0 },
            )],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(detached_report.output, [0_u8; 16]);
    assert_eq!(detached_report.status, DerivationStatus::Completed);
    Ok(())
}

#[test]
fn aes_gcm_parameters_tag_ranges() -> Result<(), Box<dyn Error>> {
    let invalid_key = run(
        b"unchanged input",
        &Recipe {
            steps: vec![aes_gcm_operation(vec![0; 24], AesGcmTagLayout::Appended)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(invalid_key.output, b"unchanged input");
    assert!(matches!(
        invalid_key.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::InvalidAesGcmParameters
        })
    ));

    let short_input = run(
        b"too short",
        &Recipe {
            steps: vec![aes_gcm_operation(vec![0; 16], AesGcmTagLayout::Appended)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(short_input.output, b"too short");
    assert!(matches!(
        short_input.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::InvalidAesGcmLayout
        })
    ));

    let overflowing_offset = run(
        &[0_u8; 32],
        &Recipe {
            steps: vec![aes_gcm_operation(
                vec![0; 16],
                AesGcmTagLayout::Detached {
                    tag_offset: usize::MAX,
                },
            )],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(overflowing_offset.output, [0_u8; 32]);
    assert!(matches!(
        overflowing_offset.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::InvalidAesGcmLayout
        })
    ));
    Ok(())
}

#[test]
fn aes_gcm_bytes_authentication_failure() -> Result<(), Box<dyn Error>> {
    let mut invalid_ciphertext_and_tag =
        decode_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")?;
    let tag_byte = invalid_ciphertext_and_tag
        .last_mut()
        .ok_or("AES-GCM fixture is empty")?;
    *tag_byte ^= 1;

    let report = run(
        &invalid_ciphertext_and_tag,
        &Recipe {
            steps: vec![aes_gcm_operation(vec![0; 16], AesGcmTagLayout::Appended)],
            constraints: Vec::new(),
        },
    )?;

    assert_eq!(report.output, invalid_ciphertext_and_tag);
    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::AuthenticatedDecryptionFailed
        })
    ));

    let wrong_aad = run(
        &decode_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")?,
        &Recipe {
            steps: vec![Operation::AesGcmDecrypt {
                key: SecretBytes::new(vec![0; 16]).into(),
                nonce: vec![0; 12].into(),
                associated_data: b"caller supplied AAD".to_vec().into(),
                tag_layout: AesGcmTagLayout::Appended,
            }],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(wrong_aad.status, DerivationStatus::Failed { step_index: 0 });
    assert!(matches!(
        wrong_aad.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::AuthenticatedDecryptionFailed
        })
    ));
    Ok(())
}

#[test]
fn scrypt_derivation_password_salt_vector() -> Result<(), Box<dyn Error>> {
    let report = run(
        b"",
        &Recipe {
            steps: vec![scrypt_operation(Vec::new(), 4, 1, 1, 64)],
            constraints: Vec::new(),
        },
    )?;

    assert_eq!(
        report.output,
        decode_hex(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        )?
    );
    assert_eq!(report.status, DerivationStatus::Completed);
    assert_eq!(report.work_bytes, 2368);
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Applied)
    ));
    Ok(())
}

#[test]
fn scrypt_derivation_without_replacing_input() -> Result<(), Box<dyn Error>> {
    for operation in [
        scrypt_operation(Vec::new(), 4, 0, 1, 32),
        scrypt_operation(Vec::new(), 4, 1, 0, 32),
        scrypt_operation(Vec::new(), 4, 1, 1, 0),
    ] {
        let report = run(
            b"prior password bytes",
            &Recipe {
                steps: vec![operation],
                constraints: Vec::new(),
            },
        )?;

        assert_eq!(report.output, b"prior password bytes");
        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed {
                error: StepFailure::InvalidScryptParameters
            })
        ));
    }
    Ok(())
}

#[test]
fn scrypt_derivation_work_output_budgets() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![scrypt_operation(Vec::new(), 4, 1, 1, 64)],
        constraints: Vec::new(),
    };
    let estimated_work = (128 * 16) + (128 * 2);

    let work_limited = run_with_limits(
        b"",
        &recipe,
        DerivationLimits {
            max_work_bytes: estimated_work - 1,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(work_limited.output, b"");
    assert!(matches!(
        work_limited.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::WorkBudgetExceeded { .. }
        })
    ));

    let exact_work = run_with_limits(
        b"",
        &recipe,
        DerivationLimits {
            max_work_bytes: estimated_work + 64,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(exact_work.status, DerivationStatus::Completed);
    assert_eq!(exact_work.work_bytes, estimated_work + 64);

    let output_limited = run_with_limits(
        b"",
        &recipe,
        DerivationLimits {
            max_output_bytes: 63,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(output_limited.output, b"");
    assert!(matches!(
        output_limited.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::OutputLimitExceeded { limit: 63 }
        })
    ));

    let unrepresentable_work = run(
        b"",
        &Recipe {
            steps: vec![scrypt_operation(Vec::new(), u8::MAX, 1, 1, 32)],
            constraints: Vec::new(),
        },
    )?;
    assert_eq!(unrepresentable_work.output, b"");
    assert!(matches!(
        unrepresentable_work.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::WorkBudgetExceeded { .. }
        })
    ));
    Ok(())
}

#[test]
fn scrypt_salt_recipe_parameter_budget() {
    let recipe = Recipe {
        steps: vec![scrypt_operation(b"explicit salt".to_vec(), 4, 1, 1, 16)],
        constraints: Vec::new(),
    };
    assert_eq!(
        run_with_limits(
            b"password",
            &recipe,
            DerivationLimits {
                max_recipe_parameter_bytes: b"explicit salt".len() - 1,
                ..DerivationLimits::default()
            },
        ),
        Err(DerivationError::RecipeParametersTooLarge {
            limit: b"explicit salt".len() - 1,
        })
    );
}

#[test]
fn crypto_material_budget_redacted_receipts() -> Result<(), Box<dyn Error>> {
    let seed = b"secret seed".to_vec();
    let key = vec![0xa5; 16];
    let operation = Operation::AesGcmDecrypt {
        key: SecretBytes::new(key.clone()).into(),
        nonce: vec![0; 12].into(),
        associated_data: vec![1, 2, 3].into(),
        tag_layout: AesGcmTagLayout::Appended,
    };
    let recipe = Recipe {
        steps: vec![operation],
        constraints: Vec::new(),
    };
    let serialized = serde_json::to_value(&recipe)?;
    assert_eq!(
        serialized.pointer("/steps/0/key/byte_length"),
        Some(&json!(16))
    );
    assert_eq!(
        serialized.pointer("/steps/0/key/sha256"),
        Some(&json!(l2_workbench::sha256(&key)))
    );
    assert!(!format!("{:?}", recipe.steps).contains(&format!("{key:?}")));

    let sha_recipe = Recipe {
        steps: vec![Operation::Sha256CounterXor {
            seed: SecretBytes::new(seed.clone()).into(),
            initial_counter: 0,
            counter_width: CounterWidth::FourBytes,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }],
        constraints: Vec::new(),
    };
    let sha_serialized = serde_json::to_value(&sha_recipe)?;
    assert_eq!(
        sha_serialized.pointer("/steps/0/seed/byte_length"),
        Some(&json!(seed.len()))
    );
    assert_eq!(
        sha_serialized.pointer("/steps/0/seed/sha256"),
        Some(&json!(l2_workbench::sha256(&seed)))
    );
    assert!(!format!("{:?}", sha_recipe.steps).contains(&format!("{seed:?}")));

    let limits = DerivationLimits {
        max_recipe_parameter_bytes: 30,
        ..DerivationLimits::default()
    };
    assert_eq!(
        run_with_limits(b"", &recipe, limits),
        Err(DerivationError::RecipeParametersTooLarge { limit: 30 })
    );

    let seed_limits = DerivationLimits {
        max_recipe_parameter_bytes: seed.len() - 1,
        ..DerivationLimits::default()
    };
    assert_eq!(
        run_with_limits(b"", &sha_recipe, seed_limits),
        Err(DerivationError::RecipeParametersTooLarge {
            limit: seed.len() - 1
        })
    );
    Ok(())
}

fn budgeted_sha256_operation() -> Operation {
    Operation::Sha256CounterXor {
        seed: SecretBytes::new(b"seed".to_vec()).into(),
        initial_counter: 1,
        counter_width: CounterWidth::OneByte,
        counter_byte_order: CounterByteOrder::BigEndian,
        seed_order: SeedCounterOrder::SeedThenCounter,
    }
}

fn budgeted_sha256_recipe() -> Recipe {
    Recipe {
        steps: vec![budgeted_sha256_operation()],
        constraints: Vec::new(),
    }
}

#[test]
fn crypto_operations_intermediate_work_budgets() -> Result<(), Box<dyn Error>> {
    let input = [3_u8; 33];

    let output_limited = run_with_limits(
        &input,
        &budgeted_sha256_recipe(),
        DerivationLimits {
            max_output_bytes: 32,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(output_limited.output, input);
    assert!(matches!(
        output_limited.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::OutputLimitExceeded { limit: 32 }
        })
    ));

    let intermediate_input = [3_u8; 32];
    let intermediate_limited = run_with_limits(
        &intermediate_input,
        &Recipe {
            steps: vec![Operation::Reverse {}, budgeted_sha256_operation()],
            constraints: Vec::new(),
        },
        DerivationLimits {
            max_output_bytes: 64,
            max_intermediate_bytes: 32,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(intermediate_limited.output, intermediate_input);
    assert_eq!(
        intermediate_limited.intermediate_bytes,
        intermediate_input.len()
    );
    assert_eq!(
        intermediate_limited.status,
        DerivationStatus::Failed { step_index: 1 }
    );
    assert!(matches!(
        intermediate_limited.steps.get(1).map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::OutputLimitExceeded { limit: 0 }
        })
    ));

    let work_limited = run_with_limits(
        &input,
        &budgeted_sha256_recipe(),
        DerivationLimits {
            max_work_bytes: 75,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(work_limited.output, input);
    assert!(matches!(
        work_limited.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::WorkBudgetExceeded { limit: 75 }
        })
    ));

    let exact_work_budget = run_with_limits(
        &input,
        &budgeted_sha256_recipe(),
        DerivationLimits {
            max_work_bytes: 76,
            ..DerivationLimits::default()
        },
    )?;
    assert_eq!(exact_work_budget.output.len(), input.len());
    assert_eq!(exact_work_budget.work_bytes, 76);
    assert_eq!(exact_work_budget.status, DerivationStatus::Completed);
    Ok(())
}

fn aes_gcm_operation(key: Vec<u8>, tag_layout: AesGcmTagLayout) -> Operation {
    Operation::AesGcmDecrypt {
        key: SecretBytes::new(key).into(),
        nonce: vec![0; 12].into(),
        associated_data: Vec::new().into(),
        tag_layout,
    }
}

fn scrypt_operation(salt: Vec<u8>, log_n: u8, r: u32, p: u32, output_length: usize) -> Operation {
    Operation::ScryptDerive {
        salt: SecretBytes::new(salt).into(),
        log_n,
        r,
        p,
        output_length,
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex fixture has odd length".into());
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}
