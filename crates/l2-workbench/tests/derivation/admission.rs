use super::{
    Base64Alphabet, Base64Padding, Constraint, DerivationLimits, DerivationReport,
    DerivationStatus, Operation, Recipe, STREAM_WORKSPACE_BYTES, StepFailure, StepReport,
    StepStatus,
    execute::{AdmittedDerivationError, run_with_memory},
    run_with_limits,
};
use crate::job::{MemoryBudget, MemoryClass, MemoryError};
use flate2::{Compression, GzBuilder, write::GzEncoder, write::ZlibEncoder};
use std::{error::Error, io::Write};

fn recipe(steps: Vec<Operation>) -> Recipe {
    Recipe {
        steps,
        constraints: Vec::new(),
    }
}

#[test]
fn xor_accounts_for_output_and_releases_failed_admission() -> Result<(), Box<dyn Error>> {
    let operations = vec![Operation::XorRepeat {
        key: vec![0x73],
        offset: 0,
    }];
    let input: Vec<_> = b"one\r\n&amp; two".iter().map(|byte| byte ^ 0x73).collect();
    let budget = MemoryBudget::new(32 * 1024);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 4)?;
    let report = run_with_memory(
        &input,
        &recipe(operations.clone()),
        generous_limits(),
        &mut memory,
    )?;
    assert_eq!(report.output, b"one\r\n&amp; two");
    assert!(memory.bytes() >= 4 + report_heap_bytes(&report)?);
    drop(report);
    memory.try_resize(4)?;
    let small = MemoryBudget::new(5);
    let mut denied = small.try_reserve(MemoryClass::Executor, 3)?;
    assert!(matches!(
        run_with_memory(&input, &recipe(operations), generous_limits(), &mut denied),
        Err(AdmittedDerivationError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(denied.bytes(), 3);
    assert_eq!(small.snapshot()?.used_bytes, 3);
    Ok(())
}

#[test]
fn direct_normalization_tracks_output_and_restores_denied_lease() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(128);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 7)?;
    let output = super::normalize_message_with_memory(b"A\r\n&amp;", &mut memory)?;
    assert_eq!(output, b"A\n&");
    assert!(memory.bytes() >= 7 + u64::try_from(output.capacity())?);
    assert_eq!(budget.snapshot()?.used_bytes, memory.bytes());
    let limited = MemoryBudget::new(7);
    let mut denied = limited.try_reserve(MemoryClass::Executor, 5)?;
    assert!(super::normalize_message_with_memory(b"A\r\n&amp;", &mut denied).is_err());
    assert_eq!(denied.bytes(), 5);
    assert_eq!(limited.snapshot()?.used_bytes, 5);
    Ok(())
}

#[test]
fn admitted_xor_reports_charge_cloned_key_material() -> Result<(), Box<dyn Error>> {
    let key = vec![0x57; 4096];
    let operation = Operation::XorRepeat { key, offset: 0 };
    let budget = MemoryBudget::new(metadata_charge(1)? + 1024);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 3)?;
    let result = run_with_memory(
        b"x",
        &recipe(vec![operation]),
        generous_limits(),
        &mut memory,
    );
    assert!(matches!(
        result,
        Err(AdmittedDerivationError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(memory.bytes(), 3);
    assert_eq!(budget.snapshot()?.used_bytes, 3);
    Ok(())
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn zlib(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn generous_limits() -> DerivationLimits {
    DerivationLimits {
        max_output_bytes: 512 * 1024 * 1024,
        max_intermediate_bytes: 512 * 1024 * 1024,
        max_work_bytes: 1024 * 1024 * 1024,
        ..DerivationLimits::default()
    }
}

fn metadata_charge(step_count: usize) -> Result<u64, Box<dyn Error>> {
    let mut steps = Vec::new();
    if step_count == 2 {
        steps.push(Operation::Slice {
            start: 0,
            length: Some(0),
        });
    }
    steps.push(Operation::HexDecode {});
    let budget = MemoryBudget::new(16 * 1024);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = run_with_memory(b"", &recipe(steps), generous_limits(), &mut memory)?;
    assert_eq!(report.output.capacity(), 0);
    assert!(memory.bytes() > 0);
    Ok(memory.bytes())
}

fn report_heap_bytes(report: &DerivationReport) -> Result<u64, Box<dyn Error>> {
    let mut bytes = report.output.capacity()
        + report.input_sha256.capacity()
        + report.output_sha256.capacity()
        + report.steps.capacity() * std::mem::size_of::<StepReport>();
    for step in &report.steps {
        bytes += step.input_sha256.as_ref().map_or(0, String::capacity);
        bytes += step.output_sha256.as_ref().map_or(0, String::capacity);
    }
    Ok(u64::try_from(bytes)?)
}

#[test]
fn denied_source_copy_returns_memory_error_and_preserves_incoming_charge()
-> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(12);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 7)?;
    let result = run_with_memory(
        b"414243",
        &recipe(vec![Operation::HexDecode {}]),
        DerivationLimits::default(),
        &mut memory,
    );

    assert!(matches!(
        result,
        Err(AdmittedDerivationError::Memory(MemoryError::Limit {
            requested: 6,
            ..
        }))
    ));
    assert_eq!(memory.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn metadata_denial_after_source_copy_restores_the_incoming_charge() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(14);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 7)?;
    let result = run_with_memory(
        b"414243",
        &recipe(vec![Operation::HexDecode {}]),
        DerivationLimits::default(),
        &mut memory,
    );

    match result {
        Err(AdmittedDerivationError::Memory(MemoryError::Limit {
            used, requested, ..
        })) => {
            assert!(used >= 7 + 6);
            assert!(requested > 1);
        }
        other => return Err(format!("expected metadata admission failure, got {other:?}").into()),
    }
    assert_eq!(memory.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn source_and_slice_overlap_until_the_source_buffer_is_dropped() -> Result<(), Box<dyn Error>> {
    let input = b"xx41424344zz";
    let steps = recipe(vec![
        Operation::Slice {
            start: 2,
            length: Some(8),
        },
        Operation::HexDecode {},
    ]);
    let metadata = metadata_charge(2)?;
    let budget = MemoryBudget::new(5 + metadata + 12 + 8 - 1);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 5)?;
    let result = run_with_memory(input, &steps, DerivationLimits::default(), &mut memory);

    assert!(matches!(
        result,
        Err(AdmittedDerivationError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(memory.bytes(), 5);
    assert_eq!(budget.snapshot()?.used_bytes, 5);

    let budget = MemoryBudget::new(metadata + 128);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 5)?;
    let report = run_with_memory(input, &steps, DerivationLimits::default(), &mut memory)?;
    assert_eq!(report.output, b"ABCD");
    assert!(memory.bytes() >= 5 + report_heap_bytes(&report)?);
    assert!(budget.snapshot()?.peak_bytes >= 5 + metadata + 12 + 8);
    drop(report);
    memory.try_resize(5)?;
    assert_eq!(budget.snapshot()?.used_bytes, 5);
    Ok(())
}

#[test]
fn base64_admits_decoder_capacity_not_only_final_length() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(2 + metadata_charge(1)? + 4 + 2);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 2)?;
    let result = run_with_memory(
        b"QQ==",
        &recipe(vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }]),
        DerivationLimits::default(),
        &mut memory,
    );

    assert!(matches!(
        result,
        Err(AdmittedDerivationError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(memory.bytes(), 2);
    assert_eq!(budget.snapshot()?.used_bytes, 2);
    Ok(())
}

#[test]
fn tiny_decompression_does_not_reserve_the_large_output_ceiling() -> Result<(), Box<dyn Error>> {
    for (input, operation) in [
        (gzip(b"small result")?, Operation::GzipDecompress {}),
        (zlib(b"small result")?, Operation::ZlibDecompress {}),
    ] {
        let ceiling =
            7 + metadata_charge(1)? + STREAM_WORKSPACE_BYTES + u64::try_from(input.len())? + 256;
        let budget = MemoryBudget::new(ceiling);
        let mut memory = budget.try_reserve(MemoryClass::Executor, 7)?;
        let report = run_with_memory(
            &input,
            &recipe(vec![operation]),
            generous_limits(),
            &mut memory,
        )?;

        assert_eq!(report.output, b"small result");
        assert!(memory.bytes() >= 7 + report_heap_bytes(&report)?);
        assert_eq!(budget.snapshot()?.used_bytes, memory.bytes());
        assert!(budget.snapshot()?.peak_bytes <= ceiling);
    }
    Ok(())
}

#[test]
fn gzip_workspace_covers_large_optional_header_fields() -> Result<(), Box<dyn Error>> {
    let mut encoder = GzBuilder::new()
        .extra(vec![b'e'; 65_535])
        .filename(vec![b'f'; 65_535])
        .comment(vec![b'c'; 65_535])
        .write(Vec::new(), Compression::default());
    encoder.write_all(b"data")?;
    let input = encoder.finish()?;
    let ceiling = metadata_charge(1)? + STREAM_WORKSPACE_BYTES + u64::try_from(input.len())? + 64;
    let budget = MemoryBudget::new(ceiling);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = run_with_memory(
        &input,
        &recipe(vec![Operation::GzipDecompress {}]),
        generous_limits(),
        &mut memory,
    )?;

    assert_eq!(report.output, b"data");
    assert!(memory.bytes() >= report_heap_bytes(&report)?);
    assert!(budget.snapshot()?.peak_bytes <= ceiling);
    Ok(())
}

#[test]
fn compressed_output_growth_denial_rolls_back_the_entire_attempt() -> Result<(), Box<dyn Error>> {
    let expanded = vec![b'x'; 32 * 1024];
    for (input, operation) in [
        (gzip(&expanded)?, Operation::GzipDecompress {}),
        (zlib(&expanded)?, Operation::ZlibDecompress {}),
    ] {
        let initial = 13;
        let input_bytes = u64::try_from(input.len())?;
        let metadata = metadata_charge(1)?;
        let ceiling = initial + metadata + STREAM_WORKSPACE_BYTES + input_bytes + 4096 + 8192 - 1;
        let budget = MemoryBudget::new(ceiling);
        let mut memory = budget.try_reserve(MemoryClass::Executor, initial)?;
        let result = run_with_memory(
            &input,
            &recipe(vec![operation]),
            generous_limits(),
            &mut memory,
        );

        match result {
            Err(AdmittedDerivationError::Memory(MemoryError::Limit {
                used, requested, ..
            })) => {
                assert!(used > initial + metadata + STREAM_WORKSPACE_BYTES + input_bytes);
                assert!(requested > 0);
            }
            other => return Err(format!("expected growth admission failure, got {other:?}").into()),
        }
        assert_eq!(memory.bytes(), initial);
        assert_eq!(budget.snapshot()?.used_bytes, initial);
    }
    Ok(())
}

#[test]
fn output_denial_after_slice_releases_both_owned_buffers() -> Result<(), Box<dyn Error>> {
    let expanded = vec![b'x'; 16 * 1024];
    let encoded = gzip(&expanded)?;
    let mut input = vec![b'!'; 512];
    input.extend_from_slice(&encoded);
    let initial = 11;
    let ceiling = initial
        + metadata_charge(2)?
        + STREAM_WORKSPACE_BYTES
        + u64::try_from(encoded.len())?
        + 4095;
    let budget = MemoryBudget::new(ceiling);
    let mut memory = budget.try_reserve(MemoryClass::Executor, initial)?;
    let result = run_with_memory(
        &input,
        &recipe(vec![
            Operation::Slice {
                start: 512,
                length: Some(encoded.len()),
            },
            Operation::GzipDecompress {},
        ]),
        generous_limits(),
        &mut memory,
    );

    assert!(matches!(
        result,
        Err(AdmittedDerivationError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(memory.bytes(), initial);
    assert_eq!(budget.snapshot()?.used_bytes, initial);
    Ok(())
}

#[test]
fn failed_step_keeps_the_last_successful_slice_charged() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(metadata_charge(2)? + 128);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 9)?;
    let report = run_with_memory(
        b"xx41GG44yy",
        &recipe(vec![
            Operation::Slice {
                start: 2,
                length: Some(6),
            },
            Operation::HexDecode {},
        ]),
        DerivationLimits::default(),
        &mut memory,
    )?;

    assert_eq!(report.status, DerivationStatus::Failed { step_index: 1 });
    assert_eq!(report.output, b"41GG44");
    assert!(matches!(
        report.steps.get(1).map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::InvalidHexDigit { offset: 2 }
        })
    ));
    assert!(memory.bytes() >= 9 + report_heap_bytes(&report)?);
    drop(report);
    memory.try_resize(9)?;
    assert_eq!(budget.snapshot()?.used_bytes, 9);
    Ok(())
}

#[test]
fn unsupported_recipe_is_rejected_without_changing_the_lease() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(128);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 3)?;
    let result = run_with_memory(
        b"4142",
        &recipe(vec![Operation::Reverse {}]),
        DerivationLimits::default(),
        &mut memory,
    );

    assert!(matches!(
        result,
        Err(AdmittedDerivationError::UnsupportedOperation)
    ));
    assert_eq!(memory.bytes(), 3);
    assert_eq!(budget.snapshot()?.used_bytes, 3);

    let mut constrained = recipe(vec![Operation::HexDecode {}]);
    constrained.constraints.push(Constraint::Utf8 {});
    assert!(matches!(
        run_with_memory(
            b"4142",
            &constrained,
            DerivationLimits::default(),
            &mut memory
        ),
        Err(AdmittedDerivationError::UnsupportedOperation)
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 3);
    Ok(())
}

#[test]
fn failed_slice_returns_source_and_marks_decoder_skipped() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(metadata_charge(2)? + 64);
    let mut memory = budget.try_reserve(MemoryClass::Executor, 4)?;
    let report = run_with_memory(
        b"4142",
        &recipe(vec![
            Operation::Slice {
                start: 9,
                length: None,
            },
            Operation::HexDecode {},
        ]),
        DerivationLimits::default(),
        &mut memory,
    )?;

    assert_eq!(report.output, b"4142");
    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::SliceOutOfBounds { .. }
        })
    ));
    assert!(matches!(
        report.steps.get(1).map(|step| &step.status),
        Some(StepStatus::Skipped { after_step: 0 })
    ));
    assert!(memory.bytes() >= 4 + report_heap_bytes(&report)?);
    Ok(())
}

#[test]
fn trailing_compressed_bytes_remain_a_step_failure() -> Result<(), Box<dyn Error>> {
    for (mut input, operation) in [
        (gzip(b"decoded")?, Operation::GzipDecompress {}),
        (zlib(b"decoded")?, Operation::ZlibDecompress {}),
    ] {
        input.extend_from_slice(b"tail");
        let budget = MemoryBudget::new(metadata_charge(1)? + STREAM_WORKSPACE_BYTES + 1024);
        let mut memory = budget.try_reserve(MemoryClass::Executor, 0)?;
        let report = run_with_memory(
            &input,
            &recipe(vec![operation]),
            generous_limits(),
            &mut memory,
        )?;
        assert_eq!(report.output, input);
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed {
                error: StepFailure::TrailingCompressedData
            })
        ));
        assert!(memory.bytes() >= report_heap_bytes(&report)?);
    }
    Ok(())
}

#[test]
fn admitted_and_legacy_runners_preserve_canonical_failures_and_budgets()
-> Result<(), Box<dyn Error>> {
    let mut gzip_trailing = gzip(b"decoded")?;
    gzip_trailing.extend_from_slice(b"tail");
    let mut zlib_trailing = zlib(b"decoded")?;
    zlib_trailing.extend_from_slice(b"tail");
    let base64 = Operation::Base64Decode {
        alphabet: Base64Alphabet::Standard,
        padding: Base64Padding::Required,
    };
    let small_output = DerivationLimits {
        max_output_bytes: 2,
        ..DerivationLimits::default()
    };
    let small_work = DerivationLimits {
        max_work_bytes: 8,
        ..DerivationLimits::default()
    };
    let cases = [
        (
            b"414243".to_vec(),
            Operation::HexDecode {},
            generous_limits(),
        ),
        (b"41GG".to_vec(), Operation::HexDecode {}, generous_limits()),
        (b"QQ==".to_vec(), base64.clone(), generous_limits()),
        (b"QQ".to_vec(), base64, generous_limits()),
        (
            gzip_trailing,
            Operation::GzipDecompress {},
            generous_limits(),
        ),
        (
            zlib_trailing,
            Operation::ZlibDecompress {},
            generous_limits(),
        ),
        (b"414243".to_vec(), Operation::HexDecode {}, small_output),
        (b"414243".to_vec(), Operation::HexDecode {}, small_work),
    ];

    for (input, operation, limits) in cases {
        let recipe = recipe(vec![operation]);
        let expected = run_with_limits(&input, &recipe, limits)?;
        let budget = MemoryBudget::new(metadata_charge(1)? + STREAM_WORKSPACE_BYTES + 4096);
        let mut memory = budget.try_reserve(MemoryClass::Executor, 0)?;
        let report = run_with_memory(&input, &recipe, limits, &mut memory)?;
        assert_eq!(report, expected, "input {input:?}");
        assert!(memory.bytes() >= report_heap_bytes(&report)?);
    }
    Ok(())
}
