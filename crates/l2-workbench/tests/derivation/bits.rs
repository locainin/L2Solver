use super::support::run_steps;
use l2_workbench::derivation::{
    BitRemainder, DerivationError, DerivationStatus, MAX_RECIPE_PARAMETER_BYTES, Operation, Recipe,
    StepFailure, StepStatus, run,
};
use std::error::Error;

#[test]
fn selected_bit_low_output_bits() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        &[0b1011_0010, 0b0110_1001],
        vec![Operation::SelectBits {
            indices: vec![0, 2, 4, 7, 8, 9, 11, 15],
            bits_per_byte: 4,
        }],
    )?;

    assert_eq!(report.output, [0b1100, 0b0101]);
    Ok(())
}

#[test]
fn bit_selection_width_boundaries() -> Result<(), Box<dyn Error>> {
    let one_bit = run_steps(
        &[0b1011_0010],
        vec![Operation::SelectBits {
            indices: (0..8).collect(),
            bits_per_byte: 1,
        }],
    )?;
    let seven_bits = run_steps(
        &[0b1011_0010],
        vec![Operation::SelectBits {
            indices: (0..7).collect(),
            bits_per_byte: 7,
        }],
    )?;
    let eight_bits = run_steps(
        &[0b1011_0010],
        vec![Operation::SelectBits {
            indices: (0..8).collect(),
            bits_per_byte: 8,
        }],
    )?;

    assert_eq!(one_bit.output, [1, 0, 1, 1, 0, 0, 1, 0]);
    assert_eq!(seven_bits.output, [0b101_1001]);
    assert_eq!(eight_bits.output, [0b1011_0010]);
    Ok(())
}

#[test]
fn bit_selection_repeated_reordered_positions() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        &[0b1000_0001, 0b0110_0101],
        vec![Operation::SelectBits {
            indices: vec![15, 0, 15, 8, 6, 0, 8, 1],
            bits_per_byte: 4,
        }],
    )?;

    assert_eq!(report.output, [0b1110, 0b0100]);
    Ok(())
}

#[test]
fn empty_bit_valid_supported_widths() -> Result<(), Box<dyn Error>> {
    for bits_per_byte in [1, 7, 8] {
        for input in [b"input".as_slice(), &[]] {
            let report = run_steps(
                input,
                vec![Operation::SelectBits {
                    indices: Vec::new(),
                    bits_per_byte,
                }],
            )?;
            assert_eq!(report.status, DerivationStatus::Completed);
            assert_eq!(report.output.len(), 0);
        }
    }
    Ok(())
}

#[test]
fn invalid_bit_widths_empty_arithmetic() -> Result<(), Box<dyn Error>> {
    for bits_per_byte in [0, 9, u8::MAX] {
        let report = run_steps(
            b"input",
            vec![Operation::SelectBits {
                indices: Vec::new(),
                bits_per_byte,
            }],
        )?;
        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, b"input");
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed {
                error: StepFailure::InvalidBitsPerByte { bits_per_byte: value }
            }) if *value == bits_per_byte
        ));
    }
    Ok(())
}

#[test]
fn incomplete_bit_without_padding_truncation() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        &[0b1011_0010],
        vec![Operation::SelectBits {
            indices: vec![0, 1, 2],
            bits_per_byte: 2,
        }],
    )?;

    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    assert_eq!(report.output, [0b1011_0010]);
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::IncompleteBitGroup {
                selected_bits: 3,
                bits_per_byte: 2,
            }
        })
    ));
    Ok(())
}

#[test]
fn compact_bit_stride_phase_width() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        &[0b1011_0010, 0b0110_1001],
        vec![Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 16,
            stride_bits: 2,
            phase: 1,
            bits_per_byte: 4,
            remainder: BitRemainder::Reject,
        }],
    )?;

    assert_eq!(report.output, [0b0100, 0b1001]);
    Ok(())
}

#[test]
fn compact_bit_explicit_remainder_policy() -> Result<(), Box<dyn Error>> {
    let input = [0b1011_0010];
    let dropped = run_steps(
        &input,
        vec![Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 3,
            stride_bits: 1,
            phase: 0,
            bits_per_byte: 2,
            remainder: BitRemainder::Drop,
        }],
    )?;
    let zero_filled = run_steps(
        &input,
        vec![Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 3,
            stride_bits: 1,
            phase: 0,
            bits_per_byte: 2,
            remainder: BitRemainder::ZeroFill,
        }],
    )?;
    let one_filled = run_steps(
        &input,
        vec![Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 3,
            stride_bits: 1,
            phase: 0,
            bits_per_byte: 2,
            remainder: BitRemainder::OneFill,
        }],
    )?;

    assert_eq!(dropped.output, [0b10]);
    assert_eq!(zero_filled.output, [0b10, 0b10]);
    assert_eq!(one_filled.output, [0b10, 0b11]);
    Ok(())
}

#[test]
fn compact_bit_invalid_incomplete_selections() -> Result<(), Box<dyn Error>> {
    for operation in [
        Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 4,
            stride_bits: 0,
            phase: 0,
            bits_per_byte: 1,
            remainder: BitRemainder::Reject,
        },
        Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 4,
            stride_bits: 2,
            phase: 2,
            bits_per_byte: 1,
            remainder: BitRemainder::Reject,
        },
    ] {
        let report = run_steps(&[0xff], vec![operation])?;
        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    }

    let incomplete = run_steps(
        &[0b1011_0010],
        vec![Operation::SelectBitRange {
            start_bit: 0,
            bit_count: 3,
            stride_bits: 1,
            phase: 0,
            bits_per_byte: 2,
            remainder: BitRemainder::Reject,
        }],
    )?;
    assert!(matches!(
        incomplete.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::IncompleteBitGroup {
                selected_bits: 3,
                bits_per_byte: 2,
            }
        })
    ));

    let out_of_range = run_steps(
        &[0xff],
        vec![Operation::SelectBitRange {
            start_bit: 7,
            bit_count: 2,
            stride_bits: 1,
            phase: 0,
            bits_per_byte: 1,
            remainder: BitRemainder::Reject,
        }],
    )?;
    assert!(matches!(
        out_of_range.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: StepFailure::BitRangeOutOfBounds { .. }
        })
    ));
    Ok(())
}

#[test]
fn bit_selection_index_input_size() -> Result<(), Box<dyn Error>> {
    let cases = [
        (&[0b1000_0001][..], 8, 8),
        (&[0b1000_0001][..], usize::MAX, 8),
        (&[][..], 0, 0),
    ];
    for (input, index, input_bits) in cases {
        let report = run_steps(
            input,
            vec![Operation::SelectBits {
                indices: vec![index],
                bits_per_byte: 1,
            }],
        )?;

        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, input);
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed {
                error: StepFailure::BitSelectionOutOfBounds {
                    index: observed,
                    input_bits: observed_input_bits,
                }
            }) if *observed == index && *observed_input_bits == input_bits
        ));
    }
    Ok(())
}

#[test]
fn bit_selection_recipe_parameter_limit() {
    let index_count = MAX_RECIPE_PARAMETER_BYTES / std::mem::size_of::<usize>() + 1;
    let recipe = Recipe {
        steps: vec![Operation::SelectBits {
            indices: vec![0; index_count],
            bits_per_byte: 1,
        }],
        constraints: Vec::new(),
    };

    assert_eq!(
        run(b"", &recipe),
        Err(DerivationError::RecipeParametersTooLarge {
            limit: MAX_RECIPE_PARAMETER_BYTES,
        })
    );
}

#[test]
fn failed_bit_selection_later_steps() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        b"bits",
        vec![
            Operation::SelectBits {
                indices: vec![0],
                bits_per_byte: 2,
            },
            Operation::Reverse {},
        ],
    )?;

    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    assert_eq!(report.output, b"bits");
    assert!(matches!(
        report.steps.get(1).map(|step| &step.status),
        Some(StepStatus::Skipped { after_step: 0 })
    ));
    Ok(())
}
