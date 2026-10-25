use super::support::run_steps;
use l2_workbench::derivation::{DerivationStatus, Operation, StepStatus};
use std::error::Error;

#[test]
fn repeating_xor_explicit_key_offset() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        &[0x10, 0x20, 0x30, 0x40],
        vec![Operation::XorRepeat {
            key: vec![1, 2, 3],
            offset: 1,
        }],
    )?;

    assert_eq!(report.output, [0x12, 0x23, 0x31, 0x42]);

    let large_offset = run_steps(
        &[0x10, 0x20, 0x30],
        vec![Operation::XorRepeat {
            key: vec![1, 2],
            offset: usize::MAX,
        }],
    )?;
    assert_eq!(large_offset.output, [0x12, 0x21, 0x32]);

    let empty_key = run_steps(
        b"input",
        vec![Operation::XorRepeat {
            key: Vec::new(),
            offset: 0,
        }],
    )?;
    assert_eq!(empty_key.status, DerivationStatus::Failed { step_index: 0 });
    assert_eq!(empty_key.output, b"input");
    Ok(())
}

#[test]
fn slice_selection_requested_byte() -> Result<(), Box<dyn Error>> {
    let sliced = run_steps(
        b"abcdef",
        vec![Operation::Slice {
            start: 2,
            length: Some(3),
        }],
    )?;
    assert_eq!(sliced.output, b"cde");

    let selected = run_steps(
        b"abcd",
        vec![Operation::Select {
            indices: vec![3, 0, 3, 1],
        }],
    )?;
    assert_eq!(selected.output, b"dadb");
    Ok(())
}

#[test]
fn slice_without_through_end_input() -> Result<(), Box<dyn Error>> {
    let recipe: l2_workbench::derivation::Recipe =
        serde_json::from_str(r#"{"steps":[{"kind":"slice","start":2}],"constraints":[]}"#)?;
    let report = l2_workbench::derivation::run(b"abcdef", &recipe)?;

    assert_eq!(report.output, b"cdef");
    let receipt = serde_json::to_value(&report)?;
    assert_eq!(
        receipt.pointer("/steps/0/operation/start"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(receipt.pointer("/steps/0/operation/length"), None);
    Ok(())
}

#[test]
fn reverse_permutation_each_requested_byte() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        b"abcd",
        vec![
            Operation::Reverse {},
            Operation::Permute {
                indices: vec![2, 0, 3, 1],
            },
        ],
    )?;

    assert_eq!(report.output, b"bdac");
    assert_eq!(report.steps.len(), 2);
    Ok(())
}

#[test]
fn invalid_permutation_without_last_bytes() -> Result<(), Box<dyn Error>> {
    for indices in [vec![0, 0, 2], vec![0, 1], vec![0, 1, 3]] {
        let report = run_steps(b"abc", vec![Operation::Permute { indices }])?;

        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, b"abc");
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed { .. })
        ));
    }
    Ok(())
}

#[test]
fn slice_selection_bounds_step_results() -> Result<(), Box<dyn Error>> {
    for operation in [
        Operation::Slice {
            start: 3,
            length: Some(1),
        },
        Operation::Slice {
            start: usize::MAX,
            length: Some(1),
        },
        Operation::Slice {
            start: 4,
            length: None,
        },
        Operation::Select { indices: vec![3] },
    ] {
        let report = run_steps(b"abc", vec![operation])?;
        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, b"abc");
    }
    Ok(())
}

#[test]
fn byte_wraps_across_value() -> Result<(), Box<dyn Error>> {
    let input: Vec<_> = (0..=u8::MAX).collect();
    let added = run_steps(&input, vec![Operation::ByteAdd { value: 1 }])?;
    let expected: Vec<_> = input.iter().map(|byte| byte.wrapping_add(1)).collect();
    assert_eq!(added.output, expected);

    let identity = run_steps(&input, vec![Operation::ByteAdd { value: 0 }])?;
    assert_eq!(identity.output, input);

    let reversed = run_steps(&added.output, vec![Operation::ByteAdd { value: u8::MAX }])?;
    assert_eq!(reversed.output, input);

    let empty = run_steps(&[], vec![Operation::ByteAdd { value: 173 }])?;
    assert!(empty.output.is_empty());
    Ok(())
}

#[test]
fn bit_rotation_byte_counts_inverse() -> Result<(), Box<dyn Error>> {
    let input: Vec<_> = (0..=u8::MAX).collect();
    let rotated = run_steps(&input, vec![Operation::RotateBits { count: u8::MAX }])?;
    let expected: Vec<_> = input.iter().map(|byte| byte.rotate_left(7)).collect();
    assert_eq!(rotated.output, expected);

    let inverse = run_steps(&rotated.output, vec![Operation::RotateBits { count: 1 }])?;
    assert_eq!(inverse.output, input);

    let identity = run_steps(&input, vec![Operation::RotateBits { count: 8 }])?;
    assert_eq!(identity.output, input);

    let empty = run_steps(&[], vec![Operation::RotateBits { count: 255 }])?;
    assert!(empty.output.is_empty());
    Ok(())
}
