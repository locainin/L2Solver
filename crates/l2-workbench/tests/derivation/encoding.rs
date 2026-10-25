use super::support::run_steps;
use l2_workbench::derivation::{
    Base64Alphabet, Base64Padding, DerivationStatus, HexCase, Operation, StepStatus,
};
use std::error::Error;

#[test]
fn hex_encodes_case_exact_bytes() -> Result<(), Box<dyn Error>> {
    let report = run_steps(
        b"A\xff",
        vec![
            Operation::HexEncode {
                case: HexCase::Upper,
            },
            Operation::HexDecode {},
        ],
    )?;

    let input_hash = l2_workbench::sha256(b"A\xff");
    let encoded_hash = l2_workbench::sha256(b"41FF");
    assert_eq!(report.status, DerivationStatus::Completed);
    assert_eq!(report.output, b"A\xff");
    assert_eq!(report.output_sha256, input_hash);
    let first_step = report.steps.first().ok_or("missing first step")?;
    assert_eq!(
        first_step.operation,
        Operation::HexEncode {
            case: HexCase::Upper,
        }
    );
    assert_eq!(first_step.input_length, Some(2));
    assert_eq!(
        first_step.input_sha256.as_deref(),
        Some(input_hash.as_str())
    );
    assert_eq!(first_step.output_length, Some(4));
    assert_eq!(
        first_step.output_sha256.as_deref(),
        Some(encoded_hash.as_str())
    );
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Applied)
    ));
    assert!(matches!(
        report.steps.get(1).map(|step| &step.status),
        Some(StepStatus::Applied)
    ));
    Ok(())
}

#[test]
fn malformed_hex_recipe_input() -> Result<(), Box<dyn Error>> {
    for malformed in [b"123".as_slice(), b"4g".as_slice()] {
        let report = run_steps(
            malformed,
            vec![Operation::HexDecode {}, Operation::Reverse {}],
        )?;

        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, malformed);
        assert_eq!(report.output_sha256, l2_workbench::sha256(malformed));
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed { .. })
        ));
        assert!(matches!(
            report.steps.get(1).map(|step| &step.status),
            Some(StepStatus::Skipped { after_step: 0 })
        ));
    }
    Ok(())
}

#[test]
fn base64_padding_alphabet_explicit() -> Result<(), Box<dyn Error>> {
    let standard = run_steps(
        b"QQ==",
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
    )?;
    assert_eq!(standard.output, b"A");

    let unpadded = run_steps(
        b"-_8",
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Forbidden,
        }],
    )?;
    assert_eq!(unpadded.output, [0xfb, 0xff]);

    let wrong_alphabet = run_steps(
        b"-_8",
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Forbidden,
        }],
    )?;
    assert_eq!(
        wrong_alphabet.status,
        DerivationStatus::Failed { step_index: 0 }
    );

    let missing_required_padding = run_steps(
        b"QQ",
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
    )?;
    assert_eq!(
        missing_required_padding.status,
        DerivationStatus::Failed { step_index: 0 }
    );

    let forbidden_padding = run_steps(
        b"QQ==",
        vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Forbidden,
        }],
    )?;
    assert_eq!(
        forbidden_padding.status,
        DerivationStatus::Failed { step_index: 0 }
    );
    Ok(())
}

#[test]
fn base64_encode_requested_alphabet_padding() -> Result<(), Box<dyn Error>> {
    let standard = run_steps(
        &[0xfb, 0xff],
        vec![Operation::Base64Encode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
    )?;
    assert_eq!(standard.output, b"+/8=");

    let url_safe = run_steps(
        &[0xfb, 0xff],
        vec![Operation::Base64Encode {
            alphabet: Base64Alphabet::UrlSafe,
            padding: Base64Padding::Forbidden,
        }],
    )?;
    assert_eq!(url_safe.output, b"-_8");
    Ok(())
}
