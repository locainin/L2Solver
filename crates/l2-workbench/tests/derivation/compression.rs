use super::support::{gzip, run_steps, zlib};
use l2_workbench::derivation::{DerivationStatus, MAX_OUTPUT_BYTES, Operation, StepStatus};
use std::error::Error;

const PLAINTEXT: &[u8] = b"bounded compression fixture with repeated values";

#[test]
fn gzip_zlib_decode_complete_streams() -> Result<(), Box<dyn Error>> {
    for (encoded, operation) in [
        (gzip(PLAINTEXT)?, Operation::GzipDecompress {}),
        (zlib(PLAINTEXT)?, Operation::ZlibDecompress {}),
    ] {
        let report = run_steps(&encoded, vec![operation])?;
        assert_eq!(report.status, DerivationStatus::Completed);
        assert_eq!(report.output, PLAINTEXT);
    }
    Ok(())
}

#[test]
fn decompression_malformed_truncated_trailing_streams() -> Result<(), Box<dyn Error>> {
    let mut truncated_gzip = gzip(PLAINTEXT)?;
    let _removed_trailer = truncated_gzip.pop().ok_or("compressed stream is empty")?;
    let mut truncated_zlib = zlib(PLAINTEXT)?;
    let _removed_trailer = truncated_zlib.pop().ok_or("compressed stream is empty")?;
    let mut trailing_zlib = zlib(PLAINTEXT)?;
    trailing_zlib.extend_from_slice(&[0; 8192]);
    let mut trailing_gzip = gzip(PLAINTEXT)?;
    trailing_gzip.extend_from_slice(&[0; 8192]);

    for (input, operation) in [
        (&b"not gzip"[..], Operation::GzipDecompress {}),
        (&truncated_gzip, Operation::GzipDecompress {}),
        (&truncated_zlib, Operation::ZlibDecompress {}),
        (&trailing_gzip, Operation::GzipDecompress {}),
        (&trailing_zlib, Operation::ZlibDecompress {}),
    ] {
        let report = run_steps(input, vec![operation])?;
        assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
        assert_eq!(report.output, input);
        assert!(matches!(
            report.steps.first().map(|step| &step.status),
            Some(StepStatus::Failed { .. })
        ));
    }

    let mut multiple_members = gzip(PLAINTEXT)?;
    multiple_members.extend_from_slice(&gzip(PLAINTEXT)?);
    let report = run_steps(&multiple_members, vec![Operation::GzipDecompress {}])?;
    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    Ok(())
}

#[test]
fn decompression_accepts_exact_output_limit() -> Result<(), Box<dyn Error>> {
    let expanded = vec![0_u8; MAX_OUTPUT_BYTES];
    let compressed = gzip(&expanded)?;
    let report = run_steps(&compressed, vec![Operation::GzipDecompress {}])?;

    assert_eq!(report.status, DerivationStatus::Completed);
    assert_eq!(report.output, expanded);
    Ok(())
}

#[test]
fn decompression_stops_output_limit() -> Result<(), Box<dyn Error>> {
    let expanded = vec![0_u8; MAX_OUTPUT_BYTES + 1];
    let compressed = gzip(&expanded)?;
    let report = run_steps(&compressed, vec![Operation::GzipDecompress {}])?;

    assert_eq!(report.status, DerivationStatus::Failed { step_index: 0 });
    assert!(report.output.len() <= MAX_OUTPUT_BYTES);
    assert_eq!(report.output, compressed);
    Ok(())
}
