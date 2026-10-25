use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use l2_workbench::{
    derivation::Constraint,
    hypothesis::{CandidateStatus, Family, KeyTestStatus, SearchPlan, search},
};
use std::{error::Error, io::Write};

const fn plan(families: Vec<Family>, constraints: Vec<Constraint>) -> SearchPlan {
    SearchPlan {
        families,
        constraints,
        max_depth: 3,
        max_candidates: 128,
    }
}

#[test]
fn known_plaintext_offset_stream_phase() -> Result<(), Box<dyn Error>> {
    let plaintext = b"payload bytes with a known middle section and a repeating key";
    let key = [0x19_u8, 0xA4, 0x5C, 0xE1];
    let stream_phase = 2;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (position, byte) in plaintext.iter().copied().enumerate() {
        let key_byte = key
            .get((stream_phase + position) % key.len())
            .copied()
            .ok_or("key phase out of bounds")?;
        ciphertext.push(byte ^ key_byte);
    }
    let known_offset = 7;
    let known_end = 27;
    let known = plaintext
        .get(known_offset..known_end)
        .ok_or("known plaintext extent")?;

    let report = search(
        &ciphertext,
        &plan(
            vec![Family::KnownPlaintextXor {
                offset: known_offset,
                bytes: known.to_vec(),
                key_lengths: vec![u16::try_from(key.len())?],
            }],
            vec![Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(plaintext),
            }],
        ),
    )?;

    let initial_key_test = report
        .key_tests
        .iter()
        .find(|test| test.parent_candidate == 0)
        .ok_or("missing key test for the captured ciphertext")?;
    assert_eq!(initial_key_test.status, KeyTestStatus::Consistent);
    assert_eq!(initial_key_test.offset, known_offset);
    assert_eq!(initial_key_test.holdout_bytes, known.len() - key.len());
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
        .ok_or("nonzero-offset XOR pipeline was not recovered")?;
    assert_eq!(candidate.output_sha256, l2_workbench::sha256(plaintext));
    Ok(())
}

#[test]
fn known_plaintext_correct_key_length() -> Result<(), Box<dyn Error>> {
    let plaintext = b"independent bytes make the wrong heldout plaintext detectable";
    let key = [0x13_u8, 0x72, 0xD9];
    let ciphertext: Vec<_> = plaintext
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect();
    let known_offset = 5;
    let known_end = 21;
    let mut wrong_known = plaintext
        .get(known_offset..known_end)
        .ok_or("known plaintext extent")?
        .to_vec();
    // Change a byte beyond both inferred periods so the holdout check must catch it
    let wrong_position = 7;
    let wrong_byte = wrong_known
        .get_mut(wrong_position)
        .ok_or("wrong plaintext byte extent")?;
    *wrong_byte ^= 1;

    let report = search(
        &ciphertext,
        &plan(
            vec![Family::KnownPlaintextXor {
                offset: known_offset,
                bytes: wrong_known,
                key_lengths: vec![3],
            }],
            vec![Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(plaintext),
            }],
        ),
    )?;

    let initial_key_tests: Vec<_> = report
        .key_tests
        .iter()
        .filter(|test| test.parent_candidate == 0)
        .collect();
    assert_eq!(initial_key_tests.len(), 1);
    assert!(initial_key_tests.iter().all(|test| {
        test.status == KeyTestStatus::Contradicted && test.first_mismatch == Some(wrong_position)
    }));
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| { candidate.status != CandidateStatus::ConstraintsSatisfied })
    );
    Ok(())
}

#[test]
fn layered_wrong_not_satisfied_candidate() -> Result<(), Box<dyn Error>> {
    let plaintext = b"the intended decoded bytes";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(plaintext)?;
    let input = STANDARD.encode(encoder.finish()?);
    let report = search(
        input.as_bytes(),
        &plan(
            vec![Family::Base64, Family::Gzip],
            vec![Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(b"a different expected result"),
            }],
        ),
    )?;

    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| { candidate.status != CandidateStatus::ConstraintsSatisfied })
    );
    assert!(report.candidates.iter().any(|candidate| {
        candidate.recipe.steps.len() == 2
            && candidate.status == CandidateStatus::ConstraintFailed
            && candidate.output_sha256 == l2_workbench::sha256(plaintext)
    }));
    Ok(())
}
