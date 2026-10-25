use l2_workbench::measurement::{
    ByteOrder, LengthFieldCandidate, LengthMeaning, MessageSample, evaluate_constant_prefix,
    evaluate_length_fields,
};
use std::error::Error;

fn length_prefixed(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = u16::try_from(payload.len())?;
    let mut bytes = length.to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn messages_with_length_field(
    candidate: LengthFieldCandidate,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut messages = Vec::new();
    for message_length in [8_usize, 9, 10, 11] {
        let field_end = candidate
            .offset
            .checked_add(candidate.width)
            .ok_or("fixture field range overflow")?;
        let value = match candidate.meaning {
            LengthMeaning::WholeMessage => message_length,
            LengthMeaning::BytesAfterField => message_length
                .checked_sub(field_end)
                .ok_or("fixture field exceeds message length")?,
        };
        let encoded = match candidate.byte_order {
            ByteOrder::BigEndian => u64::try_from(value)?.to_be_bytes(),
            ByteOrder::LittleEndian => u64::try_from(value)?.to_le_bytes(),
        };
        let field_start = match candidate.byte_order {
            ByteOrder::BigEndian => encoded
                .len()
                .checked_sub(candidate.width)
                .ok_or("invalid field width")?,
            ByteOrder::LittleEndian => 0,
        };
        let encoded_end = field_start
            .checked_add(candidate.width)
            .ok_or("encoded field range overflow")?;
        let field = encoded
            .get(field_start..encoded_end)
            .ok_or("encoded field width is invalid")?;
        let mut message = vec![0xa5; message_length];
        let target = message
            .get_mut(candidate.offset..field_end)
            .ok_or("fixture field range is invalid")?;
        target.copy_from_slice(field);
        messages.push(message);
    }
    Ok(messages)
}

fn samples_with_prefix() -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    Ok(vec![
        length_prefixed(b"a")?,
        length_prefixed(b"bc")?,
        length_prefixed(b"def")?,
        length_prefixed(b"ghij")?,
    ])
}

fn views(samples: &[Vec<u8>]) -> Result<Vec<MessageSample<'_>>, Box<dyn Error>> {
    samples
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Ok(MessageSample::new(
                u64::try_from(index + 1)?,
                bytes.as_slice(),
            ))
        })
        .collect()
}

#[test]
fn explicit_length_separates_discovery_holdout() -> Result<(), Box<dyn Error>> {
    let bytes = samples_with_prefix()?;
    let samples = views(&bytes)?;
    let report = evaluate_length_fields(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|result| {
            result.candidate.offset == 0
                && result.candidate.width == 2
                && result.candidate.byte_order == ByteOrder::BigEndian
                && result.candidate.meaning == LengthMeaning::BytesAfterField
        })
        .ok_or("expected length-field candidate was not enumerated")?;
    assert_eq!(candidate.discovery.sample_count, 2);
    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.sample_count, 2);
    assert_eq!(candidate.holdout.supported, 2);
    assert_eq!(candidate.holdout.counterexample_count, 0);
    Ok(())
}

#[test]
fn length_fields_decode_supported_widths() -> Result<(), Box<dyn Error>> {
    let cases = [
        LengthFieldCandidate {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::BytesAfterField,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::BytesAfterField,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
            meaning: LengthMeaning::BytesAfterField,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 4,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 4,
            byte_order: ByteOrder::LittleEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 4,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::BytesAfterField,
        },
        LengthFieldCandidate {
            offset: 2,
            width: 4,
            byte_order: ByteOrder::LittleEndian,
            meaning: LengthMeaning::BytesAfterField,
        },
    ];

    for candidate in cases {
        let bytes = messages_with_length_field(candidate)?;
        let samples = views(&bytes)?;
        let report = evaluate_length_fields(&samples)?;
        let result = report
            .candidates
            .iter()
            .find(|result| result.candidate == candidate)
            .ok_or("expected nonzero-offset candidate is missing")?;

        assert_eq!(result.discovery.supported, 2);
        assert_eq!(result.holdout.supported, 2);
        assert_eq!(result.discovery.counterexample_count, 0);
        assert_eq!(result.holdout.counterexample_count, 0);
    }
    Ok(())
}

#[test]
fn held_out_reported_without_grammar() -> Result<(), Box<dyn Error>> {
    let mut bytes = samples_with_prefix()?;
    let final_sample = bytes.get_mut(3).ok_or("missing holdout sample")?;
    let payload = final_sample
        .get(2..)
        .ok_or("missing sample payload")?
        .to_vec();
    let mut wrong = 7_u16.to_be_bytes().to_vec();
    wrong.extend_from_slice(&payload);
    *final_sample = wrong;

    let samples = views(&bytes)?;
    let report = evaluate_length_fields(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|result| {
            result.candidate.offset == 0
                && result.candidate.width == 2
                && result.candidate.byte_order == ByteOrder::BigEndian
                && result.candidate.meaning == LengthMeaning::BytesAfterField
        })
        .ok_or("expected length-field candidate was not enumerated")?;
    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.supported, 1);
    assert_eq!(candidate.holdout.counterexample_count, 1);
    assert_eq!(
        candidate
            .holdout
            .counterexamples
            .first()
            .map(|item| item.sample),
        Some(4)
    );
    Ok(())
}

#[test]
fn constant_prefix_counterexamples_kept_holdout() -> Result<(), Box<dyn Error>> {
    let samples = vec![
        b"ABone".to_vec(),
        b"ABtwo".to_vec(),
        b"ABthree".to_vec(),
        b"XYfour".to_vec(),
    ];
    let samples = views(&samples)?;
    let result = evaluate_constant_prefix(&samples, 2)?;
    assert_eq!(result.discovery.supported, 2);
    assert_eq!(result.holdout.supported, 1);
    assert_eq!(result.holdout.counterexample_count, 1);
    assert_eq!(
        result
            .holdout
            .counterexamples
            .first()
            .map(|item| item.sample),
        Some(4)
    );
    Ok(())
}

#[test]
fn variable_length_sample_requirement() -> Result<(), Box<dyn Error>> {
    let too_few = vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()];
    let too_few = views(&too_few)?;
    assert!(evaluate_length_fields(&too_few).is_err());
    let constant_lengths = vec![
        b"aa".to_vec(),
        b"bb".to_vec(),
        b"cc".to_vec(),
        b"dd".to_vec(),
    ];
    let constant_lengths = views(&constant_lengths)?;
    assert!(evaluate_length_fields(&constant_lengths).is_err());
    Ok(())
}

#[test]
fn single_byte_length_order() -> Result<(), Box<dyn Error>> {
    let bytes = samples_with_prefix()?;
    let samples = views(&bytes)?;
    let report = evaluate_length_fields(&samples)?;

    assert_eq!(report.candidates.len(), 160);
    assert!(report.candidates.iter().all(|result| {
        result.candidate.width != 1 || result.candidate.byte_order == ByteOrder::BigEndian
    }));
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|result| result.candidate.width == 1)
            .count(),
        32
    );
    Ok(())
}

#[test]
fn repeated_samples_not_independent_corroboration() -> Result<(), Box<dyn Error>> {
    let bytes = vec![vec![2, 99], vec![3, 99, 99], vec![2, 99], vec![3, 99, 99]];
    let samples = views(&bytes)?;
    let report = evaluate_length_fields(&samples)?;
    assert!(
        report
            .candidates
            .iter()
            .any(|result| result.discovery.supported == 2 && result.holdout.supported == 2)
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|limit| limit.contains("repeated") && limit.contains("independent"))
    );
    Ok(())
}
