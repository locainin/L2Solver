use l2_discovery::dns::{DnsErrorKind, DnsValue, decode};

use crate::support::{append_question, append_record, header, labels, pointer, range_bytes};

#[test]
fn empty_message_preserves_header_fields() -> Result<(), &'static str> {
    let bytes = header(0x4a21, 0x8183, 0, 0, 0, 0);
    let message = decode(&bytes).map_err(|_| "empty DNS message should decode")?;

    assert_eq!(message.id, 0x4a21);
    assert_eq!(message.flags, 0x8183);
    assert_eq!(message.questions, [] as [l2_discovery::dns::DnsQuestion; 0]);
    assert_eq!(message.records, [] as [l2_discovery::dns::DnsRecord; 0]);
    assert!(message.is_response());
    assert_eq!(message.opcode(), 0);
    assert_eq!(message.response_code(), 3);
    Ok(())
}

#[test]
fn dns_root_wire_encoding() -> Result<(), &'static str> {
    let bytes = question_with_name(&[0]);
    let message = decode(&bytes).map_err(|_| "root question should decode")?;
    let name = &message.questions.first().ok_or("question missing")?.name;

    assert_eq!(name.wire(), [0]);
    assert_eq!(name.canonical(), [0]);
    assert_eq!(name.to_string(), ".");
    Ok(())
}

#[test]
fn name_wire_canonical_folds_ascii() -> Result<(), &'static str> {
    let original = labels(&[b"MiXeD", b"a.b", b"c\\d", &[0, 0xff, b'Z']])?;
    let bytes = question_with_name(&original);
    let message = decode(&bytes).map_err(|_| "binary-label question should decode")?;
    let name = &message.questions.first().ok_or("question missing")?.name;

    assert_eq!(name.wire(), original);
    assert_eq!(
        name.canonical(),
        labels(&[b"mixed", b"a.b", b"c\\d", &[0, 0xff, b'z']])?
    );
    assert_eq!(name.to_string(), "MiXeD.a\\.b.c\\\\d.\\000\\255Z.");
    Ok(())
}

#[test]
fn compressed_questions_expand_uncompressed_names() -> Result<(), &'static str> {
    let mut bytes = header(0x1248, 0x0100, 6, 0, 0, 0);
    let first = labels(&[b"Example", b"Test"])?;
    let first_offset = bytes.len();
    append_question(&mut bytes, &first, 1, 1);

    // A suffix pointer may begin at any previously decoded label boundary
    let suffix_offset = first_offset
        .checked_add(8)
        .ok_or("suffix offset overflow")?;
    let second_offset = bytes.len();
    append_question(&mut bytes, &pointer(suffix_offset)?, 28, 1);

    let third_offset = bytes.len();
    let third_pointer_offset = third_offset
        .checked_add(4)
        .ok_or("pointer offset overflow")?;
    let mut third = vec![3];
    third.extend_from_slice(b"www");
    third.extend_from_slice(&pointer(suffix_offset)?);
    append_question(&mut bytes, &third, 1, 1);

    append_question(&mut bytes, &pointer(second_offset)?, 1, 1);
    append_question(&mut bytes, &pointer(third_pointer_offset)?, 1, 1);
    let root_offset = first_offset
        .checked_add(first.len() - 1)
        .ok_or("root offset overflow")?;
    append_question(&mut bytes, &pointer(root_offset)?, 1, 1);

    let message = decode(&bytes).map_err(|_| "backward compression chain should decode")?;
    let questions = &message.questions;
    let [
        first_question,
        second_question,
        third_question,
        fourth_question,
        fifth_question,
        sixth_question,
    ] = questions.as_slice()
    else {
        return Err("expected exactly six questions");
    };
    assert_eq!(first_question.name.wire(), first);
    assert_eq!(second_question.name.wire(), labels(&[b"Test"])?);
    assert_eq!(third_question.name.wire(), labels(&[b"www", b"Test"])?);
    assert_eq!(fourth_question.name.wire(), second_question.name.wire());
    assert_eq!(fifth_question.name.wire(), second_question.name.wire());
    assert_eq!(sixth_question.name.wire(), [0]);
    Ok(())
}

#[test]
fn exact_maximum_oversized_name_rejected() -> Result<(), &'static str> {
    // The 255-byte wire limit includes label lengths and the final root byte
    let accepted_name = labels(&[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &[b'd'; 61]])?;
    assert_eq!(accepted_name.len(), 255);
    let accepted = question_with_name(&accepted_name);
    let decoded = decode(&accepted).map_err(|_| "255-byte wire name should decode")?;
    assert_eq!(
        decoded
            .questions
            .first()
            .ok_or("question missing")?
            .name
            .wire(),
        accepted_name
    );

    let oversized_name = labels(&[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &[b'd'; 62]])?;
    assert_eq!(oversized_name.len(), 256);
    let oversized = question_with_name(&oversized_name);
    let Err(error) = decode(&oversized) else {
        return Err("256-byte wire name should be rejected");
    };
    let prefix = labels(&[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63]])?;
    assert_eq!(error.kind, DnsErrorKind::NameLimit);
    assert_eq!(error.offset, 12 + prefix.len() - 1);
    Ok(())
}

#[test]
fn compression_invalid_unsupported_label_forms() -> Result<(), &'static str> {
    for target in [0_usize, 11, 12, 14, 0x3fff] {
        let mut bytes = header(1, 0, 1, 0, 0, 0);
        bytes.extend_from_slice(&pointer(target)?);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        assert!(
            decode(&bytes).is_err(),
            "invalid compression target {target} accepted"
        );
    }

    for label_form in [0x40, 0x80] {
        let mut bytes = header(1, 0, 1, 0, 0, 0);
        bytes.extend_from_slice(&[label_form, 0, 1, 0, 1]);
        assert!(
            decode(&bytes).is_err(),
            "unsupported label form {label_form:#04x} accepted"
        );
    }
    Ok(())
}

#[test]
fn compression_pointer_cannot_scalar_fields() -> Result<(), &'static str> {
    let mut bytes = header(3, 0, 2, 0, 0, 0);
    let first_name = labels(&[&[0]])?;
    append_question(&mut bytes, &first_name, 256, 1);
    // Offset 15 is the first question's QTYPE, whose bytes resemble a wire name
    bytes.extend_from_slice(&pointer(15)?);
    bytes.extend_from_slice(&256_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());

    assert!(decode(&bytes).is_err());
    Ok(())
}

#[test]
fn compression_pointer_cannot_label_contents() -> Result<(), &'static str> {
    let mut bytes = header(6, 0, 2, 0, 0, 0);
    let first_offset = bytes.len();
    append_question(&mut bytes, &[3, 1, b'x', 0, 0], 1, 1);
    // The label body also parses as a name, but its first byte is not a boundary
    bytes.extend_from_slice(&pointer(first_offset + 1)?);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());

    assert!(decode(&bytes).is_err());
    Ok(())
}

#[test]
fn compression_pointer_cannot_opaque_rdata() -> Result<(), &'static str> {
    let mut bytes = header(4, 0, 0, 2, 0, 0);
    let opaque_name_like = labels(&[b"not-a-decoded-name"])?;
    let opaque_range = append_record(&mut bytes, &[0], 65000, 1, 0, &opaque_name_like)?;
    let second_owner = pointer(opaque_range.start)?;
    append_record(&mut bytes, &second_owner, 65001, 1, 0, &[])?;

    let error = decode(&bytes)
        .err()
        .ok_or("unparsed compression target should stay unresolved")?;
    assert_eq!(error.kind, DnsErrorKind::UnsupportedNameTarget);
    Ok(())
}

#[test]
fn valid_name_chain_entry_limit() -> Result<(), &'static str> {
    let mut bytes = header(5, 0, 0, 64, 0, 0);
    let base_name = labels(&[b"base"])?;
    let mut previous_rdata_offset = None;

    for _ in 0..64 {
        let owner_offset = bytes.len();
        let owner = match previous_rdata_offset {
            Some(offset) => pointer(offset)?.to_vec(),
            None => base_name.clone(),
        };
        let rdata = pointer(owner_offset)?;
        let rdata_range = append_record(&mut bytes, &owner, 5, 1, 60, &rdata)?;
        previous_rdata_offset = Some(rdata_range.start);
    }

    let message = decode(&bytes).map_err(|_| "valid decoded-name chain should fit the limit")?;
    assert_eq!(message.records.len(), 64);
    for record in &message.records {
        assert_eq!(record.name.wire(), base_name);
        assert_eq!(record.value, DnsValue::Name(record.name.clone()));
    }
    Ok(())
}

#[test]
fn truncated_trailing_message_bytes_rejected() -> Result<(), &'static str> {
    let name = labels(&[b"truncated", b"example"])?;
    let complete = question_with_name(&name);
    for length in 0..complete.len() {
        let prefix = range_bytes(&complete, 0, length)?;
        assert!(
            decode(prefix).is_err(),
            "truncated prefix of length {length} accepted"
        );
    }

    let mut trailing = complete;
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    Ok(())
}

#[test]
fn entry_limit_counts_questions_together() -> Result<(), &'static str> {
    let mut within_limit = header(2, 0, 63, 0, 0, 1);
    let root = [0];
    for _ in 0..63 {
        append_question(&mut within_limit, &root, 1, 1);
    }
    append_record(&mut within_limit, &root, 65000, 1, 0, &[])?;
    assert_eq!(
        decode(&within_limit)
            .map_err(|_| "64 total entries should decode")?
            .questions
            .len(),
        63
    );

    let mut over_limit = header(2, 0, 63, 0, 0, 2);
    for _ in 0..63 {
        append_question(&mut over_limit, &root, 1, 1);
    }
    append_record(&mut over_limit, &root, 65000, 1, 0, &[])?;
    append_record(&mut over_limit, &root, 65001, 1, 0, &[])?;
    assert!(decode(&over_limit).is_err());
    Ok(())
}

fn question_with_name(name: &[u8]) -> Vec<u8> {
    let mut bytes = header(0x0110, 0, 1, 0, 0, 0);
    append_question(&mut bytes, name, 1, 1);
    bytes
}
