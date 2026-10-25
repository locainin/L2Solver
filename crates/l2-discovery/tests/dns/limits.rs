use l2_discovery::dns::{DnsError, DnsErrorKind, MAX_ENTRIES, MAX_MESSAGE_BYTES, decode};

use super::support::{append_question, append_record, header, root_name};

#[test]
fn impossible_section_incomplete_parser_budgets() -> Result<(), &'static str> {
    let below_entry_limit = header(1, 0, 1, 0, 0, 0);
    let below_limit_error = decode(&below_entry_limit)
        .err()
        .ok_or("missing question bytes were accepted")?;
    assert_eq!(
        below_limit_error,
        DnsError {
            kind: DnsErrorKind::Incomplete,
            offset: below_entry_limit.len(),
        }
    );

    let above_entry_limit =
        u16::try_from(MAX_ENTRIES + 1).map_err(|_| "entry limit does not fit in a DNS count")?;
    let above_limit = header(2, 0, above_entry_limit, 0, 0, 0);
    let above_limit_error = decode(&above_limit)
        .err()
        .ok_or("impossible question count was accepted")?;
    assert_eq!(
        above_limit_error,
        DnsError {
            kind: DnsErrorKind::Incomplete,
            offset: above_limit.len(),
        }
    );

    let above_record_limit = header(
        5,
        0,
        0,
        u16::try_from(MAX_ENTRIES + 1).map_err(|_| "entry limit does not fit in a DNS count")?,
        0,
        0,
    );
    let above_record_limit_error = decode(&above_record_limit)
        .err()
        .ok_or("impossible record count was accepted")?;
    assert_eq!(
        above_record_limit_error,
        DnsError {
            kind: DnsErrorKind::Incomplete,
            offset: above_record_limit.len(),
        }
    );
    Ok(())
}

#[test]
fn impossible_section_message_size_limit() -> Result<(), &'static str> {
    let input_length = MAX_MESSAGE_BYTES + 1;
    let minimum_question_count = (input_length - 12) / 5 + 1;
    let question_count = u16::try_from(minimum_question_count)
        .map_err(|_| "question count does not fit in a DNS header")?;
    let mut bytes = header(3, 0, question_count, 0, 0, 0);
    bytes.resize(input_length, 0);

    let error = decode(&bytes)
        .err()
        .ok_or("question section that cannot fit was accepted")?;
    assert_eq!(
        error,
        DnsError {
            kind: DnsErrorKind::Incomplete,
            offset: bytes.len(),
        }
    );
    Ok(())
}

#[test]
fn valid_minimum_section_entry_limit() -> Result<(), &'static str> {
    let question_count =
        u16::try_from(MAX_ENTRIES + 1).map_err(|_| "entry limit does not fit in a DNS count")?;
    let mut bytes = header(4, 0, question_count, 0, 0, 0);
    for _ in 0..question_count {
        append_question(&mut bytes, &root_name(), 1, 1);
    }

    let error = decode(&bytes)
        .err()
        .ok_or("over-budget question section was accepted")?;
    assert_eq!(
        error,
        DnsError {
            kind: DnsErrorKind::EntryLimit,
            offset: 4,
        }
    );
    Ok(())
}

#[test]
fn valid_minimum_section_entry_sized() -> Result<(), &'static str> {
    let record_count =
        u16::try_from(MAX_ENTRIES + 1).map_err(|_| "entry limit does not fit in a DNS count")?;
    let mut bytes = header(6, 0, 0, record_count, 0, 0);
    for _ in 0..record_count {
        append_record(&mut bytes, &root_name(), 1, 1, 0, &[])?;
    }

    let error = decode(&bytes)
        .err()
        .ok_or("over-budget record section was accepted")?;
    assert_eq!(
        error,
        DnsError {
            kind: DnsErrorKind::EntryLimit,
            offset: 4,
        }
    );
    Ok(())
}
