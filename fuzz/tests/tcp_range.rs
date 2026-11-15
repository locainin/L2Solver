#[path = "../fuzz_targets/tcp_range.rs"]
pub mod target;

use l2_workbench::{
    evidence::MAX_NODES,
    tcp_range::{MAX_OBSERVATIONS, SpanStatus},
};
use std::error::Error;

fn append_segment(
    input: &mut Vec<u8>,
    offset: u32,
    flags: u8,
    frame_offset: u16,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    input.extend_from_slice(&offset.to_be_bytes());
    input.push(flags);
    input.extend_from_slice(&frame_offset.to_be_bytes());
    input.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    input.extend_from_slice(payload);
    Ok(())
}

fn alternating_seed(length: usize, with_omissions: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let first = vec![b'a'; length];
    let second: Vec<_> = (0..length)
        .map(|index| if index % 2 == 0 { b'a' } else { b'x' })
        .collect();
    let mut input = 0xffff_fff0_u32.to_be_bytes().to_vec();
    input.extend_from_slice(&u16::try_from(length - 1)?.to_be_bytes());
    append_segment(&mut input, 0, 0x10, 17, &first)?;
    append_segment(&mut input, 0, 0x10, 41, &second)?;
    if with_omissions {
        for _ in 2..MAX_OBSERVATIONS {
            append_segment(&mut input, 0, 0x02, 8, &[])?;
        }
        append_segment(&mut input, 1, 0x10, 11, b"b")?;
        append_segment(&mut input, u32::try_from(length - 1)?, 0x10, 12, b"c")?;
    }
    Ok(input)
}

#[test]
fn alternating_spans_omit_exact_suffix() -> Result<(), Box<dyn Error>> {
    let input = alternating_seed(MAX_NODES / 16 + 2, false)?;
    let (start, length, segments) = target::decode_input(&input).ok_or("invalid seed")?;
    let report = target::verify_range(start, length, &segments);
    assert_eq!(report.observed_bytes, length / 2);
    assert_eq!(report.conflicting_bytes, length / 2);
    assert_eq!(report.missing_bytes, 0);
    assert_eq!(report.omitted_bytes, 2);
    let suffix = report.spans.last().ok_or("missing suffix")?;
    assert_eq!(
        (suffix.offset, suffix.length, suffix.status),
        (length - 2, 2, SpanStatus::Omitted)
    );
    assert!(suffix.omitted_observation && suffix.bytes.is_none());
    assert_eq!(report.observations.len(), 2);
    assert_eq!(
        report
            .observations
            .get(1)
            .ok_or("missing source")?
            .payload_frame_offset,
        41
    );
    Ok(())
}

#[test]
fn omitted_suffix_and_observations_union() -> Result<(), Box<dyn Error>> {
    let input = alternating_seed(MAX_NODES / 16 + 2, true)?;
    let (start, length, segments) = target::decode_input(&input).ok_or("invalid seed")?;
    let report = target::verify_range(start, length, &segments);
    assert_eq!(report.omitted_observations, 2);
    assert_eq!(report.omitted_bytes, 3);
    assert_eq!(report.conflicting_bytes, length / 2);
    Ok(())
}

#[test]
fn span_limit_boundaries() -> Result<(), Box<dyn Error>> {
    let cap = MAX_NODES / 16;
    for length in [cap - 1, cap, cap + 1] {
        let input = alternating_seed(length, false)?;
        let (start, actual_length, segments) =
            target::decode_input(&input).ok_or("invalid seed")?;
        let report = target::verify_range(start, actual_length, &segments);
        assert_eq!(report.spans.len(), length);
        assert_eq!(report.omitted_bytes, usize::from(length > cap));
        assert_eq!(
            report.spans.last().ok_or("missing final span")?.status == SpanStatus::Omitted,
            length > cap
        );
    }
    Ok(())
}

fn rejects_with(f: impl FnOnce() + std::panic::UnwindSafe, expected: &str) {
    let Err(panic) = std::panic::catch_unwind(f) else {
        panic!("oracle accepted the corrupt report");
    };
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied());
    assert!(message.is_some_and(|message| message.contains(expected)));
}

#[test]
fn oracle_rejects_wrong_suffix_and_source() -> Result<(), Box<dyn Error>> {
    let input = alternating_seed(MAX_NODES / 16 + 2, false)?;
    let (start, length, segments) = target::decode_input(&input).ok_or("invalid seed")?;
    let mut report = target::verify_range(start, length, &segments);
    report.spans.last_mut().ok_or("missing suffix")?.status = SpanStatus::Gap;
    rejects_with(
        || target::check_report(start, length, &segments, &[true, true], &report),
        "detailed span exceeds limit",
    );
    let mut report = target::verify_range(start, length, &segments);
    report.spans.last_mut().ok_or("missing suffix")?.bytes = Some(vec![b'x']);
    rejects_with(
        || target::check_report(start, length, &segments, &[true, true], &report),
        "omitted suffix carries bytes",
    );
    let mut report = target::verify_range(start, length, &segments);
    report
        .observations
        .get_mut(1)
        .ok_or("missing source")?
        .payload_frame_offset += 1;
    rejects_with(
        || target::check_report(start, length, &segments, &[true, true], &report),
        "source frame offset",
    );
    let mut report = target::verify_range(start, length, &segments);
    *report
        .observations
        .get_mut(1)
        .ok_or("missing source")?
        .bytes
        .last_mut()
        .ok_or("missing source byte")? = b'!';
    rejects_with(
        || target::check_report(start, length, &segments, &[true, true], &report),
        "source bytes",
    );
    let mut report = target::verify_range(start, length, &segments);
    report.conflicting_bytes -= 1;
    rejects_with(
        || target::check_report(start, length, &segments, &[true, true], &report),
        "range totals",
    );
    Ok(())
}
