use l2_workbench::{
    protocol::{
        Direction, FramingKind, MessageContext, ProtocolLimits, StreamExtractionReport,
        StreamMessageParser,
    },
    reconstruction::Origin,
};
use std::error::Error;

#[path = "../../../../../fuzz/fuzz_targets/workbench/stream_checkpoint_schedule.rs"]
mod schedule;

fn checkpoints(count: usize, selector: u8) -> Vec<usize> {
    (0..count)
        .filter(|&index| schedule::should_checkpoint(index, count, selector))
        .collect()
}

#[test]
fn small_inputs_checkpoint_after_every_chunk() {
    for count in 0..=schedule::MAX_CHECKPOINTS {
        let expected = (0..count).collect::<Vec<_>>();
        for selector in [0, 1, 127, 255] {
            assert_eq!(checkpoints(count, selector), expected);
        }
    }
}

#[test]
fn large_inputs_bound_checkpoints_and_include_first_last_and_interior() {
    for count in [9, 10, 11, 56, 315, 316, 4096] {
        for selector in [0, 1, 127, 255] {
            let selected = checkpoints(count, selector);
            assert!(selected.len() <= schedule::MAX_CHECKPOINTS);
            assert_eq!(selected.first(), Some(&0));
            assert_eq!(selected.last(), Some(&(count - 1)));
            assert!(selected.iter().any(|&index| index > 0 && index < count - 1));
        }
    }
    assert!(!schedule::should_checkpoint(0, 0, 0));
    assert!(!schedule::should_checkpoint(9, 9, 0));
    assert!(schedule::should_checkpoint(usize::MAX - 1, usize::MAX, 255));
}

#[test]
fn input_selector_changes_the_interior_checkpoint_positions() {
    assert_ne!(checkpoints(56, 0), checkpoints(56, 1));
}

fn report(input: &[u8], resume: bool) -> Result<(StreamExtractionReport, usize), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        MessageContext {
            source: "fuzz-source".into(),
            scope: "fuzz-scope".into(),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        false,
        false,
        vec![
            FramingKind::Delimiter { byte: b'\n' },
            FramingKind::FixedSize { bytes: 7 },
        ],
        ProtocolLimits::default(),
    )?;
    let count = input.len().div_ceil(schedule::CHUNK_BYTES);
    let selector = input.first().copied().unwrap_or_default();
    let mut offset = 0;
    let mut checkpoint_count = 0;
    for (index, chunk) in input.chunks(schedule::CHUNK_BYTES).enumerate() {
        let origin = Origin {
            packet: u32::try_from(index + 1)?,
            frame_offset: 54,
            offset,
            length: chunk.len(),
        };
        parser.push_chunk(offset, chunk, &[origin])?;
        if resume && schedule::should_checkpoint(index, count, selector) {
            parser = serde_json::from_slice(&serde_json::to_vec(&parser)?)?;
            checkpoint_count += 1;
        }
        offset += chunk.len();
    }
    Ok((parser.into_report()?, checkpoint_count))
}

#[test]
fn bounded_checkpoints_preserve_delimiter_dense_stream_report() -> Result<(), Box<dyn Error>> {
    // Delimiter-heavy input matches the shape of the saved timeout regression
    let input = (0..726)
        .map(|index| if index % 7 == 0 { b'x' } else { b'\n' })
        .collect::<Vec<_>>();
    let (uninterrupted, unchecked) = report(&input, false)?;
    let (resumed, checkpoints) = report(&input, true)?;
    assert_eq!(unchecked, 0);
    assert!((3..=schedule::MAX_CHECKPOINTS).contains(&checkpoints));
    assert_eq!(resumed, uninterrupted);
    assert_eq!(resumed.input_bytes, input.len());
    Ok(())
}
