use l2_workbench::{
    protocol::{
        Direction, FramingKind, MessageContext, MessageOrigin, ProtocolLimits, StreamMessageParser,
        StreamTransitionState,
    },
    reconstruction::Origin,
};

pub fn exercise(input: &[u8]) {
    exercise_contiguous(input);
    exercise_gaps_and_overlapping_origins(input);
}

fn parser() -> StreamMessageParser {
    let Ok(parser) = StreamMessageParser::new(
        MessageContext {
            source: "fuzz-source".into(),
            scope: "fuzz-scope".into(),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        false,
        false,
        vec![
            FramingKind::Delimiter { byte: 10 },
            FramingKind::FixedSize { bytes: 7 },
        ],
        ProtocolLimits::default(),
    ) else {
        panic!("valid fuzz framing was rejected");
    };
    parser
}

fn exercise_contiguous(input: &[u8]) {
    let mut parser = parser();
    // Small generated chunks exercise boundaries and checkpoint resumption cheaply
    let mut offset = 0;
    for (index, chunk) in input.chunks(13).enumerate() {
        let origin = Origin {
            packet: u32::try_from(index + 1).unwrap(),
            frame_offset: 54,
            offset,
            length: chunk.len(),
        };
        parser.push_chunk(offset, chunk, &[origin]).unwrap();
        let encoded = serde_json::to_vec(&parser).unwrap();
        parser = serde_json::from_slice(&encoded).unwrap();
        offset += chunk.len();
    }
    if !input.is_empty() {
        // A checkpoint cannot reset consumed-byte accounting while keeping its observed offsets
        let mut checkpoint = serde_json::to_value(&parser).unwrap();
        *checkpoint.get_mut("total_input_bytes").unwrap() = serde_json::json!(0);
        let changed: StreamMessageParser = serde_json::from_value(checkpoint).unwrap();
        assert!(changed.into_report().is_err());
    }
    let report = parser.into_report().unwrap();
    for message in report.messages {
        assert_eq!(
            message.bytes.as_slice(),
            input
                .get(message.stream_range.start..message.stream_range.end)
                .unwrap()
        );
        assert_eq!(message.sha256, l2_workbench::sha256(&message.bytes));
        assert_eq!(
            message
                .origins
                .iter()
                .map(|origin| origin.length)
                .sum::<usize>(),
            message.bytes.len()
        );
    }
}

fn exercise_gaps_and_overlapping_origins(input: &[u8]) {
    let Some(first) = input.first() else {
        return;
    };
    let mut parser = parser();
    let segment_length = input.len().div_ceil(3);
    let gap_length = usize::from(*first % 32) + 1;
    let mut supplied = Vec::new();
    let mut input_start = 0;
    let mut stream_start = 0;
    let mut packet = 4;
    for (segment_index, segment) in input.chunks(segment_length).enumerate() {
        let shared_origin = Origin {
            packet: u32::try_from(segment_index + 1).unwrap(),
            frame_offset: 54 + input_start,
            offset: stream_start,
            length: segment.len(),
        };
        let mut consumed = 0;
        for chunk in segment.chunks(segment.len().div_ceil(2)) {
            let start = stream_start + consumed;
            let origin = Origin {
                packet,
                frame_offset: 54 + input_start + consumed,
                offset: start,
                length: chunk.len(),
            };
            // A full-segment alias may extend past the current chunk and repeat on resume
            parser
                .push_chunk(start, chunk, &[shared_origin.clone(), origin])
                .unwrap();
            supplied.push((start, chunk));
            let encoded = serde_json::to_vec(&parser).unwrap();
            parser = serde_json::from_slice(&encoded).unwrap();
            consumed += chunk.len();
            packet += 1;
        }
        input_start += segment.len();
        stream_start += segment.len() + gap_length;
    }

    let report = parser.into_report().unwrap();
    assert_eq!(report.input_bytes, input.len());
    let mut covered = vec![false; input.len()];
    for transition in &report.transitions {
        if transition.state == StreamTransitionState::SequenceGap {
            assert!(transition.origins.is_empty());
            assert!(transition.evidence_sha256.is_none());
            continue;
        }
        let bytes = observed_range(
            transition.stream_range.start,
            transition.stream_range.end,
            &supplied,
        );
        assert_eq!(
            transition.evidence_sha256.as_deref(),
            Some(l2_workbench::sha256(&bytes).as_str())
        );
        assert_origins(&bytes, &transition.origins, input, &mut covered);
    }
    for message in &report.messages {
        assert_eq!(
            message.bytes,
            observed_range(
                message.stream_range.start,
                message.stream_range.end,
                &supplied
            )
        );
        assert_origins(&message.bytes, &message.origins, input, &mut covered);
    }
    // Message boundaries and unresolved tails must account for every supplied byte
    assert!(covered.iter().all(|value| *value));
}

fn observed_range(start: usize, end: usize, supplied: &[(usize, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut next = start;
    for (offset, chunk) in supplied {
        let left = start.max(*offset);
        let right = end.min(offset + chunk.len());
        if left < right {
            assert_eq!(left, next);
            bytes.extend_from_slice(chunk.get(left - offset..right - offset).unwrap());
            next = right;
        }
    }
    assert_eq!(next, end);
    bytes
}

fn assert_origins(bytes: &[u8], origins: &[MessageOrigin], input: &[u8], covered: &mut [bool]) {
    let mut mapped = vec![false; bytes.len()];
    for origin in origins {
        let input_start = origin.frame_offset.checked_sub(54).unwrap();
        let input_end = input_start + origin.length;
        let message_end = origin.message_offset + origin.length;
        assert_eq!(
            input.get(input_start..input_end).unwrap(),
            bytes.get(origin.message_offset..message_end).unwrap()
        );
        covered.get_mut(input_start..input_end).unwrap().fill(true);
        mapped
            .get_mut(origin.message_offset..message_end)
            .unwrap()
            .fill(true);
    }
    // Overlapping origins are independent receipts, so coverage uses a union rather than a sum
    assert!(mapped.iter().all(|value| *value));
}
