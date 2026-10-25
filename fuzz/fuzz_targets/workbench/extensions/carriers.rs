use l2_workbench::{
    carrier::{
        Ambiguity, BitOrder, CompositionEncoding, CompositionField, CompositionPart,
        CompositionRecipe, PartialBytePadding, Rule, Sample, SourceReader, compose, extract,
    },
    evidence::{ByteMapping, SourceRange},
    sha256,
};
use std::io::Cursor;

pub(super) fn exercise(input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let id = format!("sha256:{}", sha256(input));
    let mut source =
        SourceReader::verify(id.clone(), input.len() as u64, Cursor::new(input.to_vec()))
            .unwrap_or_else(|_| panic!("bounded in-memory source verification failed"));
    let mappings = [ByteMapping {
        offset: 0,
        range: SourceRange {
            source: id.clone(),
            packet: None,
            offset: 0,
            length: input.len() as u64,
        },
    }];
    let sample = Sample {
        id: 1,
        event_id: Some("fuzz-event"),
        sequence: Some(1),
        length: input.len(),
        mappings: &mappings,
        time: None,
        ambiguity: Ambiguity::None,
    };
    let report = extract(
        std::slice::from_mut(&mut source),
        &[sample],
        &[
            Rule::Bytes,
            Rule::Bits {
                order: BitOrder::MostSignificantFirst,
            },
            Rule::Capitalization,
            Rule::MessageLength,
            Rule::Sequence,
        ],
    )
    .unwrap_or_else(|_| panic!("bounded mapped sample extraction failed"));
    assert!(report.complete);
    for observation in &report.observations {
        for range in &observation.ranges {
            assert_eq!(range.source, id);
            assert!(range.offset <= input.len() as u64);
            assert!(range.length <= input.len() as u64 - range.offset);
        }
    }
    let bits = CompositionPart {
        sample_ids: vec![1],
        rule: Rule::Bits {
            order: BitOrder::MostSignificantFirst,
        },
        component_index: None,
        field: CompositionField::Bits,
        encoding: CompositionEncoding::Bits {
            order: BitOrder::MostSignificantFirst,
            padding: PartialBytePadding::Reject,
        },
    };
    let recipe = CompositionRecipe {
        parts: vec![bits.clone()],
    };
    let output = compose(&report, &recipe).unwrap_or_else(|_| panic!("full bit projection failed"));
    assert_eq!(output.bytes(), Some(input));
    assert_eq!(
        output.receipt().output_sha256.as_deref(),
        Some(sha256(input).as_str())
    );

    // Missing selected data must never silently shorten a candidate byte stream
    let mut missing = bits.clone();
    missing.sample_ids = vec![2];
    let incomplete = CompositionRecipe {
        parts: vec![bits, missing],
    };
    let output = compose(&report, &incomplete)
        .unwrap_or_else(|_| panic!("missing selection was not reported"));
    assert!(!output.receipt().complete);
    assert!(output.bytes().is_none());
    assert!(output.receipt().output_sha256.is_none());
}
