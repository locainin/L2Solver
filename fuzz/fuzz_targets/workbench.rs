#![no_main]

use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_workbench::{
    application,
    derivation::{Base64Alphabet, Base64Padding, Constraint, HexCase, Operation, Recipe, run},
    evidence::{ByteMapping, Case, SourceRange},
    measurement::{
        Clock, MessageSample, TimedSample, evaluate_constant_prefix, evaluate_length_fields,
        measure_bytes, measure_timing,
    },
    reconstruction::{Limits, Reconstructor},
};
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/l2-workbench/tests/protocol/assembly_plan_fuzz.rs"]
mod assembly_plan_fuzz;
#[path = "workbench/extensions.rs"]
mod extensions;
#[path = "workbench/observation.rs"]
mod observation;
#[path = "workbench/recovery.rs"]
mod recovery;
#[path = "workbench/stream_messages.rs"]
mod stream_messages;

const MAX_FUZZ_INPUT_BYTES: usize = 4_096;
const MAX_RECIPE_INPUT_BYTES: usize = 512;
const MAX_RECONSTRUCTION_PAYLOAD_BYTES: usize = 1_024;

fuzz_target!(|data: &[u8]| {
    let input = bounded_input(data);
    exercise_application(input);
    exercise_measurements(input);
    exercise_derivations(input);
    exercise_evidence(input);
    exercise_reconstruction(input);
    extensions::exercise(input);
    observation::exercise(input);
    let assembly_plan_result = assembly_plan_fuzz::exercise(input);
    assert!(
        assembly_plan_result.is_ok(),
        "bounded assembly-plan property failed for input {input:?}: {assembly_plan_result:?}"
    );
    recovery::exercise(input);
    stream_messages::exercise(input);
});

fn bounded_input(data: &[u8]) -> &[u8] {
    // Keep parsers, recipes, and evidence work below their per-call ceilings
    let end = data.len().min(MAX_FUZZ_INPUT_BYTES);
    data.get(..end).unwrap_or_default()
}

fn exercise_application(input: &[u8]) {
    let report = application::inspect(
        input,
        input.first().is_some_and(|byte| byte & 1 != 0),
        input.last().is_some_and(|byte| byte & 1 != 0),
    );

    assert!(
        report
            .dns_tcp
            .unparsed
            .iter()
            .all(|range| range.slice(input).is_some())
    );
    assert!(
        report
            .dns_tcp
            .findings
            .iter()
            .all(|frame| frame.frame_range.slice(input).is_some())
    );
    assert!(
        report
            .dns_tcp
            .budget_omissions
            .iter()
            .all(|omission| omission.range.slice(input).is_some())
    );
    assert!(
        report
            .http
            .unparsed
            .iter()
            .all(|range| range.slice(input).is_some())
    );
    assert!(
        report
            .http
            .findings
            .iter()
            .all(|message| message.range.slice(input).is_some())
    );
    assert!(
        report
            .http
            .budget_omissions
            .iter()
            .all(|omission| omission.range.slice(input).is_some())
    );
    assert!(
        report
            .ftp
            .unparsed
            .iter()
            .all(|range| range.slice(input).is_some())
    );
    assert!(
        report
            .ftp
            .findings
            .iter()
            .all(|item| item.range.slice(input).is_some())
    );
    assert!(
        report
            .ftp
            .budget_omissions
            .iter()
            .all(|omission| omission.range.slice(input).is_some())
    );
}

fn exercise_measurements(input: &[u8]) {
    let half = input.len() / 2;
    let three_quarters = input.len().saturating_mul(3) / 4;
    let Some(first_half) = input.get(..half) else {
        return;
    };
    let _profile = measure_bytes(&[input, first_half]);

    let samples = [
        MessageSample::new(1, input),
        MessageSample::new(2, first_half),
        MessageSample::new(3, input.get(..three_quarters).unwrap_or_default()),
        MessageSample::new(4, input.get(..input.len() / 4).unwrap_or_default()),
    ];
    let _length_candidates = evaluate_length_fields(&samples);
    let _prefix_candidates = evaluate_constant_prefix(&samples, input.len().min(16));

    let Ok(clock) = Clock::new("fuzz-clock", "fuzz-scope", 10, 0, 0) else {
        return;
    };
    let samples = [
        TimedSample {
            packet: 1,
            clock: clock.clone(),
            ticks: input.first().map(|byte| u64::from(*byte)),
        },
        TimedSample {
            packet: 2,
            clock,
            ticks: input.last().map(|byte| u64::from(*byte)),
        },
    ];
    let _timing = measure_timing(&samples);
}

fn exercise_derivations(input: &[u8]) {
    let recipe_input = input
        .get(..input.len().min(MAX_RECIPE_INPUT_BYTES))
        .unwrap_or_default();
    let constraints = generated_constraints(recipe_input);

    // Run each operation alone so one rejected encoding cannot skip later paths
    for operation in generated_operations(input, recipe_input) {
        let recipe = Recipe {
            steps: vec![operation],
            constraints: constraints.clone(),
        };
        let report = run(recipe_input, &recipe)
            .unwrap_or_else(|_| panic!("bounded generated recipe exceeded its limits"));
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.constraints.len(), constraints.len());
        assert!(report.output.len() <= l2_workbench::derivation::MAX_OUTPUT_BYTES);
    }
}

fn generated_constraints(input: &[u8]) -> Vec<Constraint> {
    let prefix = input
        .get(..input.len().min(16))
        .unwrap_or_default()
        .to_vec();
    vec![
        Constraint::Length { bytes: input.len() },
        Constraint::Prefix { bytes: prefix },
        Constraint::Sha256 {
            expected_hex: l2_workbench::sha256(input),
        },
        Constraint::Utf8 {},
        Constraint::Json {},
    ]
}

fn generated_operations(input: &[u8], recipe_input: &[u8]) -> [Operation; 14] {
    let selection = input
        .iter()
        .take(32)
        .map(|byte| usize::from(*byte) % recipe_input.len().saturating_add(1))
        .collect();
    let permutation = (0..recipe_input.len()).rev().collect();
    let bit_indices = input
        .iter()
        .take(32)
        .map(|byte| usize::from(*byte) % recipe_input.len().saturating_mul(8).saturating_add(1))
        .collect();
    let key = input
        .get(..input.len().min(32))
        .unwrap_or_default()
        .to_vec();
    let start = input
        .first()
        .map(|byte| usize::from(*byte) % recipe_input.len().saturating_add(1))
        .unwrap_or_default();
    let slice_length = input.get(1).map_or(recipe_input.len(), |byte| {
        usize::from(*byte) % recipe_input.len().saturating_add(2)
    });
    let alphabet = if input.first().is_some_and(|byte| byte & 1 != 0) {
        Base64Alphabet::UrlSafe
    } else {
        Base64Alphabet::Standard
    };
    let padding = if input.get(1).is_some_and(|byte| byte & 1 != 0) {
        Base64Padding::Forbidden
    } else {
        Base64Padding::Required
    };
    [
        Operation::HexDecode {},
        Operation::HexEncode {
            case: if input.first().is_some_and(|byte| byte & 1 != 0) {
                HexCase::Upper
            } else {
                HexCase::Lower
            },
        },
        Operation::Base64Decode { alphabet, padding },
        Operation::Base64Encode { alphabet, padding },
        Operation::XorRepeat {
            key,
            offset: input.first().map_or(0, |byte| usize::from(*byte)),
        },
        Operation::ByteAdd {
            value: input.first().copied().unwrap_or_default(),
        },
        Operation::RotateBits {
            count: input.get(1).copied().unwrap_or_default(),
        },
        Operation::Slice {
            start,
            length: Some(slice_length),
        },
        Operation::Select { indices: selection },
        Operation::SelectBits {
            indices: bit_indices,
            bits_per_byte: input.get(2).copied().unwrap_or_default() % 10,
        },
        Operation::Reverse {},
        Operation::Permute {
            indices: permutation,
        },
        Operation::GzipDecompress {},
        Operation::ZlibDecompress {},
    ]
}

fn exercise_evidence(input: &[u8]) {
    if let Ok(case) = Case::from_json(input) {
        assert!(case.validate().is_ok());
        let encoded = case.to_json();
        assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            assert!(Case::from_json(&encoded).is_ok());
        }
    }

    let mut case = Case::new();
    let blob_id = case
        .add_blob(input)
        .unwrap_or_else(|_| panic!("bounded input did not fit an empty evidence case"));
    let Ok(length) = u64::try_from(input.len()) else {
        return;
    };
    let source_id = case.add_source(
        "fuzz-input.bin",
        "fuzz_input",
        length,
        &l2_workbench::sha256(input),
        Some(&blob_id),
    );
    let source_id = source_id
        .unwrap_or_else(|_| panic!("known source metadata was rejected for its retained blob"));
    exercise_mapped_evidence(&mut case, &source_id, input);
    assert!(case.validate().is_ok());

    let encoded = case.to_json();
    assert!(encoded.is_ok());
    if let Ok(encoded) = encoded {
        let restored = Case::from_json(&encoded);
        assert!(
            restored
                .as_ref()
                .is_ok_and(|loaded| loaded.validate().is_ok())
        );
    }
}

fn exercise_mapped_evidence(case: &mut Case, source_id: &str, input: &[u8]) {
    let Some((output, mappings)) = reordered_mapping(source_id, input) else {
        return;
    };
    let node_id = case
        .add_mapped_bytes_node(
            "fuzz-reordered-bytes",
            &output,
            &mappings,
            serde_json::json!({"mapping":"two reordered input ranges"}),
        )
        .unwrap_or_else(|_| panic!("valid bounded mapping was rejected"));
    check_mapped_receipt(case, node_id, source_id, &output, &mappings, input.len());

    let before_failure = case.clone();
    let Some(invalid_range) = mappings.first().map(|mapping| mapping.range.clone()) else {
        return;
    };
    let invalid_mapping = [ByteMapping {
        offset: output.len().saturating_add(1),
        range: invalid_range,
    }];
    assert!(
        case.add_mapped_bytes_node(
            "invalid-fuzz-mapping",
            &output,
            &invalid_mapping,
            serde_json::json!({})
        )
        .is_err()
    );
    assert_eq!(case, &before_failure);
}

fn reordered_mapping(source_id: &str, input: &[u8]) -> Option<(Vec<u8>, [ByteMapping; 2])> {
    if input.len() < 2 {
        return None;
    }
    let split = input.len() / 2;
    let later = input.get(split..)?;
    let earlier = input.get(..split)?;
    let split_offset = u64::try_from(split).ok()?;
    let later_length = u64::try_from(later.len()).ok()?;
    let earlier_length = u64::try_from(earlier.len()).ok()?;

    // Reordering two input slices forces a receipt with distinct output offsets
    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(later);
    output.extend_from_slice(earlier);
    let mappings = [
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id.to_owned(),
                packet: None,
                offset: split_offset,
                length: later_length,
            },
        },
        ByteMapping {
            offset: later.len(),
            range: SourceRange {
                source: source_id.to_owned(),
                packet: None,
                offset: 0,
                length: earlier_length,
            },
        },
    ];
    Some((output, mappings))
}

fn check_mapped_receipt(
    case: &Case,
    node_id: u64,
    source_id: &str,
    output: &[u8],
    mappings: &[ByteMapping; 2],
    input_length: usize,
) {
    let output_node = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id)
        .unwrap_or_else(|| panic!("mapped output node was not retained"));
    let output_blob_id = output_node
        .blob
        .as_deref()
        .unwrap_or_else(|| panic!("mapped output node has no blob"));
    let output_blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == output_blob_id)
        .unwrap_or_else(|| panic!("mapped output blob was not retained"));
    assert_eq!(output_blob.bytes, output);

    let receipt_id = case
        .edges()
        .iter()
        .find(|edge| edge.from == node_id && edge.relation == "mapped_by")
        .unwrap_or_else(|| panic!("reordered mapping has no receipt edge"))
        .to;
    let receipt_node = case
        .nodes()
        .iter()
        .find(|node| node.id == receipt_id)
        .unwrap_or_else(|| panic!("mapping receipt node was not retained"));
    assert_eq!(receipt_node.kind, "byte_mapping_receipt");
    assert_eq!(
        receipt_node
            .details
            .get("output_node")
            .and_then(serde_json::Value::as_u64),
        Some(node_id)
    );
    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .unwrap_or_else(|| panic!("mapping receipt has no blob"));
    let receipt_blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .unwrap_or_else(|| panic!("mapping receipt blob was not retained"));
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)
        .unwrap_or_else(|_| panic!("mapping receipt is not valid JSON"));
    let entries = receipt
        .as_array()
        .unwrap_or_else(|| panic!("mapping receipt is not an array"));
    assert_eq!(entries.len(), mappings.len());
    let input_length =
        u64::try_from(input_length).unwrap_or_else(|_| panic!("generated input length is invalid"));
    let output_length = u64::try_from(output.len())
        .unwrap_or_else(|_| panic!("generated output length is invalid"));
    for (entry, expected) in entries.iter().zip(mappings) {
        assert!(receipt_entry_matches(
            entry,
            expected,
            source_id,
            output_length,
            input_length
        ));
    }
}

fn receipt_entry_matches(
    entry: &serde_json::Value,
    expected: &ByteMapping,
    source_id: &str,
    output_length: u64,
    input_length: u64,
) -> bool {
    let Some(output_offset) = entry.get("offset").and_then(serde_json::Value::as_u64) else {
        return false;
    };
    let Ok(expected_offset) = u64::try_from(expected.offset) else {
        return false;
    };
    let Some(range) = entry.get("range") else {
        return false;
    };
    let Some(receipt_source) = range.get("source").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let Some(source_offset) = range.get("offset").and_then(serde_json::Value::as_u64) else {
        return false;
    };
    let Some(length) = range.get("length").and_then(serde_json::Value::as_u64) else {
        return false;
    };

    output_offset == expected_offset
        && receipt_source == source_id
        && range.get("packet").is_some_and(serde_json::Value::is_null)
        && source_offset == expected.range.offset
        && length == expected.range.length
        && output_offset
            .checked_add(length)
            .is_some_and(|end| end <= output_length)
        && source_offset
            .checked_add(length)
            .is_some_and(|end| end <= input_length)
}

fn exercise_reconstruction(input: &[u8]) {
    // Use paired fragments and TCP records with generated metadata and bounded payloads
    let Some(frames) = generated_frames(input) else {
        return;
    };
    let frame_lengths = frames
        .iter()
        .map(|frame| frame.bytes().len())
        .collect::<Vec<_>>();
    let report = reconstruct_frames(&frames)
        .unwrap_or_else(|_| panic!("generated bounded frames exceeded reconstruction limits"));
    check_reconstruction_report(&report, &frame_lengths);
    recovery::exercise_reconstructed_framing(&report);
}

fn generated_frames(input: &[u8]) -> Option<[CapturedFrame; 4]> {
    let bounded = input
        .get(..input.len().min(MAX_RECONSTRUCTION_PAYLOAD_BYTES))
        .unwrap_or_default();
    let tail = if bounded.is_empty() { &[0] } else { bounded };
    let interface = u32::from(byte_at(input, 10));
    let [first_fragment, last_fragment] = udp_fragments(input, interface, tail)?;
    let sequence = u32::from_be_bytes([
        byte_at(input, 0),
        byte_at(input, 1),
        byte_at(input, 2),
        byte_at(input, 3),
    ]);
    let syn = tcp_frame(input, interface, sequence, 0x02, &[])?;
    let payload = tcp_frame(input, interface, sequence.wrapping_add(1), 0x10, tail)?;
    Some([first_fragment, last_fragment, syn, payload])
}

fn reconstruct_frames(
    frames: &[CapturedFrame; 4],
) -> Result<
    l2_workbench::reconstruction::ReconstructionReport,
    l2_workbench::reconstruction::ReconstructionError,
> {
    let mut reconstructor = Reconstructor::with_limits(Limits {
        frames: 4,
        bytes: 8_192,
        units: 8,
        range_bytes: 65_536,
        sessions: 4,
        datagrams: 4,
        range_observations: 8,
        range_retained_bytes: 8_192,
    })?;

    for (packet, frame) in (1_u32..).zip(frames.iter()) {
        reconstructor.observe(packet, frame)?;
    }
    reconstructor.finish()
}

fn check_reconstruction_report(
    report: &l2_workbench::reconstruction::ReconstructionReport,
    frame_lengths: &[usize],
) {
    assert_eq!(report.frames, 4);
    assert_eq!(report.omitted_frames, 0);
    assert!(
        report
            .datagrams
            .iter()
            .flat_map(|item| &item.origins)
            .all(|origin| {
                origin_is_bounded(
                    origin.packet,
                    origin.frame_offset,
                    origin.length,
                    frame_lengths,
                )
            })
    );
    assert!(report.udp.iter().all(|message| {
        message.origins.iter().all(|origin| {
            origin_is_bounded(
                origin.packet,
                origin.frame_offset,
                origin.length,
                frame_lengths,
            ) && origin
                .offset
                .checked_add(origin.length)
                .is_some_and(|end| end <= message.bytes.len())
        })
    }));
    assert!(report.sessions.iter().all(|session| {
        session.directions.iter().all(|direction| {
            direction.origins.iter().all(|origin| {
                origin_is_bounded(
                    origin.packet,
                    origin.frame_offset,
                    origin.length,
                    frame_lengths,
                ) && direction.coverage.as_ref().is_some_and(|coverage| {
                    origin
                        .offset
                        .checked_add(origin.length)
                        .is_some_and(|end| end <= coverage.length)
                })
            })
        })
    }));
}

fn udp_fragments(input: &[u8], interface: u32, payload: &[u8]) -> Option<[CapturedFrame; 2]> {
    let udp_length = u16::try_from(8_usize.checked_add(payload.len())?).ok()?;
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(&[
        byte_at(input, 0),
        byte_at(input, 1),
        byte_at(input, 2),
        byte_at(input, 3),
    ]);
    header.extend_from_slice(&udp_length.to_be_bytes());
    header.extend_from_slice(&[0, 0]);

    let first = ipv4_frame(input, interface, 17, 0x2000, &header)?;
    let last = ipv4_frame(input, interface, 17, 1, payload)?;
    Some([first, last])
}

fn tcp_frame(
    input: &[u8],
    interface: u32,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Option<CapturedFrame> {
    let mut header = Vec::with_capacity(20 + payload.len());
    header.extend_from_slice(&[
        byte_at(input, 0),
        byte_at(input, 1),
        byte_at(input, 2),
        byte_at(input, 3),
    ]);
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&0_u32.to_be_bytes());
    header.extend_from_slice(&[0x50, flags, 0x10, 0, 0, 0, 0, 0]);
    header.extend_from_slice(payload);
    ipv4_frame(input, interface, 6, 0, &header)
}

fn ipv4_frame(
    input: &[u8],
    interface: u32,
    protocol: u8,
    fragment: u16,
    payload: &[u8],
) -> Option<CapturedFrame> {
    let total_length = u16::try_from(20_usize.checked_add(payload.len())?).ok()?;
    let mut bytes = Vec::with_capacity(14 + usize::from(total_length));
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    bytes.extend_from_slice(&total_length.to_be_bytes());
    bytes.extend_from_slice(&[byte_at(input, 8), byte_at(input, 9)]);
    bytes.extend_from_slice(&fragment.to_be_bytes());
    bytes.extend_from_slice(&[64, protocol, 0, 0]);
    bytes.extend_from_slice(&[
        byte_at(input, 12),
        byte_at(input, 13),
        byte_at(input, 14),
        byte_at(input, 15),
        byte_at(input, 16),
        byte_at(input, 17),
        byte_at(input, 18),
        byte_at(input, 19),
    ]);
    bytes.extend_from_slice(payload);

    let captured_length = u32::try_from(bytes.len()).ok()?;
    CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: interface,
            },
            captured_length,
        ),
    )
    .ok()
}

fn byte_at(input: &[u8], offset: usize) -> u8 {
    input.get(offset).copied().unwrap_or_default()
}

fn origin_is_bounded(packet: u32, offset: usize, length: usize, frames: &[usize]) -> bool {
    let Some(index) = packet
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(frame_length) = frames.get(index) else {
        return false;
    };
    offset
        .checked_add(length)
        .is_some_and(|end| end <= *frame_length)
}
