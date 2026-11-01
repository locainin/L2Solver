use std::mem::size_of;

use l2_workbench::{
    artifact::{AnalysisOmission, ArtifactOrigin, EmbeddedFormat, FileRange},
    derivation::{
        AesGcmTagLayout, CounterByteOrder, CounterWidth, OperandRef, Operation, SecretBytes,
        SeedCounterOrder,
    },
    recovery::{proposals::TransformEvidence, regions::RegionCueOrigin},
};

fn transformed(operation: Operation, cue_origins: Vec<RegionCueOrigin>) -> ArtifactOrigin {
    ArtifactOrigin::Transformation {
        parent_index: 0,
        input_range: FileRange {
            offset: 0,
            length: 3,
        },
        operation,
        evidence: TransformEvidence::HexSyntax { digit_count: 2 },
        cue_origins,
    }
}

#[test]
fn inline_origins_and_operations_need_no_clone_heap_bytes() {
    let range = FileRange {
        offset: 1,
        length: 2,
    };
    for origin in [
        ArtifactOrigin::Source,
        ArtifactOrigin::SourceRange {
            range,
            format: EmbeddedFormat::Png,
        },
        ArtifactOrigin::EmbeddedObject {
            parent_index: 0,
            range,
            format: EmbeddedFormat::Zip,
        },
        transformed(Operation::HexDecode {}, Vec::new()),
    ] {
        assert_eq!(origin.owned_heap_bytes(), Some(0));
    }
}

#[test]
fn archive_origin_charges_exact_owned_string_capacity() {
    let origin = ArtifactOrigin::ArchiveMember {
        parent_index: 0,
        archive_range: FileRange {
            offset: 0,
            length: 3,
        },
        entry_index: 0,
        raw_name_sha256: "hash".to_owned(),
        raw_name_hex_preview: "70617468".to_owned(),
        compressed_size: 3,
        expanded_size: 3,
    };
    assert_eq!(origin.owned_heap_bytes(), Some(12));
}

#[test]
fn source_archive_origin_charges_all_owned_string_capacity() {
    let origin = ArtifactOrigin::SourceArchiveMember {
        archive_range: FileRange {
            offset: 0,
            length: 3,
        },
        archive_sha256: "archive".to_owned(),
        entry_index: 0,
        raw_name_sha256: "hash".to_owned(),
        raw_name_hex_preview: "70617468".to_owned(),
        compression_method: 0,
        compressed_size: 3,
        expanded_size: 3,
        crc32: 0,
        local_header_offset: 0,
    };
    assert_eq!(origin.owned_heap_bytes(), Some(19));
}

#[test]
fn transformation_origin_charges_keys_indices_and_cue_capacity() {
    let cues = vec![
        RegionCueOrigin::EncodingRun,
        RegionCueOrigin::RecognizedOffset { signature_index: 1 },
    ];
    let cue_bytes = cues.len() * size_of::<RegionCueOrigin>();
    let xor = transformed(
        Operation::XorRepeat {
            key: vec![1, 2, 3],
            offset: 0,
        },
        cues.clone(),
    );
    assert_eq!(xor.owned_heap_bytes(), Some(cue_bytes + 3));
    let select = transformed(
        Operation::Select {
            indices: vec![0, 1, 2],
        },
        cues.clone(),
    );
    let select_bits = transformed(
        Operation::SelectBits {
            indices: vec![0, 1],
            bits_per_byte: 8,
        },
        cues.clone(),
    );
    let permute = transformed(
        Operation::Permute {
            indices: vec![2, 0, 1],
        },
        cues,
    );
    assert_eq!(
        select.owned_heap_bytes(),
        Some(cue_bytes + 3 * size_of::<usize>())
    );
    assert_eq!(
        select_bits.owned_heap_bytes(),
        Some(cue_bytes + 2 * size_of::<usize>())
    );
    assert_eq!(
        permute.owned_heap_bytes(),
        Some(cue_bytes + 3 * size_of::<usize>())
    );
}

#[test]
fn literal_operand_lengths_are_counted_without_exposing_secret_contents() {
    let literal = |length| OperandRef::literal(SecretBytes::new(vec![7; length]));
    let aes = transformed(
        Operation::AesGcmDecrypt {
            key: literal(32),
            nonce: literal(12),
            associated_data: literal(5),
            tag_layout: AesGcmTagLayout::Appended,
        },
        Vec::new(),
    );
    assert_eq!(aes.owned_heap_bytes(), Some(49));
    let counter = transformed(
        Operation::Sha256CounterXor {
            seed: literal(17),
            initial_counter: 0,
            counter_width: CounterWidth::FourBytes,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        },
        Vec::new(),
    );
    assert_eq!(counter.owned_heap_bytes(), Some(17));
    let scrypt = transformed(
        Operation::ScryptDerive {
            salt: literal(29),
            log_n: 1,
            r: 1,
            p: 1,
            output_length: 16,
        },
        Vec::new(),
    );
    assert_eq!(scrypt.owned_heap_bytes(), Some(29));
}

#[test]
fn omission_payload_counts_owned_capacity_including_operation_buffers() {
    let mut key = Vec::with_capacity(128);
    key.extend([1, 2, 3]);
    let mut message = String::with_capacity(96);
    message.push_str("rejected");
    let expected = key.capacity() + message.capacity();
    let omission = AnalysisOmission::TransformFailed {
        artifact_index: 0,
        operation: Operation::XorRepeat { key, offset: 0 },
        message,
    };
    assert_eq!(omission.owned_heap_bytes(), Some(expected));
}
