use l2_workbench::artifact;

pub(super) fn exercise(input: &[u8]) {
    let signatures = artifact::scan_file_signatures(input);
    assert_eq!(signatures.source_sha256, l2_workbench::sha256(input));
    assert_eq!(signatures.source_length, input.len());
    for signature in signatures.matches {
        let Some(end) = signature.range.offset.checked_add(signature.range.length) else {
            panic!("signature range overflowed");
        };
        assert!(end <= input.len());
        assert_eq!(
            signature.observed_hex.split_whitespace().count(),
            signature.range.length
        );
    }

    let Ok(report) = artifact::inspect(input) else {
        return;
    };
    assert_eq!(report.sha256, l2_workbench::sha256(input));
    for mapping in report.mappings {
        assert!(
            mapping
                .file_offset
                .checked_add(mapping.file_size)
                .is_some_and(|end| end <= input.len())
        );
    }
    for reference in report.references {
        for range in [
            Some(reference.record_range),
            reference.name_range,
            reference.library_range,
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                range
                    .offset
                    .checked_add(range.length)
                    .is_some_and(|end| end <= input.len())
            );
        }
    }
    if let Some(entry) = report.entrypoint.and_then(|entry| entry.file_offset) {
        assert!(entry < input.len());
    }
}
