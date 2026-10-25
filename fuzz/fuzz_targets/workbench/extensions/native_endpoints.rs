use l2_workbench::{endpoint, evidence::SourceRange, sha256};

pub fn exercise(input: &[u8]) {
    let source = format!("sha256:{}", sha256(input));
    // Keep each parser independent so a rejected format cannot skip another format
    exercise_usn(input, &source);
    exercise_mft(input, &source);
    exercise_evtx(input, &source);
    exercise_event_xml(input, &source);
    exercise_strace(input, &source);
}

fn exercise_usn(input: &[u8], source: &str) {
    for report in [
        endpoint::parse_usn_records(input),
        endpoint::parse_usn_device_buffer(input),
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(report.source_sha256, source);
        for record in report.records {
            check_range(&record.source_range, source, input);
        }
        for record in report.unsupported {
            check_range(&record.source_range, source, input);
        }
    }
}

fn exercise_mft(input: &[u8], source: &str) {
    if let Ok(report) = endpoint::parse_mft(input) {
        assert_eq!(report.source_sha256, source);
        for record in report.records {
            check_range(&record.source_range, source, input);
            if let Some(range) = record.standard_information_range {
                check_range(&range, source, input);
            }
            for name in record.file_names {
                check_range(&name.source_range, source, input);
            }
        }
    }
}

fn exercise_evtx(input: &[u8], source: &str) {
    if let Ok(report) = endpoint::parse_evtx_envelope(input) {
        assert_eq!(report.source_sha256, source);
        for record in report.records {
            check_range(&record.source_range, source, input);
            check_range(&record.binxml_range, source, input);
        }
    }
}

fn exercise_event_xml(input: &[u8], source: &str) {
    if let Ok(report) = endpoint::parse_event_xml(input) {
        assert_eq!(report.source_sha256, source);
        for event in report.events {
            check_range(&event.source_range, source, input);
        }
    }
}

fn exercise_strace(input: &[u8], source: &str) {
    if let Ok(report) = endpoint::parse_strace(input) {
        assert_eq!(report.source_sha256, source);
        for event in report.events {
            check_range(&event.source_range, source, input);
            if let Some(range) = &event.data_source_range {
                check_range(range, source, input);
            } else {
                assert!(event.bytes.is_empty());
            }
            if event.bytes_complete {
                assert_eq!(
                    event
                        .return_value
                        // A failed syscall transfers zero bytes even when its input buffer was printed
                        .map(|value| value.max(0))
                        .and_then(|value| usize::try_from(value).ok()),
                    Some(event.bytes.len())
                );
            }
            for frame in event.frames {
                check_range(&frame.source_range, source, input);
            }
        }
    }
}

fn check_range(range: &SourceRange, source: &str, input: &[u8]) {
    assert_eq!(range.source, source);
    assert!(range.packet.is_none());
    assert!(range.offset <= input.len() as u64);
    assert!(range.length <= input.len() as u64 - range.offset);
}
