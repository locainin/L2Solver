use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_pcap::{CaptureLocator, CaptureSource};
use l2_workbench::endpoint::{
    EvtxBinXmlStatus, IoDirection, MAX_ENDPOINT_RECORDS, MftVisitError, TraceMatchStatus,
    UsnFileReference, correlate_trace_with_capture, parse_event_xml, parse_evtx_envelope,
    parse_mft, parse_mft_reader, parse_strace, parse_usn_device_buffer, parse_usn_records,
    visit_mft_records,
};
use l2_workbench::{
    evidence::{Case, SourceRange},
    reconstruction::{ReconstructionReport, Reconstructor},
    sha256,
};
#[path = "endpoint/event_xml.rs"]
mod event_xml;
#[path = "endpoint/support.rs"]
mod support;

use serde_json::json;
use std::{
    error::Error,
    io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
};
use support::{
    FixtureError, evtx_file, mft_record, put_u16, put_u32, put_u64, strace_sendto_line,
    sysmon_event_xml, usn_v2_record, usn_v3_record,
};

#[test]
fn usn_raw_ranges_nonmonotonic_values() -> Result<(), Box<dyn Error>> {
    let first_record = usn_v2_record(9, "alpha.bin")?;
    let first_record_length = u64::try_from(first_record.len())?;
    let mut bytes = first_record;
    bytes.extend_from_slice(&usn_v2_record(8, "beta.bin")?);

    let report = parse_usn_records(&bytes)?;
    let first = report.records.first().ok_or("first USN record missing")?;
    let second = report.records.get(1).ok_or("second USN record missing")?;

    assert_eq!(report.records.len(), 2);
    assert_eq!(first.file_name, "alpha.bin");
    assert_eq!(first.usn, 9);
    assert_eq!(first.source_range.offset, 0);
    assert_eq!(second.source_range.offset, first_record_length);
    assert_eq!(report.nonmonotonic_usn_records, 1);
    assert_eq!(report.source_length, u64::try_from(bytes.len())?);
    Ok(())
}

#[test]
fn usn_truncation_inconsistent_name_ranges() -> Result<(), Box<dyn Error>> {
    let mut truncated = usn_v2_record(1, "x")?;
    truncated.pop();
    assert!(parse_usn_records(&truncated).is_err());

    let mut invalid_name = usn_v2_record(1, "x")?;
    put_u16(&mut invalid_name, 56, 500)?;
    assert!(parse_usn_records(&invalid_name).is_err());
    Ok(())
}

#[test]
fn usn_v3_reference_width_prefix() -> Result<(), Box<dyn Error>> {
    let mut buffer = 44_u64.to_le_bytes().to_vec();
    let record = usn_v3_record(31, "x")?;
    buffer.extend_from_slice(&record);
    let report = parse_usn_device_buffer(&buffer)?;
    let parsed = report.records.first().ok_or("USN V3 record missing")?;

    assert_eq!(report.next_usn, Some(44));
    assert_eq!(parsed.usn, 31);
    assert_eq!(parsed.file_reference, UsnFileReference::V3(17));
    assert_eq!(parsed.source_range.offset, 8);
    Ok(())
}

#[test]
fn unsupported_usn_without_file_events() -> Result<(), Box<dyn Error>> {
    let mut record = vec![0_u8; 8];
    put_u32(&mut record, 0, 8)?;
    put_u16(&mut record, 4, 4)?;
    let report = parse_usn_records(&record)?;

    assert!(!report.complete);
    assert!(report.records.is_empty());
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(
        report.unsupported.first().map(|item| item.major_version),
        Some(4)
    );
    Ok(())
}

#[test]
fn mft_independent_attributes_raw_provenance() -> Result<(), Box<dyn Error>> {
    let bytes = mft_record(111)?;
    let report = parse_mft(&bytes)?;
    let record = report.records.first().ok_or("MFT record missing")?;
    let name = record.file_names.first().ok_or("MFT name missing")?;

    assert_eq!(record.file_reference, 1_u64 << 48 | 1);
    assert_eq!(name.name, "alpha.bin");
    assert_eq!(record.source_range.offset, 0);
    assert!(record.timestamps_differ_from_file_name);
    assert_eq!(report.timestamp_differences, 1);
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("do not prove"))
    );
    Ok(())
}

#[test]
fn mft_reader_exact_later_ranges() -> Result<(), Box<dyn Error>> {
    let first = mft_record(100)?;
    let mut second = mft_record(101)?;
    put_u32(&mut second, 44, 2)?;
    let mut bytes = first;
    bytes.extend_from_slice(&second);

    let report = parse_mft_reader(Cursor::new(bytes.as_slice()))?;
    let second_record = report.records.get(1).ok_or("second MFT record missing")?;
    assert_eq!(report.source_sha256, format!("sha256:{}", sha256(&bytes)));
    assert_eq!(report.source_length, u64::try_from(bytes.len())?);
    assert_eq!(second_record.source_range.offset, 1024);
    assert_eq!(second_record.source_range.source, report.source_sha256);
    assert!(report.complete);

    let truncated_length = bytes.len().checked_sub(1).ok_or("empty MFT fixture")?;
    assert!(
        parse_mft_reader(Cursor::new(
            bytes.get(..truncated_length).ok_or("range missing")?
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn mft_reader_retained_byte_budget() -> Result<(), Box<dyn Error>> {
    let source_records = 16 * 1024 + 1;
    let source = many_mft_records(source_records)?;
    let report = parse_mft_reader(Cursor::new(source.as_slice()))?;

    assert_eq!(report.records_seen, u64::try_from(source_records)?);
    assert_eq!(report.records.len(), source_records - 1);
    assert_eq!(report.omitted_records, 1);
    assert_eq!(report.source_length, u64::try_from(source.len())?);
    assert!(!report.complete);
    Ok(())
}

#[test]
fn mft_visitor_ranges_summary_counts() -> Result<(), Box<dyn Error>> {
    let first = mft_record(100)?;
    let mut second = mft_record(101)?;
    put_u32(&mut second, 44, 2)?;
    let mut bytes = first;
    bytes.extend_from_slice(&second);
    let mut reader = Cursor::new(bytes.as_slice());
    let mut streamed = Vec::new();

    let report = visit_mft_records(&mut reader, |record| {
        streamed.push(record.clone());
        Ok(())
    })?;
    assert_eq!(report.source_sha256, format!("sha256:{}", sha256(&bytes)));
    assert_eq!(report.records_seen, 2);
    assert_eq!(report.streamed_records, 2);
    assert!(report.records.is_empty());
    assert_eq!(streamed.len(), 2);
    assert_eq!(
        streamed.get(1).map(|record| record.source_range.offset),
        Some(1024)
    );
    assert_eq!(
        streamed
            .get(1)
            .map(|record| record.source_range.source.as_str()),
        Some(report.source_sha256.as_str())
    );
    assert!(report.complete);
    Ok(())
}

#[test]
fn mft_visitor_bounded_detail_limit() -> Result<(), Box<dyn Error>> {
    let record_count = MAX_ENDPOINT_RECORDS
        .checked_add(1)
        .ok_or("MFT record count overflow")?;
    let source = many_mft_records(record_count)?;
    let expected_last = u32::try_from(record_count)?;
    let mut last_offset = None;
    let mut last_reference = None;
    let mut reader = Cursor::new(source.as_slice());
    let report = visit_mft_records(&mut reader, |record| {
        if record.record_number == expected_last {
            last_offset = Some(record.source_range.offset);
            last_reference = Some(record.source_range.source.clone());
        }
        Ok(())
    })?;
    let expected_offset = MAX_ENDPOINT_RECORDS
        .checked_mul(1024)
        .ok_or("MFT source offset overflow")?;

    assert_eq!(report.records_seen, u64::try_from(record_count)?);
    assert_eq!(report.streamed_records, u64::try_from(record_count)?);
    assert_eq!(report.omitted_records, 0);
    assert_eq!(report.reference_checks_omitted, 1);
    assert_eq!(last_offset, Some(u64::try_from(expected_offset)?));
    assert_eq!(
        last_reference.as_deref(),
        Some(report.source_sha256.as_str())
    );
    assert!(!report.complete);
    Ok(())
}

#[test]
fn mft_visitor_references_source_changes() -> Result<(), Box<dyn Error>> {
    let valid = mft_record(100)?;
    assert!(visit_truncated_mft(&valid).is_err());
    assert!(visit_duplicate_mft(&valid).is_err());
    assert!(visit_changed_mft(valid).is_err());
    Ok(())
}

#[test]
fn mft_bad_fixups_truncated_slots() -> Result<(), Box<dyn Error>> {
    let mut invalid_fixup = mft_record(100)?;
    put_u16(&mut invalid_fixup, 510, 0x9999)?;
    assert!(parse_mft(&invalid_fixup).is_err());

    let mut truncated = mft_record(100)?;
    truncated.pop();
    assert!(parse_mft(&truncated).is_err());

    let mut overlap = mft_record(100)?;
    put_u16(&mut overlap, 20, 52)?;
    assert!(parse_mft(&overlap).is_err());
    Ok(())
}

#[test]
fn mft_noncreation_timestamp_disagreements() -> Result<(), Box<dyn Error>> {
    let mut bytes = mft_record(100)?;
    put_u64(&mut bytes, 88, 201)?;
    let report = parse_mft(&bytes)?;
    let record = report.records.first().ok_or("MFT record missing")?;

    assert!(record.timestamps_differ_from_file_name);
    assert_eq!(report.timestamp_differences, 1);
    Ok(())
}

#[test]
fn exported_event_change_exact_range() -> Result<(), Box<dyn Error>> {
    let xml = sysmon_event_xml();
    let report = parse_event_xml(xml.as_bytes())?;
    let event = report.events.first().ok_or("event missing")?;
    let change = event
        .sysmon_time_change
        .as_ref()
        .ok_or("Sysmon Event 2 fields missing")?;
    let offset = usize::try_from(event.source_range.offset)?;
    let length = usize::try_from(event.source_range.length)?;

    assert_eq!(event.provider.as_deref(), Some("Microsoft-Windows-Sysmon"));
    assert_eq!(event.event_id.as_deref(), Some("2"));
    assert_eq!(change.target_filename, "C:\\Temp\\alpha.bin");
    assert_eq!(
        change.previous_creation_time,
        "2025-01-01T00:00:00.0000000Z"
    );
    assert_eq!(change.creation_time, "2025-01-02T00:00:00.0000000Z");
    let exact_event = xml
        .as_bytes()
        .get(offset..offset + length)
        .ok_or("event XML range is invalid")?;
    assert!(exact_event.starts_with(b"<Event "));
    assert!(exact_event.ends_with(b"</Event>"));
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("authenticity"))
    );
    Ok(())
}

#[test]
fn exported_event_duplicate_named_data() {
    let truncated = "<Events><Event><System><EventID>2</EventID></System>";
    assert!(parse_event_xml(truncated.as_bytes()).is_err());

    let duplicate = sysmon_event_xml().replace(
        "</EventData>",
        "<Data Name=\"Image\">second.exe</Data></EventData>",
    );
    assert!(parse_event_xml(duplicate.as_bytes()).is_err());
}

#[test]
fn evtx_envelope_crc_binxml_unparsed() -> Result<(), Box<dyn Error>> {
    let bytes = evtx_file()?;
    let report = parse_evtx_envelope(&bytes)?;
    let record = report.records.first().ok_or("record envelope missing")?;

    assert_eq!(report.chunks.len(), 1);
    assert_eq!(record.record_id, 7);
    assert_eq!(record.filetime_ticks, 13);
    assert_eq!(record.source_range.offset, 4096 + 512);
    assert_eq!(report.binxml_status, EvtxBinXmlStatus::NotParsed);
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("BinXML"))
    );

    let mut corrupt = bytes;
    let byte = corrupt
        .get_mut(4096 + 512 + 24)
        .ok_or("record byte missing")?;
    *byte ^= 1;
    assert!(parse_evtx_envelope(&corrupt).is_err());
    Ok(())
}

#[test]
fn evtx_envelope_file_header_crc() -> Result<(), Box<dyn Error>> {
    let mut truncated = evtx_file()?;
    truncated.pop();
    assert!(parse_evtx_envelope(&truncated).is_err());

    let mut corrupt_header = evtx_file()?;
    let byte = corrupt_header.get_mut(16).ok_or("header byte missing")?;
    *byte ^= 1;
    assert!(parse_evtx_envelope(&corrupt_header).is_err());
    Ok(())
}

#[test]
fn strace_import_code_identity_unclaimed() -> Result<(), Box<dyn Error>> {
    let line = b"412 write(4<TCP:[192.0.2.10:40000->198.51.100.20:443]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5) = 5\n > /usr/lib/libc.so.6(send+0xa5) [0x12345]\n > /opt/app(+0x0) [0x45678]\n";
    let report = parse_strace(line)?;
    let event = report.events.first().ok_or("I/O observation missing")?;
    let socket = event.socket.as_ref().ok_or("socket tuple missing")?;

    assert_eq!(event.pid, Some(412));
    assert_eq!(event.direction, IoDirection::OutOfProcess);
    assert_eq!(event.bytes, b"HELLO");
    assert_eq!(
        socket.peer.address,
        "198.51.100.20".parse::<std::net::IpAddr>()?
    );
    assert_eq!(socket.peer.port, 443);
    assert!(
        event
            .source_range
            .length
            .checked_add(event.source_range.offset)
            .is_some()
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("function identity"))
    );
    let frame = event.frames.first().ok_or("observed stack frame missing")?;
    assert_eq!(frame.module.as_deref(), Some("/usr/lib/libc.so.6"));
    assert_eq!(frame.symbol.as_deref(), Some("send"));
    assert_eq!(frame.symbol_offset, Some(0xa5));
    assert_eq!(frame.instruction_pointer, Some(0x12345));
    assert_eq!(frame.source_range.source, report.source_sha256);
    Ok(())
}

#[test]
fn strace_import_unusable_exact_correlation() -> Result<(), Box<dyn Error>> {
    let line = b"412 write(4, \"\\x41\\x42\"..., 8) = 8\n";
    let report = parse_strace(line)?;
    let event = report.events.first().ok_or("I/O observation missing")?;

    assert!(!event.bytes_complete);
    assert_eq!(event.bytes, b"AB");
    assert_eq!(event.direction, IoDirection::OutOfProcess);
    Ok(())
}

#[test]
fn strace_correlate_io_captured_packets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let pcap_path = directory.path().join("owned-loopback.pcap");
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let mut capture = start_loopback_capture(&pcap_path, port)?;
    let output = Command::new("strace")
        .args([
            "-f",
            "-qq",
            "-k",
            "-xx",
            "-s",
            "65535",
            "-yy",
            "-e",
            "trace=network",
            "--",
            "/usr/bin/python3",
            "-c",
            LOOPBACK_SCRIPT,
        ])
        .arg(port.to_string())
        .output()?;
    assert!(output.status.success());
    let (mut connection, _) = listener.accept()?;
    let mut received = Vec::new();
    connection.read_to_end(&mut received)?;
    assert_eq!(received, LOOPBACK_BYTES);
    let report = parse_strace(&output.stderr)?;
    let event = report
        .events
        .iter()
        .find(|item| item.bytes == LOOPBACK_BYTES)
        .ok_or("controlled write event missing")?;
    assert!(event.bytes_complete);
    assert_eq!(event.direction, IoDirection::OutOfProcess);
    assert!(!event.frames.is_empty());

    let capture_status = capture.0.wait()?;
    assert!(capture_status.success());
    let pcap = std::fs::read(pcap_path)?;
    let (case, reconstruction) = index_captured_pcap(&pcap)?;
    let scope = capture_source_id(&case)?;
    let correlation = correlate_trace_with_capture(&report, &reconstruction, &case, Some(scope))
        .into_iter()
        .find(|item| item.trace_source_range == event.source_range)
        .ok_or("trace correlation missing")?;
    assert_eq!(correlation.status, TraceMatchStatus::ExactUniqueMatch);
    assert_eq!(correlation.candidate_count, 1);
    assert!(!correlation.captured_ranges.is_empty());
    Ok(())
}

const LOOPBACK_BYTES: &[u8] = b"owned-loopback-fixture";
const LOOPBACK_SCRIPT: &str = "import socket,sys; client=socket.create_connection(('127.0.0.1', int(sys.argv[1]))); client.sendall(b'owned-loopback-fixture'); client.close()";

struct CaptureProcess(Child);

impl Drop for CaptureProcess {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn start_loopback_capture(path: &Path, port: u16) -> Result<CaptureProcess, Box<dyn Error>> {
    let filter = format!("tcp and host 127.0.0.1 and port {port}");
    let mut capture = CaptureProcess(
        Command::new("dumpcap")
            .args([
                "-i", "lo", "-p", "-f", &filter, "-c", "5", "-F", "pcap", "-w",
            ])
            .arg(path)
            .arg("tcp")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let stderr = capture.0.stderr.as_mut().ok_or("tcpdump stderr missing")?;
    let mut reader = BufReader::new(stderr);
    let mut ready = String::new();
    reader.read_line(&mut ready)?;
    drop(reader);
    if !ready.contains("Capturing on") || !ready.contains("lo") {
        return Err(format!("dumpcap did not start capture: {ready}").into());
    }
    Ok(capture)
}

fn index_captured_pcap(bytes: &[u8]) -> Result<(Case, ReconstructionReport), Box<dyn Error>> {
    let mut reader = CaptureSource::new(Cursor::new(bytes))?;
    let mut case = Case::new();
    let source = case.add_source(
        "owned-loopback.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &sha256(bytes),
        None,
    )?;
    let mut reconstructor = Reconstructor::new();
    let mut packet = 0_u32;
    while let Some(frame) = reader.next_packet()? {
        packet = packet.checked_add(1).ok_or("packet number overflow")?;
        reconstructor.observe(packet, &frame)?;
        let Some(CaptureLocator::ClassicPcap { data_offset, .. }) = frame.metadata().locator()
        else {
            return Err("classic PCAP source range missing".into());
        };
        case.add_bytes_node(
            "packet",
            frame.bytes(),
            vec![SourceRange {
                source: source.clone(),
                packet: Some(u64::from(packet)),
                offset: data_offset,
                length: u64::try_from(frame.bytes().len())?,
            }],
            json!({"record": packet, "captured_length": frame.bytes().len()}),
        )?;
    }
    if packet == 0 {
        return Err("loopback PCAP contains no packet records".into());
    }
    Ok((case, reconstructor.finish()?))
}

#[test]
fn trace_packet_exact_directional_bytes() -> Result<(), Box<dyn Error>> {
    let (case, reconstruction) = synthetic_capture(false)?;
    let trace = parse_strace(
        b"412 write(4<TCP:[192.0.2.10:40000->198.51.100.20:443]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5) = 5\n",
    )?;
    let correlations = correlate_trace_with_capture(
        &trace,
        &reconstruction,
        &case,
        Some(capture_source_id(&case)?),
    );
    let exact = correlations.first().ok_or("correlation missing")?;

    assert_eq!(exact.status, TraceMatchStatus::ExactUniqueMatch);
    assert_eq!(exact.candidate_count, 1);
    assert_eq!(
        exact.captured_ranges.first().map(|range| range.packet),
        Some(4)
    );

    let wrong_bytes = parse_strace(
        b"412 write(4<TCP:[192.0.2.10:40000->198.51.100.20:443]>, \"\\x4e\\x4f\", 2) = 2\n",
    )?;
    let missing = correlate_trace_with_capture(
        &wrong_bytes,
        &reconstruction,
        &case,
        Some(capture_source_id(&case)?),
    );
    assert_eq!(
        missing.first().map(|result| result.status),
        Some(TraceMatchStatus::BytesNotObserved)
    );
    Ok(())
}

#[test]
fn trace_packet_repeated_bytes_ambiguous() -> Result<(), Box<dyn Error>> {
    let (case, reconstruction) = synthetic_capture(true)?;
    let trace = parse_strace(
        b"412 write(4<TCP:[192.0.2.10:40000->198.51.100.20:443]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5) = 5\n",
    )?;
    let correlations = correlate_trace_with_capture(
        &trace,
        &reconstruction,
        &case,
        Some(capture_source_id(&case)?),
    );
    let result = correlations.first().ok_or("correlation missing")?;

    assert_eq!(result.status, TraceMatchStatus::Ambiguous);
    assert_eq!(result.candidate_count, 2);
    assert!(result.captured_ranges.is_empty());
    Ok(())
}

#[test]
fn trace_packet_not_unique_incomplete() -> Result<(), Box<dyn Error>> {
    let (case, mut reconstruction) = synthetic_capture(false)?;
    reconstruction.complete = false;
    let trace = parse_strace(
        b"412 write(4<TCP:[192.0.2.10:40000->198.51.100.20:443]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5) = 5\n",
    )?;
    let correlations = correlate_trace_with_capture(
        &trace,
        &reconstruction,
        &case,
        Some(capture_source_id(&case)?),
    );
    let result = correlations.first().ok_or("correlation missing")?;

    assert_eq!(result.status, TraceMatchStatus::CaptureIncomplete);
    assert_eq!(
        result.captured_ranges.first().map(|range| range.packet),
        Some(4)
    );
    Ok(())
}

#[test]
fn trace_correlation_unresolved_without_scope() -> Result<(), Box<dyn Error>> {
    let (case, reconstruction, _, _) = two_source_udp_case()?;
    let trace = trace_sendto("192.0.2.10:40000->198.51.100.20:53", b"HELLO")?;
    let unresolved = correlate_trace_with_capture(&trace, &reconstruction, &case, None);
    assert_eq!(
        unresolved.first().map(|result| result.status),
        Some(TraceMatchStatus::CaptureProvenanceUnavailable)
    );
    Ok(())
}

#[test]
fn trace_correlation_local_packet_numbers() -> Result<(), Box<dyn Error>> {
    let (case, reconstruction, first_source_scope, other_source_scope) = two_source_udp_case()?;
    let trace_a = trace_sendto("192.0.2.10:40000->198.51.100.20:53", b"HELLO")?;
    let scoped =
        correlate_trace_with_capture(&trace_a, &reconstruction, &case, Some(&first_source_scope));
    let exact = scoped.first().ok_or("source-scoped correlation missing")?;
    assert_eq!(exact.status, TraceMatchStatus::ExactUniqueMatch);
    assert_eq!(exact.candidate_count, 1);
    assert_eq!(
        exact
            .captured_ranges
            .first()
            .map(|range| range.source.as_str()),
        Some(first_source_scope.as_str())
    );
    assert_eq!(
        exact.captured_ranges.first().map(|range| range.offset),
        Some(42)
    );

    let trace_b = trace_sendto("203.0.113.10:41000->203.0.113.20:53", b"WORLD")?;
    let other_flow =
        correlate_trace_with_capture(&trace_b, &reconstruction, &case, Some(&other_source_scope));
    assert_eq!(
        other_flow.first().map(|result| result.status),
        Some(TraceMatchStatus::NoMatchingFlow)
    );
    Ok(())
}

fn two_source_udp_case() -> Result<(Case, ReconstructionReport, String, String), Box<dyn Error>> {
    let mut case = Case::new();
    let frame_a = udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 40000, 53, b"HELLO")?;
    let frame_b = udp_frame([203, 0, 113, 10], [203, 0, 113, 20], 41000, 53, b"WORLD")?;
    let source_a = add_packet_source(&mut case, "source-a.pcap", 1, &frame_a)?;
    let source_b = add_packet_source(&mut case, "source-b.pcap", 1, &frame_b)?;
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe(1, &frame_a)?;
    Ok((case, reconstructor.finish()?, source_a, source_b))
}

fn trace_sendto(
    endpoints: &str,
    payload: &[u8],
) -> Result<l2_workbench::endpoint::TraceIoReport, Box<dyn Error>> {
    let line = strace_sendto_line(endpoints, payload);
    Ok(parse_strace(&line)?)
}

fn capture_source_id(case: &Case) -> Result<&str, Box<dyn Error>> {
    case.sources()
        .first()
        .map(|source| source.id.as_str())
        .ok_or_else(|| "capture source missing".into())
}

fn synthetic_capture(
    duplicate_application_bytes: bool,
) -> Result<(Case, ReconstructionReport), Box<dyn Error>> {
    let frames = synthetic_tcp_frames(duplicate_application_bytes)?;
    let source_bytes = frames
        .iter()
        .flat_map(|frame| frame.bytes().iter().copied())
        .collect::<Vec<_>>();
    let mut case = Case::new();
    let source = case.add_source(
        "controlled.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &sha256(&source_bytes),
        None,
    )?;
    let mut reconstruction = Reconstructor::new();
    let mut source_offset = 0_u64;
    for (index, frame) in frames.iter().enumerate() {
        add_capture_packet(
            &mut case,
            &mut reconstruction,
            &source,
            &mut source_offset,
            index,
            frame,
        )?;
    }
    Ok((case, reconstruction.finish()?))
}

fn synthetic_tcp_frames(
    duplicate_application_bytes: bool,
) -> Result<Vec<CapturedFrame>, Box<dyn Error>> {
    let mut frames = vec![
        tcp_frame([192, 0, 2, 10], [198, 51, 100, 20], 40000, 443, 100, 2, b"")?,
        tcp_frame(
            [198, 51, 100, 20],
            [192, 0, 2, 10],
            443,
            40000,
            500,
            0x12,
            b"",
        )?,
        tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40000,
            443,
            101,
            0x10,
            b"",
        )?,
        tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40000,
            443,
            101,
            0x18,
            b"HELLO",
        )?,
    ];
    if duplicate_application_bytes {
        frames.push(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40000,
            443,
            106,
            0x18,
            b"HELLO",
        )?);
    }
    Ok(frames)
}

fn add_capture_packet(
    case: &mut Case,
    reconstruction: &mut Reconstructor,
    source: &str,
    source_offset: &mut u64,
    index: usize,
    frame: &CapturedFrame,
) -> Result<(), Box<dyn Error>> {
    let packet = u32::try_from(index)
        .ok()
        .and_then(|number| number.checked_add(1))
        .ok_or("packet number overflow")?;
    reconstruction.observe(packet, frame)?;
    let frame_length = u64::try_from(frame.bytes().len())?;
    case.add_bytes_node(
        "packet",
        frame.bytes(),
        vec![SourceRange {
            source: source.to_owned(),
            packet: Some(u64::from(packet)),
            offset: *source_offset,
            length: frame_length,
        }],
        json!({"record": packet, "captured_length": frame.bytes().len()}),
    )?;
    *source_offset = source_offset
        .checked_add(frame_length)
        .ok_or("capture source offset overflow")?;
    Ok(())
}

fn tcp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Result<CapturedFrame, Box<dyn Error>> {
    let ip_length = u16::try_from(40 + payload.len())?;
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    bytes.extend_from_slice(&[0x45, 0]);
    bytes.extend_from_slice(&ip_length.to_be_bytes());
    bytes.extend_from_slice(&42_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&[64, 6, 0, 0]);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&[0x50, flags, 0x20, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    let original_length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original_length,
        ),
    )?)
}

fn udp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<CapturedFrame, Box<dyn Error>> {
    let udp_length = u16::try_from(8 + payload.len())?;
    let ip_length = u16::try_from(20 + usize::from(udp_length))?;
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    bytes.extend_from_slice(&[0x45, 0]);
    bytes.extend_from_slice(&ip_length.to_be_bytes());
    bytes.extend_from_slice(&42_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&[64, 17, 0, 0]);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&udp_length.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    let original_length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original_length,
        ),
    )?)
}

fn add_packet_source(
    case: &mut Case,
    label: &str,
    packet: u32,
    frame: &CapturedFrame,
) -> Result<String, Box<dyn Error>> {
    let frame_length = u64::try_from(frame.bytes().len())?;
    let source = case.add_source(label, "capture", frame_length, &sha256(frame.bytes()), None)?;
    case.add_bytes_node(
        "packet",
        frame.bytes(),
        vec![SourceRange {
            source: source.clone(),
            packet: Some(u64::from(packet)),
            offset: 0,
            length: frame_length,
        }],
        json!({"record": packet, "captured_length": frame.bytes().len()}),
    )?;
    Ok(source)
}

fn visit_truncated_mft(source: &[u8]) -> Result<(), MftVisitError> {
    let mut truncated = source.to_vec();
    let length = truncated.len().saturating_sub(1);
    truncated.truncate(length);
    let mut reader = Cursor::new(truncated);
    visit_mft_records(&mut reader, |_| Ok(()))?;
    Ok(())
}

fn visit_duplicate_mft(record: &[u8]) -> Result<(), MftVisitError> {
    let mut duplicate = record.to_vec();
    duplicate.extend_from_slice(record);
    let mut reader = Cursor::new(duplicate);
    visit_mft_records(&mut reader, |_| Ok(()))?;
    Ok(())
}

fn visit_changed_mft(source: Vec<u8>) -> Result<(), MftVisitError> {
    let mut reader = RewritingReader {
        cursor: Cursor::new(source),
        rewinds: 0,
    };
    visit_mft_records(&mut reader, |_| Ok(()))?;
    Ok(())
}

struct RewritingReader {
    cursor: Cursor<Vec<u8>>,
    rewinds: u8,
}

impl Read for RewritingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buffer)
    }
}

impl Seek for RewritingReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        if position == SeekFrom::Start(0) {
            self.rewinds = self.rewinds.saturating_add(1);
            if self.rewinds == 2
                && let Some(record_number) = self.cursor.get_mut().get_mut(44..48)
            {
                record_number.copy_from_slice(&2_u32.to_le_bytes());
            }
        }
        self.cursor.seek(position)
    }
}

fn many_mft_records(count: usize) -> Result<Vec<u8>, FixtureError> {
    let capacity = count
        .checked_mul(1024)
        .ok_or(FixtureError("MFT source size overflow"))?;
    let mut source = Vec::with_capacity(capacity);
    for number in 1..=count {
        let mut record = mft_record(u64::try_from(number)?)?;
        put_u32(&mut record, 44, u32::try_from(number)?)?;
        source.extend_from_slice(&record);
    }
    Ok(source)
}
#[path = "endpoint/strace.rs"]
mod strace;
