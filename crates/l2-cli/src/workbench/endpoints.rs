use super::{capture::HashingReader, input, label, read_bounded};
use l2_capture::CaptureLocator;
use l2_pcap::{CaptureLimits, CaptureSource, CollectionSummary};
use l2_workbench::{
    endpoint::{
        MftReport, TraceCorrelation, TraceIoReport, TraceMatchStatus, correlate_trace_with_capture,
        parse_event_xml, parse_evtx_envelope, parse_strace, parse_usn_device_buffer,
        parse_usn_records,
    },
    evidence::{Case, SourceRange},
    investigation::Record,
    reconstruction::{Limits, ReconstructionReport, Reconstructor},
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

const MAX_NATIVE_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_EVENT_XML_INPUT_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn run(
    file: &Path,
    format: &str,
    capture: Option<&Path>,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    if capture.is_some() && format != "strace" {
        return Err("--capture is supported only with --format strace".into());
    }
    match format {
        "usn" => {
            let report = parse_usn_records(&read_source(file, MAX_NATIVE_INPUT_BYTES)?)?;
            write_json(&report, report.complete, output)
        }
        "usn-device" => {
            let report = parse_usn_device_buffer(&read_source(file, MAX_NATIVE_INPUT_BYTES)?)?;
            write_json(&report, report.complete, output)
        }
        "mft" => write_mft_stream(file, output),
        "evtx" => {
            let report = parse_evtx_envelope(&read_source(file, MAX_NATIVE_INPUT_BYTES)?)?;
            write_json(&report, report.complete, output)
        }
        "event-xml" => {
            let report = parse_event_xml(&read_source(file, MAX_EVENT_XML_INPUT_BYTES)?)?;
            write_json(&report, report.complete, output)
        }
        "strace" => run_strace(file, capture, output),
        _ => Err(format!("unsupported endpoint format: {format}").into()),
    }
}

fn read_source(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    read_bounded(input::regular(path)?, maximum)
}

fn write_json<T: Serialize>(
    value: &T,
    complete: bool,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    Ok(complete)
}

fn write_mft_stream(path: &Path, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut file = input::regular(path)?;
    let report = l2_workbench::endpoint::visit_mft_records(&mut file, |record| {
        serde_json::to_writer(
            &mut *output,
            &MftRecordLine {
                record_type: "record",
                record,
            },
        )
        .map_err(io::Error::other)?;
        writeln!(output)
    })?;
    serde_json::to_writer(
        &mut *output,
        &MftSummaryLine {
            record_type: "summary",
            report: &report,
        },
    )?;
    writeln!(output)?;
    Ok(report.complete)
}

#[derive(Serialize)]
struct MftRecordLine<'a> {
    record_type: &'static str,
    record: &'a l2_workbench::endpoint::MftRecord,
}

#[derive(Serialize)]
struct MftSummaryLine<'a> {
    record_type: &'static str,
    report: &'a MftReport,
}

fn run_strace(
    trace_path: &Path,
    capture_path: Option<&Path>,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let trace = parse_strace(&read_source(trace_path, MAX_NATIVE_INPUT_BYTES)?)?;
    let Some(capture_path) = capture_path else {
        return write_json(&trace, trace.complete, output);
    };
    let (capture, reconstruction, case) = read_trace_capture(capture_path)?;
    let correlations =
        correlate_trace_with_capture(&trace, &reconstruction, &case, Some(&capture.source_sha256));
    let complete = trace.complete
        && capture.complete
        && correlations
            .iter()
            .all(|item| item.status == TraceMatchStatus::ExactUniqueMatch);
    let report = TraceCaptureReport {
        trace,
        capture,
        reconstruction,
        correlations,
    };
    serde_json::to_writer(&mut *output, &report)?;
    writeln!(output)?;
    Ok(complete)
}

#[derive(Serialize)]
struct TraceCaptureReport {
    trace: TraceIoReport,
    capture: TraceCaptureSummary,
    reconstruction: ReconstructionReport,
    correlations: Vec<TraceCorrelation>,
}

#[derive(Serialize)]
struct TraceCaptureSummary {
    source_sha256: String,
    source_length: u64,
    records_seen: u64,
    retained_records: u64,
    truncated_frames: u64,
    #[serde(serialize_with = "l2_workbench::capture_collection::serialize")]
    collection_summary: CollectionSummary,
    complete: bool,
}

fn read_trace_capture(
    path: &Path,
) -> Result<(TraceCaptureSummary, ReconstructionReport, Case), Box<dyn Error>> {
    let limits = Limits::default();
    let mut hash = Sha256::new();
    let mut source_length = 0_u64;
    let hashing = HashingReader {
        inner: input::capture(path)?,
        hash: &mut hash,
        length: &mut source_length,
    };
    let mut capture = CaptureSource::with_limits(hashing, CaptureLimits::STREAMING)?;
    let mut records = Vec::new();
    let mut frames_seen = 0_u64;
    let mut retained_bytes = 0_usize;
    let mut truncated_frames = 0_u64;
    let mut frozen = false;
    while let Some(frame) = capture.next_packet()? {
        frames_seen = frames_seen
            .checked_add(1)
            .ok_or("capture count overflows u64")?;
        truncated_frames = truncated_frames.saturating_add(u64::from(frame.is_truncated()));
        if !frozen
            && frames_seen <= limits.frames
            && frame.bytes().len() <= limits.bytes - retained_bytes
        {
            retained_bytes += frame.bytes().len();
            records.push(Record {
                number: u32::try_from(frames_seen)?,
                frame,
            });
        } else {
            frozen = true;
        }
    }
    let collection_summary = capture.collection_summary();
    let digest = format!("{:x}", hash.finalize());
    let source_sha256 = format!("sha256:{digest}");
    let (case, mut reconstruction) =
        build_trace_case(path, &digest, &source_sha256, source_length, &records)?;
    let retained_records = u64::try_from(records.len())?;
    let input_complete = frames_seen == retained_records
        && truncated_frames == 0
        && !l2_workbench::capture_collection::reports_incomplete_collection(collection_summary)
        && reconstruction.unsupported_frames == 0;
    reconstruction.complete &= input_complete;
    Ok((
        TraceCaptureSummary {
            source_sha256,
            source_length,
            records_seen: frames_seen,
            retained_records,
            truncated_frames,
            collection_summary,
            complete: reconstruction.complete,
        },
        reconstruction,
        case,
    ))
}

fn build_trace_case(
    path: &Path,
    digest: &str,
    source_sha256: &str,
    source_length: u64,
    records: &[Record],
) -> Result<(Case, ReconstructionReport), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_source(
        label(path, "trace-capture"),
        "capture",
        source_length,
        digest,
        None,
    )?;
    let mut reconstructor = Reconstructor::new();
    for record in records {
        if !reconstructor.observe(record.number, &record.frame)? {
            break;
        }
        add_packet_range(&mut case, source_sha256, record)?;
    }
    let report = reconstructor.finish()?;
    Ok((case, report))
}

fn add_packet_range(case: &mut Case, source: &str, record: &Record) -> Result<(), Box<dyn Error>> {
    let captured_length = u64::try_from(record.frame.bytes().len())?;
    let ranges = capture_data_offset(&record.frame)
        .map(|offset| SourceRange {
            source: source.to_owned(),
            packet: Some(u64::from(record.number)),
            offset,
            length: captured_length,
        })
        .into_iter()
        .collect();
    case.add_node(
        "packet",
        None,
        ranges,
        json!({"record":record.number,"captured_length":captured_length}),
    )?;
    Ok(())
}

fn capture_data_offset(frame: &l2_pcap::CapturedFrame) -> Option<u64> {
    match frame.metadata().locator()? {
        CaptureLocator::ClassicPcap { data_offset, .. }
        | CaptureLocator::PcapNg { data_offset, .. } => Some(data_offset),
    }
}
