use super::{BehaviorFinding, BehaviorKind, visitor::FindingVisitor};
use crate::evidence::{Case, EvidenceStatus, Node, SourceRange};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error};

const SMB2_HEADER_BYTES: usize = 64;
const SET_INFO_BODY_BYTES: usize = 32;
const FILE_BASIC_INFO_BYTES: usize = 40;
const MAX_MAPPED_RANGES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingWire {
    offset: usize,
    range: SourceRange,
}

#[derive(Clone)]
struct Mapping {
    offset: usize,
    range: SourceRange,
}

struct Candidate {
    stream_offset: usize,
    buffer_offset: usize,
    file_id: Vec<u8>,
    timestamps: [u64; 4],
    file_id_ranges: Vec<SourceRange>,
    timestamp_ranges: [Vec<SourceRange>; 4],
    file_id_mapping_complete: bool,
    timestamp_mapping_complete: [bool; 4],
}

struct UnparsedInput {
    offset: usize,
    length: usize,
    reason: &'static str,
}

struct RunOutput {
    candidates: Vec<Candidate>,
    unparsed: Vec<UnparsedInput>,
}

pub(super) fn analyze(case: &Case, report: &mut FindingVisitor<'_>) -> Result<(), Box<dyn Error>> {
    let blobs: HashMap<_, _> = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect();
    let nodes: HashMap<_, _> = case.nodes().iter().map(|node| (node.id, node)).collect();
    let receipts = mapping_receipts(case)?;
    for node in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "tcp_byte_run")
    {
        if !run_is_eligible(node) {
            continue;
        }
        let Some(bytes) = node_blob(&blobs, node) else {
            continue;
        };
        let mappings = run_mappings(node, bytes, &receipts, &nodes, &blobs)?;
        let parsed = parse_run(bytes, &mappings)?;
        for candidate in parsed.candidates {
            let finding = candidate_finding(node, &candidate);
            if finding.details.get("source_mapping_complete") == Some(&Value::Bool(false)) {
                report.add_limitation(
                    "Some SMB2 request fields have incomplete byte-to-source mapping receipts",
                );
            }
            report.push(finding)?;
        }
        for input in parsed.unparsed {
            let finding = unparsed_finding(node, &input, &mappings)?;
            if finding.details.get("source_mapping_complete") == Some(&Value::Bool(false)) {
                report.add_limitation(
                    "Some unparsed SMB2 ranges have incomplete byte-to-source mapping receipts",
                );
            }
            report.push(finding)?;
        }
    }
    Ok(())
}

fn run_is_eligible(node: &Node) -> bool {
    node.details.get("start_known").and_then(Value::as_bool) == Some(true)
        && node
            .details
            .get("generation_ambiguous")
            .and_then(Value::as_bool)
            != Some(true)
}

fn mapping_receipts(case: &Case) -> Result<HashMap<u64, Vec<u64>>, Box<dyn Error>> {
    let mut receipts = HashMap::new();
    for edge in case
        .edges()
        .iter()
        .filter(|edge| edge.relation == "mapped_by")
    {
        receipts
            .entry(edge.from)
            .or_insert_with(Vec::new)
            .push(edge.to);
    }
    if receipts.values().any(|ids: &Vec<u64>| ids.len() > 1) {
        return Err("TCP run has more than one mapping receipt".into());
    }
    Ok(receipts)
}

fn node_blob<'a>(blobs: &HashMap<&str, &'a [u8]>, node: &Node) -> Option<&'a [u8]> {
    blobs.get(node.blob.as_deref()?).copied()
}

fn run_mappings(
    node: &Node,
    bytes: &[u8],
    receipts: &HashMap<u64, Vec<u64>>,
    nodes: &HashMap<u64, &Node>,
    blobs: &HashMap<&str, &[u8]>,
) -> Result<Vec<Mapping>, Box<dyn Error>> {
    if let Some(receipt_id) = receipts.get(&node.id).and_then(|ids| ids.first()).copied() {
        let receipt = nodes
            .get(&receipt_id)
            .ok_or("mapping receipt node is missing")?;
        let receipt_bytes = node_blob(blobs, receipt).ok_or("mapping receipt bytes are missing")?;
        if receipt_bytes.len() > crate::evidence::MAX_NODE_DETAILS_BYTES * MAX_MAPPED_RANGES {
            return Err("mapping receipt exceeds the supported decode bound".into());
        }
        let decoded: Vec<MappingWire> = serde_json::from_slice(receipt_bytes)?;
        if decoded.len() > MAX_MAPPED_RANGES {
            return Err("mapping receipt contains too many ranges".into());
        }
        let mappings = decoded
            .into_iter()
            .map(|entry| Mapping {
                offset: entry.offset,
                range: entry.range,
            })
            .collect::<Vec<_>>();
        validate_mappings(bytes.len(), &mappings)?;
        return Ok(mappings);
    }
    if let [range] = node.ranges.as_slice()
        && usize::try_from(range.length).ok() == Some(bytes.len())
    {
        return Ok(vec![Mapping {
            offset: 0,
            range: range.clone(),
        }]);
    }
    Ok(Vec::new())
}

fn validate_mappings(output_length: usize, mappings: &[Mapping]) -> Result<(), Box<dyn Error>> {
    for mapping in mappings {
        let range_length = usize::try_from(mapping.range.length)?;
        if mapping.offset > output_length || range_length > output_length - mapping.offset {
            return Err("mapping receipt exceeds the TCP run byte range".into());
        }
    }
    Ok(())
}

fn parse_run(bytes: &[u8], mappings: &[Mapping]) -> Result<RunOutput, Box<dyn Error>> {
    let mut candidates = Vec::new();
    let mut unparsed = Vec::new();
    let mut offset = 0_usize;
    let mut framed_prefix = false;
    while offset < bytes.len() {
        let Some((message_start, message_end)) = netbios_message(bytes, offset) else {
            if framed_prefix || (offset == 0 && bytes.first() == Some(&0)) {
                unparsed.push(UnparsedInput {
                    offset,
                    length: bytes.len() - offset,
                    reason: "incomplete_or_inconsistent_netbios_frame",
                });
            }
            break;
        };
        framed_prefix = true;
        if bytes.get(offset) == Some(&0) {
            if let Some(candidate) =
                parse_set_info(bytes, offset, message_start, message_end, mappings)?
            {
                candidates.push(candidate);
            } else if maybe_file_basic_set_info(bytes, message_start, message_end) {
                unparsed.push(UnparsedInput {
                    offset,
                    length: message_end - offset,
                    reason: "unsupported_or_malformed_file_basic_set_info_request",
                });
            }
        }
        offset = message_end;
    }
    Ok(RunOutput {
        candidates,
        unparsed,
    })
}

fn maybe_file_basic_set_info(bytes: &[u8], start: usize, end: usize) -> bool {
    let Some(message) = bytes.get(start..end) else {
        return false;
    };
    if message.get(..4) != Some(b"\xfeSMB")
        || read_u16(message, 4) != Some(64)
        || read_u16(message, 12) != Some(0x0011)
    {
        return false;
    }
    if read_u32(message, 16).is_some_and(|flags| flags & 1 != 0) {
        return false;
    }
    let body = SMB2_HEADER_BYTES;
    if read_u16(message, body).is_none_or(|size| size != 33) {
        return true;
    }
    match (message.get(body + 2), message.get(body + 3)) {
        (Some(1), Some(4)) => true,
        (Some(_), Some(_)) => false,
        _ => true,
    }
}

fn unparsed_finding(
    node: &Node,
    input: &UnparsedInput,
    mappings: &[Mapping],
) -> Result<BehaviorFinding, Box<dyn Error>> {
    let source_ranges = map_range(mappings, input.offset, input.length)?;
    let source_mapping_complete = mappings_cover(mappings, input.offset, input.length)?;
    let mut packet_numbers = source_ranges
        .iter()
        .filter_map(|range| range.packet)
        .collect::<Vec<_>>();
    packet_numbers.sort_unstable();
    packet_numbers.dedup();
    Ok(BehaviorFinding {
        kind: BehaviorKind::Smb2UnparsedRange,
        status: EvidenceStatus::Unresolved,
        node_ids: vec![node.id],
        packet_numbers,
        source_ranges,
        details: json!({
            "parser":"netbios_framed_smb2",
            "reason":input.reason,
            "stream_range":{"offset":input.offset,"length":input.length},
            "source_mapping_complete":source_mapping_complete,
        }),
    })
}

fn netbios_message(bytes: &[u8], offset: usize) -> Option<(usize, usize)> {
    let header = bytes.get(offset..offset.checked_add(4)?)?;
    let length = (usize::from(*header.get(1)?) << 16)
        | (usize::from(*header.get(2)?) << 8)
        | usize::from(*header.get(3)?);
    let start = offset.checked_add(4)?;
    let end = start.checked_add(length)?;
    (end <= bytes.len()).then_some((start, end))
}

fn parse_set_info(
    bytes: &[u8],
    frame_offset: usize,
    message_start: usize,
    message_end: usize,
    mappings: &[Mapping],
) -> Result<Option<Candidate>, Box<dyn Error>> {
    let Some(message) = bytes.get(message_start..message_end) else {
        return Ok(None);
    };
    if message.get(..4) != Some(b"\xfeSMB")
        || read_u16(message, 4) != Some(64)
        || read_u16(message, 12) != Some(0x0011)
        || read_u32(message, 16).is_none_or(|flags| flags & 1 != 0)
        || read_u32(message, 20).is_none_or(|next| next != 0)
    {
        return Ok(None);
    }
    if read_u16(message, SMB2_HEADER_BYTES) != Some(33)
        || message.get(SMB2_HEADER_BYTES + 2) != Some(&1)
        || message.get(SMB2_HEADER_BYTES + 3) != Some(&4)
    {
        return Ok(None);
    }
    let Some(buffer_length) =
        read_u32(message, SMB2_HEADER_BYTES + 4).and_then(|value| usize::try_from(value).ok())
    else {
        return Ok(None);
    };
    let Some(buffer_offset) = read_u16(message, SMB2_HEADER_BYTES + 8).map(usize::from) else {
        return Ok(None);
    };
    let Some(file_id) = message.get(SMB2_HEADER_BYTES + 16..SMB2_HEADER_BYTES + 32) else {
        return Ok(None);
    };
    let buffer_start = buffer_offset;
    let Some(buffer_end) = buffer_start.checked_add(buffer_length) else {
        return Ok(None);
    };
    if buffer_start < SMB2_HEADER_BYTES + SET_INFO_BODY_BYTES
        || buffer_length < FILE_BASIC_INFO_BYTES
        || buffer_end > message.len()
    {
        return Ok(None);
    }
    let mut timestamps = [0_u64; 4];
    let mut timestamp_ranges: [Vec<SourceRange>; 4] = std::array::from_fn(|_| Vec::new());
    let mut timestamp_mapping_complete = [false; 4];
    for (index, (timestamp, (ranges, complete))) in timestamps
        .iter_mut()
        .zip(
            timestamp_ranges
                .iter_mut()
                .zip(timestamp_mapping_complete.iter_mut()),
        )
        .enumerate()
    {
        let start = buffer_start + index * 8;
        let Some(raw) = read_u64(message, start) else {
            return Ok(None);
        };
        *timestamp = raw;
        let stream_offset = message_start + start;
        *ranges = map_range(mappings, stream_offset, 8)?;
        *complete = mappings_cover(mappings, stream_offset, 8)?;
    }
    let file_id_offset = message_start + SMB2_HEADER_BYTES + 16;
    let file_id_ranges = map_range(mappings, file_id_offset, 16)?;
    let file_id_mapping_complete = mappings_cover(mappings, file_id_offset, 16)?;
    Ok(Some(Candidate {
        stream_offset: frame_offset,
        buffer_offset: buffer_start,
        file_id: file_id.to_vec(),
        timestamps,
        file_id_ranges,
        timestamp_ranges,
        file_id_mapping_complete,
        timestamp_mapping_complete,
    }))
}

fn candidate_finding(node: &Node, candidate: &Candidate) -> BehaviorFinding {
    let timestamp_names = ["creation", "last_access", "last_write", "change"];
    let timestamps = timestamp_names
        .iter()
        .zip(candidate.timestamps.iter())
        .zip(
            candidate
                .timestamp_ranges
                .iter()
                .zip(candidate.timestamp_mapping_complete.iter()),
        )
        .enumerate()
        .map(
            |(index, ((name, raw_ticks), (source_ranges, source_mapping_complete)))| {
                let offset = candidate.stream_offset + 4 + candidate.buffer_offset + index * 8;
                json!({
                    "name":name,
                    "raw_ticks":raw_ticks,
                    "meaning":timestamp_meaning(*raw_ticks),
                    "stream_range":{"offset":offset,"length":8},
                    "source_ranges":source_ranges,
                    "source_mapping_complete":source_mapping_complete,
                })
            },
        )
        .collect::<Vec<_>>();
    let mut source_ranges = candidate.file_id_ranges.clone();
    for ranges in &candidate.timestamp_ranges {
        for range in ranges {
            if !source_ranges.contains(range) {
                source_ranges.push(range.clone());
            }
        }
    }
    let mut packet_numbers = source_ranges
        .iter()
        .filter_map(|range| range.packet)
        .collect::<Vec<_>>();
    packet_numbers.sort_unstable();
    packet_numbers.dedup();
    let mut file_id = String::with_capacity(candidate.file_id.len() * 2);
    for byte in &candidate.file_id {
        use std::fmt::Write as _;
        let _ = write!(file_id, "{byte:02x}");
    }
    let source_mapping_complete = candidate.file_id_mapping_complete
        && candidate
            .timestamp_mapping_complete
            .iter()
            .all(|complete| *complete);
    BehaviorFinding {
        kind: BehaviorKind::Smb2FileBasicInfoSetRequest,
        status: EvidenceStatus::Hypothesis,
        node_ids: vec![node.id],
        packet_numbers,
        source_ranges,
        details: json!({
            "file_id":file_id,
            "file_id_stream_range":{"offset":candidate.stream_offset + 4 + SMB2_HEADER_BYTES + 16,"length":16},
            "file_id_source_mapping_complete":candidate.file_id_mapping_complete,
            "source_mapping_complete":source_mapping_complete,
            "information_type":"file",
            "file_information_class":"file_basic_information",
            "operation_result":"unresolved",
            "timestamps":timestamps,
        }),
    }
}

fn mappings_cover(
    mappings: &[Mapping],
    offset: usize,
    length: usize,
) -> Result<bool, Box<dyn Error>> {
    let end = offset
        .checked_add(length)
        .ok_or("source mapping coverage overflow")?;
    let mut intervals = mappings
        .iter()
        .filter_map(|mapping| {
            let mapped_end = mapping
                .offset
                .checked_add(usize::try_from(mapping.range.length).ok()?)?;
            let first = offset.max(mapping.offset);
            let last = end.min(mapped_end);
            (first < last).then_some((first, last))
        })
        .collect::<Vec<_>>();
    intervals.sort_unstable();
    let mut covered = offset;
    for (first, last) in intervals {
        if first > covered {
            return Ok(false);
        }
        covered = covered.max(last);
        if covered == end {
            return Ok(true);
        }
    }
    Ok(false)
}

const fn timestamp_meaning(value: u64) -> &'static str {
    match value {
        0 => "no_change",
        u64::MAX => "disable_future_updates",
        value if value == u64::MAX - 1 => "reenable_future_updates",
        value if value <= i64::MAX as u64 => "literal_time_request",
        _ => "invalid_negative_time_request",
    }
}

fn map_range(
    mappings: &[Mapping],
    offset: usize,
    length: usize,
) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    let end = offset
        .checked_add(length)
        .ok_or("SMB2 stream offset overflow")?;
    let mut ranges = Vec::new();
    for mapping in mappings {
        let mapped_end = mapping
            .offset
            .checked_add(usize::try_from(mapping.range.length)?)
            .ok_or("source mapping offset overflow")?;
        let first = offset.max(mapping.offset);
        let last = end.min(mapped_end);
        if first < last {
            ranges.push(SourceRange {
                source: mapping.range.source.clone(),
                packet: mapping.range.packet,
                offset: mapping
                    .range
                    .offset
                    .checked_add(u64::try_from(first - mapping.offset)?)
                    .ok_or("source mapping range overflow")?,
                length: u64::try_from(last - first)?,
            });
        }
    }
    Ok(ranges)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
