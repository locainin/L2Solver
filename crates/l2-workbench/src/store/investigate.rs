use super::{Result, Store, invalid, packets};
use crate::{
    evidence::{FLOW_SELECTION_KIND, FLOW_SELECTION_PREDICATE},
    investigation::{BuildInput, BuildResult, Record, build_selected_with_case},
    reconstruction::{Limits, Reconstructor, RecordRetentionLimit, RecordRetentionStatus},
};
use serde::Serialize;
use std::collections::HashSet;

const FLOW_SELECTION_RECEIPT_SCHEMA_VERSION: u64 = 2;

struct SelectedFlowSource {
    flow_ids: Vec<i64>,
    counts: Vec<FlowContribution>,
    source: super::Source,
}

struct FlowEvidence<'a> {
    requested_flows: &'a [i64],
    selected_flows: &'a [i64],
    flow_counts: &'a [FlowContribution],
    source_id: &'a str,
    total: u64,
    retained: u64,
    omitted: u64,
    retention_limits: &'a [RecordRetentionLimit],
}

#[derive(Serialize)]
struct FlowContribution {
    flow_id: i64,
    packet_records: u64,
}

#[derive(Serialize)]
struct FlowSelectionReceipt<'a> {
    requested_flow_ids: &'a [i64],
    flow_contributions: &'a [FlowContribution],
}

impl Store {
    /// Analyze a disk-indexed tuple through the canonical evidence and application engine
    ///
    /// All original records stay on disk when the bounded analysis retains only a prefix
    ///
    /// # Errors
    /// Rejects missing tuples, damaged source ranges, and invalid evidence metadata
    pub fn investigate_flow(&self, flow: i64) -> Result<BuildResult> {
        self.investigate_flows(&[flow], Limits::default())
    }

    /// Analyze the capture-order union of selected indexed flows from one retained source
    ///
    /// The supplied flow order is retained as selection evidence; repeated IDs select a flow once
    ///
    /// # Errors
    /// Rejects empty selections, missing flows, cross-source cohorts, damaged ranges, and invalid evidence
    pub fn investigate_flows(&self, flow_ids: &[i64], limits: Limits) -> Result<BuildResult> {
        let selection = self.select_flow_sources(flow_ids)?;
        let (records, total, retention_limits) =
            self.retain_flow_cohort(&selection.source, &selection.flow_ids, limits)?;
        let retained = u64::try_from(records.len())?;
        let omitted = total - retained;
        let input = BuildInput {
            label: &selection.source.label,
            length: selection.source.bytes,
            sha256_hex: selection
                .source
                .source_id
                .strip_prefix("sha256:")
                .ok_or_else(|| invalid("invalid indexed source hash"))?,
            records: &records,
            frames_seen: selection.source.packets,
        };
        // Preserve required scope and collection receipts before optional packet analysis
        let mut initial = initial_store_case(&selection.source, self.memory_budget())?;
        add_flow_evidence(
            &mut initial,
            &FlowEvidence {
                requested_flows: flow_ids,
                selected_flows: &selection.flow_ids,
                flow_counts: &selection.counts,
                source_id: &selection.source.source_id,
                total,
                retained,
                omitted,
                retention_limits: &retention_limits,
            },
        )?;
        let mut result = build_selected_with_case(input, total, limits, initial.case)?;
        result.case.add_limitation("This indexed flow selection includes complete unfragmented transport envelopes only; raw fragments remain in the source and may require separate reconstruction")?;
        Ok(result)
    }

    /// Visit bounded independent page Cases after one flow's retained prefix
    ///
    /// Pages preserve original packet numbers and use the canonical selected-record
    /// investigation path. Each source frame is integrity checked once as it enters a page.
    /// Page boundaries remain explicit; protocol state is never joined between Cases.
    ///
    /// # Errors
    /// Rejects an invalid prefix, a record that cannot fit any page, changed source bytes,
    /// analysis failures, visitor failures, and counter overflow
    pub fn visit_flow_pages_after_prefix(
        &self,
        flow: i64,
        retained_prefix_records: u64,
        limits: Limits,
        visitor: impl FnMut(super::FlowPageAnalysis) -> Result<()>,
    ) -> Result<super::FlowPageCoverage> {
        Reconstructor::with_limits(limits)?;
        let (source, total_records) = self.flow_source(flow)?;
        if retained_prefix_records > total_records {
            return Err(invalid(
                "retained flow prefix exceeds the indexed flow record count",
            ));
        }
        let selected_records = total_records - retained_prefix_records;
        let coverage = super::FlowPageCoverage {
            selected_records,
            ..super::FlowPageCoverage::default()
        };
        if selected_records == 0 {
            return Ok(coverage);
        }
        let after_packet = flow_prefix_end(self, flow, retained_prefix_records)?;
        visit_flow_page_tail(
            self,
            FlowPageRequest {
                source: &source,
                flow,
                total_records,
                prefix_records: retained_prefix_records,
                selected_records,
                after_packet,
                limits,
            },
            visitor,
        )
    }

    fn select_flow_sources(&self, flow_ids: &[i64]) -> Result<SelectedFlowSource> {
        if flow_ids.is_empty() {
            return Err(invalid("at least one indexed flow must be selected"));
        }

        let mut selected_flows = Vec::new();
        let mut flow_counts = Vec::new();
        let mut seen_flows = HashSet::new();
        let mut source = None;
        for &flow in flow_ids {
            if flow <= 0 {
                return Err(invalid("indexed flow IDs must be positive"));
            }
            if !seen_flows.insert(flow) {
                continue;
            }
            let (candidate, packet_count) = self.flow_source(flow)?;
            if source
                .as_ref()
                .is_some_and(|retained: &super::Source| retained.source_id != candidate.source_id)
            {
                return Err(invalid(
                    "selected indexed flows belong to different retained sources",
                ));
            }
            source.get_or_insert(candidate);
            selected_flows.push(flow);
            flow_counts.push(FlowContribution {
                flow_id: flow,
                packet_records: packet_count,
            });
        }
        let source = source.ok_or_else(|| invalid("at least one indexed flow must be selected"))?;
        Ok(SelectedFlowSource {
            flow_ids: selected_flows,
            counts: flow_counts,
            source,
        })
    }

    fn retain_flow_cohort(
        &self,
        source: &super::Source,
        flow_ids: &[i64],
        limits: Limits,
    ) -> Result<(Vec<Record>, u64, Vec<RecordRetentionLimit>)> {
        let mut file = packets::source_file(&self.sources.path(), &source.source_id)?;
        let byte_limit = u64::try_from(limits.bytes)?;
        let mut retained_bytes = 0_u64;
        let mut records = Vec::new();
        let mut retention_limits = Vec::new();
        // The union query is capture ordered, so each budget keeps one source-order prefix
        let total = self.visit_flow_cohort_packets(&source.source_id, flow_ids, |packet| {
            let frame_count = u64::try_from(records.len())?;
            let frame_limit_hit = frame_count == limits.frames;
            let byte_limit_hit = packet.range.length > byte_limit - retained_bytes;
            let unit_limit_hit = records.len() == limits.units;
            if frame_limit_hit || byte_limit_hit || unit_limit_hit {
                if frame_limit_hit {
                    retention_limits.push(RecordRetentionLimit::Frames);
                }
                if byte_limit_hit {
                    retention_limits.push(RecordRetentionLimit::Bytes);
                }
                if unit_limit_hit {
                    retention_limits.push(RecordRetentionLimit::Units);
                }
                return Ok(false);
            }
            let frame = packets::read_frame(&self.connection, &mut file, &packet)?;
            retained_bytes += packet.range.length;
            records.push(Record {
                number: packet.number,
                frame,
            });
            Ok(true)
        })?;
        Ok((records, total, retention_limits))
    }

    pub(super) fn visit_flow_cohort_packets(
        &self,
        source_id: &str,
        flow_ids: &[i64],
        mut visitor: impl FnMut(super::Packet) -> Result<bool>,
    ) -> Result<u64> {
        // A temporary table avoids a variable-count limit while keeping SQLite's sort file-backed
        self.connection.execute_batch(
            "DROP TABLE IF EXISTS temp.l2_workbench_cohort_flows; CREATE TEMP TABLE l2_workbench_cohort_flows (id INTEGER PRIMARY KEY)",
        )?;
        let selected = (|| {
            for flow in flow_ids {
                self.connection.execute(
                    "INSERT INTO temp.l2_workbench_cohort_flows(id) VALUES(?1)",
                    [flow],
                )?;
            }
            let total: u64 = self.connection.query_row(
                "SELECT COUNT(*) FROM packets p JOIN sources s ON s.id=p.source JOIN temp.l2_workbench_cohort_flows f ON f.id=p.flow WHERE s.sha256=?1",
                [source_id],
                |row| row.get(0),
            )?;
            let mut statement = self.connection.prepare(
                "SELECT s.sha256,p.number,p.offset,p.length,p.flow FROM packets p JOIN sources s ON s.id=p.source JOIN temp.l2_workbench_cohort_flows f ON f.id=p.flow WHERE s.sha256=?1 ORDER BY p.number",
            )?;
            let mut rows = statement.query([source_id])?;
            while let Some(row) = rows.next()? {
                if !visitor(packets::packet_row(row)?)? {
                    break;
                }
            }
            Ok(total)
        })();

        // Drop the temporary selection even when a database read or packet check fails
        let cleanup = self
            .connection
            .execute_batch("DROP TABLE temp.l2_workbench_cohort_flows");
        match (selected, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
            (Ok(total), Ok(())) => Ok(total),
        }
    }
}

#[derive(Clone, Copy)]
struct FlowPageRequest<'a> {
    source: &'a super::Source,
    flow: i64,
    total_records: u64,
    prefix_records: u64,
    selected_records: u64,
    after_packet: u32,
    limits: Limits,
}

fn visit_flow_page_tail(
    store: &Store,
    request: FlowPageRequest<'_>,
    mut visitor: impl FnMut(super::FlowPageAnalysis) -> Result<()>,
) -> Result<super::FlowPageCoverage> {
    let mut coverage = super::FlowPageCoverage {
        selected_records: request.selected_records,
        ..super::FlowPageCoverage::default()
    };
    let mut after_packet = request.after_packet;
    let mut pending = None;
    let mut visited_records = 0_u64;
    let mut file = packets::source_file(&store.sources.path(), &request.source.source_id)?;
    loop {
        let (page_packets, exhausted) = collect_flow_page_packets(
            &store.connection,
            request.flow,
            &mut after_packet,
            &mut pending,
            request.limits,
        )?;
        if page_packets.is_empty() {
            if exhausted {
                break;
            }
            return Err(super::FlowPageError::NoProgress.into());
        }

        let records = read_flow_page_records(
            store,
            &mut file,
            request.flow,
            &request.source.source_id,
            page_packets,
        )?;
        visited_records = visited_records
            .checked_add(u64::try_from(records.len())?)
            .ok_or_else(|| invalid("flow page selected-record count overflowed"))?;
        let page_index = coverage
            .pages
            .checked_add(1)
            .ok_or_else(|| invalid("flow page count overflowed"))?;
        let page = build_flow_page(request, page_index, &records, store.memory_budget())?;
        coverage.pages = page_index;
        coverage.retained_records = coverage
            .retained_records
            .checked_add(page.retained_records)
            .ok_or_else(|| invalid("flow page retained-record count overflowed"))?;
        visitor(page)?;
        if exhausted {
            break;
        }
    }
    finish_flow_page_coverage(coverage, visited_records)
}

fn read_flow_page_records(
    store: &Store,
    file: &mut std::fs::File,
    flow: i64,
    source_id: &str,
    packets: Vec<super::Packet>,
) -> Result<Vec<Record>> {
    packets
        .into_iter()
        .map(|packet| {
            if packet.flow != Some(flow) || packet.source_id != source_id {
                return Err(invalid(
                    "flow page record does not match its indexed source",
                ));
            }
            let frame = packets::read_frame(&store.connection, file, &packet)?;
            Ok(Record {
                number: packet.number,
                frame,
            })
        })
        .collect()
}

fn finish_flow_page_coverage(
    mut coverage: super::FlowPageCoverage,
    visited_records: u64,
) -> Result<super::FlowPageCoverage> {
    if visited_records != coverage.selected_records {
        return Err(invalid(
            "flow page count changed while indexed records were visited",
        ));
    }
    coverage.omitted_records = coverage
        .selected_records
        .checked_sub(coverage.retained_records)
        .ok_or_else(|| invalid("flow pages retained more records than selected"))?;
    if coverage.omitted_records != 0 {
        return Err(invalid("flow pages omitted an indexed flow record"));
    }
    Ok(coverage)
}

fn flow_prefix_end(store: &Store, flow: i64, prefix_records: u64) -> Result<u32> {
    if prefix_records == 0 {
        return Ok(0);
    }
    let offset = prefix_records
        .checked_sub(1)
        .ok_or_else(|| invalid("retained flow prefix offset underflowed"))?;
    Ok(store.connection.query_row(
        "SELECT number FROM packets WHERE flow=?1 ORDER BY number LIMIT 1 OFFSET ?2",
        rusqlite::params![flow, i64::try_from(offset)?],
        |row| row.get(0),
    )?)
}

fn collect_flow_page_packets(
    connection: &rusqlite::Connection,
    flow: i64,
    after_packet: &mut u32,
    pending: &mut Option<super::Packet>,
    limits: Limits,
) -> Result<(Vec<super::Packet>, bool)> {
    let mut page = Vec::new();
    let mut page_bytes = 0_usize;
    if let Some(packet) = pending.take() {
        page_bytes = usize::try_from(packet.range.length)?;
        page.push(packet);
    }

    let mut statement = connection.prepare(
        "SELECT s.sha256,p.number,p.offset,p.length,p.flow FROM packets p JOIN sources s ON s.id=p.source WHERE p.flow=?1 AND p.number>?2 ORDER BY p.number",
    )?;
    let mut rows = statement.query(rusqlite::params![flow, *after_packet])?;
    let mut exhausted = true;
    while let Some(row) = rows.next()? {
        let packet = packets::packet_row(row)?;
        *after_packet = packet.number;
        let frame_bytes = usize::try_from(packet.range.length)?;
        if frame_bytes > limits.bytes {
            return Err(super::FlowPageError::RecordExceedsByteLimit {
                packet: packet.number,
                frame_bytes: packet.range.length,
                byte_limit: limits.bytes,
            }
            .into());
        }
        if !flow_page_fits(page.len(), page_bytes, frame_bytes, limits)? {
            if page.is_empty() {
                return Err(super::FlowPageError::NoProgress.into());
            }
            // The cursor passed this row, so pending supplies it once on the next page
            *pending = Some(packet);
            exhausted = false;
            break;
        }
        page_bytes = page_bytes
            .checked_add(frame_bytes)
            .ok_or_else(|| invalid("flow page byte count overflowed"))?;
        page.push(packet);
    }
    Ok((page, exhausted))
}

fn flow_page_fits(
    current_records: usize,
    current_bytes: usize,
    next_frame_bytes: usize,
    limits: Limits,
) -> Result<bool> {
    let next_records = current_records
        .checked_add(1)
        .ok_or_else(|| invalid("flow page record count overflowed"))?;
    let within_frames = u64::try_from(next_records)? <= limits.frames;
    let within_units = next_records <= limits.units;
    let within_bytes = current_bytes
        .checked_add(next_frame_bytes)
        .is_some_and(|bytes| bytes <= limits.bytes);
    Ok(within_frames && within_units && within_bytes)
}

fn build_flow_page(
    request: FlowPageRequest<'_>,
    page_index: u64,
    records: &[Record],
    budget: Option<&crate::job::MemoryBudget>,
) -> Result<super::FlowPageAnalysis> {
    let source = request.source;
    let selected_records = u64::try_from(records.len())?;
    let (first_packet, last_packet) = flow_page_bounds(records)?;
    let input = BuildInput {
        label: &source.label,
        length: source.bytes,
        sha256_hex: source
            .source_id
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("invalid indexed source hash"))?,
        records,
        frames_seen: source.packets,
    };
    let metadata = FlowPageMetadata {
        flow: request.flow,
        page_index,
        first_packet,
        last_packet,
        flow_selected_records: request.total_records,
        prefix_records_skipped: request.prefix_records,
        selected_records,
        retained_records: selected_records,
        omitted_records: 0,
    };
    // Keep page and selection receipts before optional analysis can exhaust Case quotas
    let mut initial = initial_store_case(source, budget)?;
    add_flow_page_evidence(&mut initial, source, metadata)?;
    let mut result =
        build_selected_with_case(input, selected_records, request.limits, initial.case)?;
    let retained_records = capture_summary_retained_records(&result)?;
    if retained_records != selected_records {
        return Err(invalid(
            "bounded flow page did not retain every selected record",
        ));
    }
    result.case.add_limitation("This indexed flow page includes complete unfragmented transport envelopes only; raw fragments remain in the source and may require separate reconstruction")?;
    result.case.mark_incomplete(
        "This bounded flow page is an independent selected-record analysis; TCP/session/application state was not joined across page boundaries, so objects split across pages remain unresolved",
    )?;
    result.complete = false;
    result.case.validate()?;
    Ok(super::FlowPageAnalysis {
        page_index,
        first_packet,
        last_packet,
        selected_records,
        retained_records,
        omitted_records: 0,
        result,
    })
}

fn initial_store_case(
    source: &super::Source,
    budget: Option<&crate::job::MemoryBudget>,
) -> Result<BuildResult> {
    let case = if let Some(budget) = budget {
        crate::evidence::Case::with_memory_budget(budget)?
    } else {
        crate::evidence::Case::new()
    };
    let mut result = BuildResult {
        case,
        complete: true,
    };
    let hash = source
        .source_id
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("invalid indexed source hash"))?;
    let source_id = result
        .case
        .add_source(&source.label, "capture", source.bytes, hash, None)?;
    crate::capture_collection::apply_to_case(&mut result, &source_id, source.collection_summary)?;
    Ok(result)
}

fn flow_page_bounds(records: &[Record]) -> Result<(u32, u32)> {
    let first = records
        .first()
        .map(|record| record.number)
        .ok_or_else(|| invalid("cannot build an empty flow page"))?;
    let last = records
        .last()
        .map(|record| record.number)
        .ok_or_else(|| invalid("cannot build an empty flow page"))?;
    Ok((first, last))
}

#[derive(Clone, Copy)]
struct FlowPageMetadata {
    flow: i64,
    page_index: u64,
    first_packet: u32,
    last_packet: u32,
    flow_selected_records: u64,
    prefix_records_skipped: u64,
    selected_records: u64,
    retained_records: u64,
    omitted_records: u64,
}

fn add_flow_page_evidence(
    result: &mut BuildResult,
    source: &super::Source,
    metadata: FlowPageMetadata,
) -> Result<()> {
    let retention_limits: [RecordRetentionLimit; 0] = [];
    let requested_flows = [metadata.flow];
    let selected_flows = [metadata.flow];
    let flow_counts = [FlowContribution {
        flow_id: metadata.flow,
        packet_records: metadata.selected_records,
    }];
    add_flow_evidence(
        result,
        &FlowEvidence {
            requested_flows: &requested_flows,
            selected_flows: &selected_flows,
            flow_counts: &flow_counts,
            source_id: &source.source_id,
            total: metadata.selected_records,
            retained: metadata.retained_records,
            omitted: metadata.omitted_records,
            retention_limits: &retention_limits,
        },
    )?;
    result.case.add_node(
        "index_flow_page",
        None,
        Vec::new(),
        serde_json::json!({
            "flow_id": metadata.flow,
            "page_index": metadata.page_index,
            "first_packet": metadata.first_packet,
            "last_packet": metadata.last_packet,
            "flow_selected_records": metadata.flow_selected_records,
            "prefix_records_skipped": metadata.prefix_records_skipped,
            "selected_records": metadata.selected_records,
            "retained_records": metadata.retained_records,
            "omitted_records": metadata.omitted_records,
        }),
    )?;
    Ok(())
}

fn capture_summary_retained_records(result: &BuildResult) -> Result<u64> {
    result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .and_then(|node| node.details.get("retained_frames"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("flow page is missing its retained record count"))
}

fn add_flow_evidence(result: &mut BuildResult, evidence: &FlowEvidence<'_>) -> Result<()> {
    let flow_memberships = evidence
        .flow_counts
        .iter()
        .try_fold(0_u64, |count, contribution| {
            count
                .checked_add(contribution.packet_records)
                .ok_or_else(|| invalid("selected flow packet count exceeds the supported range"))
        })?;
    if flow_memberships != evidence.total {
        return Err(invalid(
            "selected flow counts disagree with the source-local cohort packet count",
        ));
    }
    let receipt = serde_json::to_vec(&FlowSelectionReceipt {
        requested_flow_ids: evidence.requested_flows,
        flow_contributions: evidence.flow_counts,
    })?;
    result.case.add_bytes_node(
        FLOW_SELECTION_KIND,
        &receipt,
        Vec::new(),
        serde_json::Value::Object(flow_selection_details(evidence)),
    )?;
    Ok(())
}

fn flow_selection_details(
    evidence: &FlowEvidence<'_>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut details = serde_json::Map::new();
    details.insert("representation".to_owned(), serde_json::json!("json_blob"));
    details.insert(
        "receipt_schema_version".to_owned(),
        serde_json::json!(FLOW_SELECTION_RECEIPT_SCHEMA_VERSION),
    );
    details.insert(
        "flow_count".to_owned(),
        serde_json::json!(evidence.selected_flows.len()),
    );
    details.insert(
        "requested_flow_count".to_owned(),
        serde_json::json!(evidence.requested_flows.len()),
    );
    details.insert(
        "duplicate_flow_selections_removed".to_owned(),
        serde_json::json!(evidence.requested_flows.len() - evidence.selected_flows.len()),
    );
    details.insert(
        "selected_records".to_owned(),
        serde_json::json!(evidence.total),
    );
    details.insert(
        "retained_input_records".to_owned(),
        serde_json::json!(evidence.retained),
    );
    details.insert(
        "omitted_records".to_owned(),
        serde_json::json!(evidence.omitted),
    );
    let retention_status = if evidence.omitted == 0 {
        RecordRetentionStatus::Complete
    } else {
        RecordRetentionStatus::ResourceTruncatedPrefix
    };
    details.insert(
        "retention_status".to_owned(),
        serde_json::json!(retention_status),
    );
    details.insert(
        "retention_limits".to_owned(),
        serde_json::json!(evidence.retention_limits),
    );
    details.insert(
        "source_id".to_owned(),
        serde_json::json!(evidence.source_id),
    );
    details.insert(
        "predicate".to_owned(),
        serde_json::json!(FLOW_SELECTION_PREDICATE),
    );
    if let [flow_id] = evidence.requested_flows {
        details.insert("flow_id".to_owned(), serde_json::json!(flow_id));
    }
    details
}
