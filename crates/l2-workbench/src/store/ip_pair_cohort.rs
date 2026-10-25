use super::{Flow, FlowCohortAnalysis, FlowCohortCoverage, Result, Store, invalid};
use crate::{
    investigation::BuildResult,
    reconstruction::{Limits, Reconstructor},
};
use rusqlite::params;

struct PairKey {
    id: i64,
    flows: u64,
    records: u64,
    frame_bytes: u64,
}

#[derive(Clone, Copy)]
struct FlowCursor {
    first_packet: u32,
    flow_id: i64,
}

struct Chunk {
    flows: Vec<Flow>,
    after: Option<FlowCursor>,
    oversized_flows: u64,
    exhausted: bool,
}

impl Store {
    /// Analyze bounded groups of flows sharing one source, scope, and unordered IP pair
    ///
    /// Ports and transport protocols do not split a pair group. Oversized groups are processed
    /// in source-order chunks, with the group marked split because cross-chunk relations are
    /// unresolved
    ///
    /// # Errors
    /// Returns invalid reconstruction limits, damaged indexes, analysis, or visitor failures
    pub fn visit_ip_pair_cohort_analyses(
        &self,
        limits: Limits,
        mut visitor: impl FnMut(FlowCohortAnalysis) -> Result<()>,
    ) -> Result<FlowCohortCoverage> {
        Reconstructor::with_limits(limits)?;
        // Temporary tables keep capture-wide grouping and member summaries off the heap
        self.prepare_pair_keys()?;
        let result = self.visit_prepared_pair_analyses(limits, &mut visitor);
        let cleanup = self.connection.execute_batch(
            "DROP TABLE temp.l2_workbench_ip_pair_groups; DROP TABLE temp.l2_workbench_flow_stats;",
        );
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
            (Ok(coverage), Ok(())) => Ok(coverage),
        }
    }

    fn visit_prepared_pair_analyses(
        &self,
        limits: Limits,
        visitor: &mut impl FnMut(FlowCohortAnalysis) -> Result<()>,
    ) -> Result<FlowCohortCoverage> {
        let mut coverage = FlowCohortCoverage::default();
        let mut previous_pair_id = 0_i64;

        // Pair IDs follow source, scope, and address order in the disk spool
        while let Some(pair) = self.next_pair_key(previous_pair_id)? {
            previous_pair_id = pair.id;
            let split = !fits(pair.records, pair.frame_bytes, limits)?;
            record_pair_start(&mut coverage, &pair, split)?;
            let (retained, complete) =
                self.analyze_pair(&pair, split, limits, &mut coverage, visitor)?;
            record_pair_result(&mut coverage, &pair, retained, complete)?;
        }

        Ok(coverage)
    }

    fn analyze_pair(
        &self,
        pair: &PairKey,
        split: bool,
        limits: Limits,
        coverage: &mut FlowCohortCoverage,
        visitor: &mut impl FnMut(FlowCohortAnalysis) -> Result<()>,
    ) -> Result<(u64, bool)> {
        let mut cursor = None;
        let mut retained = 0_u64;
        let mut analyzed = false;
        let mut complete = !split;
        let mut skipped = false;
        loop {
            let chunk = self.next_pair_chunk(pair, cursor, limits)?;
            cursor = chunk.after;
            coverage.oversized_flows_skipped =
                add(coverage.oversized_flows_skipped, chunk.oversized_flows)?;
            skipped |= chunk.oversized_flows != 0;
            if chunk.flows.is_empty() {
                if chunk.exhausted {
                    break;
                }
                continue;
            }
            if chunk.flows.len() == 1 {
                coverage.singleton_chunks_skipped = add(coverage.singleton_chunks_skipped, 1)?;
                skipped = true;
                if chunk.exhausted {
                    break;
                }
                continue;
            }
            let (chunk_retained, chunk_complete) =
                self.analyze_chunk(chunk, split, limits, coverage, visitor)?;
            retained = add(retained, chunk_retained)?;
            analyzed = true;
            complete &= chunk_complete;
            if cursor.is_none() {
                return Err(invalid("cohort chunk did not advance its flow cursor"));
            }
        }
        Ok((retained, analyzed && complete && !skipped))
    }

    fn analyze_chunk(
        &self,
        chunk: Chunk,
        split: bool,
        limits: Limits,
        coverage: &mut FlowCohortCoverage,
        visitor: &mut impl FnMut(FlowCohortAnalysis) -> Result<()>,
    ) -> Result<(u64, bool)> {
        let flow_ids = chunk.flows.iter().map(|flow| flow.id).collect::<Vec<_>>();
        let selected = chunk_record_count(&chunk.flows)?;
        let source_id = chunk
            .flows
            .first()
            .ok_or_else(|| invalid("cohort chunk has no member flows"))?
            .source_id
            .clone();
        let mut packet_flow_ids = Vec::new();
        let indexed_records = self.visit_flow_cohort_packets(&source_id, &flow_ids, |packet| {
            let flow_id = packet
                .flow
                .ok_or_else(|| invalid("selected cohort packet has no indexed flow"))?;
            packet_flow_ids.push((packet.number, flow_id));
            Ok(true)
        })?;
        if indexed_records != selected {
            return Err(invalid(
                "cohort packet map differs from selected flow records",
            ));
        }
        let result = self.investigate_flows(&flow_ids, limits)?;
        let retained = retained_records(&result)?;
        if retained > selected {
            return Err(invalid("cohort retained more records than it selected"));
        }
        let complete = result.complete && retained == selected;
        coverage.reanalyzed_flows =
            add(coverage.reanalyzed_flows, u64::try_from(chunk.flows.len())?)?;
        coverage.analysis_chunks = add(coverage.analysis_chunks, 1)?;
        if complete {
            coverage.complete_chunks = add(coverage.complete_chunks, 1)?;
        } else {
            coverage.incomplete_chunks = add(coverage.incomplete_chunks, 1)?;
        }
        visitor(FlowCohortAnalysis {
            member_flows: chunk.flows,
            packet_flow_ids,
            split,
            result,
        })?;
        Ok((retained, complete))
    }

    fn prepare_pair_keys(&self) -> Result<()> {
        // Build a disk-backed summary once so each pair page uses indexed lookups
        let prepared = (|| {
            self.connection.execute_batch(
                "DROP TABLE IF EXISTS temp.l2_workbench_ip_pair_groups; DROP TABLE IF EXISTS temp.l2_workbench_flow_stats; CREATE TEMP TABLE l2_workbench_flow_stats(flow_id INTEGER PRIMARY KEY,source INTEGER NOT NULL,scope INTEGER NOT NULL,source_id TEXT NOT NULL,protocol INTEGER NOT NULL,a BLOB NOT NULL,ap INTEGER NOT NULL,b BLOB NOT NULL,bp INTEGER NOT NULL,address_a BLOB NOT NULL,address_b BLOB NOT NULL,first_packet INTEGER NOT NULL,last_packet INTEGER NOT NULL,packets INTEGER NOT NULL,frame_bytes INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,scope_value BLOB NOT NULL) STRICT;",
            )?;
            self.connection.execute_batch(
                "INSERT INTO temp.l2_workbench_flow_stats SELECT f.id,f.source,f.scope,s.sha256,f.protocol,f.a,f.ap,f.b,f.bp,CASE WHEN f.a<=f.b THEN f.a ELSE f.b END,CASE WHEN f.a<=f.b THEN f.b ELSE f.a END,MIN(p.number),MAX(p.number),COUNT(*),SUM(p.length),SUM(p.payload_length),c.value FROM flows f JOIN sources s ON s.id=f.source JOIN scopes c ON c.id=f.scope JOIN packets p ON p.flow=f.id GROUP BY f.id; CREATE INDEX temp.l2_workbench_flow_stats_ip_pair ON l2_workbench_flow_stats(source,scope,address_a,address_b,first_packet,flow_id); CREATE TEMP TABLE l2_workbench_ip_pair_groups(id INTEGER PRIMARY KEY,source INTEGER NOT NULL,scope INTEGER NOT NULL,address_a BLOB NOT NULL,address_b BLOB NOT NULL,flows INTEGER NOT NULL,records INTEGER NOT NULL,frame_bytes INTEGER NOT NULL) STRICT; WITH pair_groups AS (SELECT source,scope,address_a,address_b,COUNT(*) AS flows,SUM(packets) AS records,SUM(frame_bytes) AS frame_bytes FROM temp.l2_workbench_flow_stats GROUP BY source,scope,address_a,address_b HAVING COUNT(*)>1) INSERT INTO temp.l2_workbench_ip_pair_groups(id,source,scope,address_a,address_b,flows,records,frame_bytes) SELECT ROW_NUMBER() OVER (ORDER BY source,scope,address_a,address_b),source,scope,address_a,address_b,flows,records,frame_bytes FROM pair_groups ORDER BY source,scope,address_a,address_b;",
            )?;
            Ok(())
        })();
        if prepared.is_err() {
            let _ = self.connection.execute_batch(
                "DROP TABLE IF EXISTS temp.l2_workbench_ip_pair_groups; DROP TABLE IF EXISTS temp.l2_workbench_flow_stats;",
            );
        }
        prepared
    }

    fn next_pair_key(&self, after_id: i64) -> Result<Option<PairKey>> {
        let mut statement = self.connection.prepare(
            "SELECT id,flows,records,frame_bytes FROM temp.l2_workbench_ip_pair_groups WHERE id>?1 ORDER BY id LIMIT 1",
        )?;
        let mut rows = statement.query([after_id])?;
        let key = if let Some(row) = rows.next()? {
            Some(PairKey {
                id: row.get(0)?,
                flows: u64::try_from(row.get::<_, i64>(1)?)?,
                records: u64::try_from(row.get::<_, i64>(2)?)?,
                frame_bytes: u64::try_from(row.get::<_, i64>(3)?)?,
            })
        } else {
            None
        };
        Ok(key)
    }

    fn next_pair_chunk(
        &self,
        pair: &PairKey,
        after: Option<FlowCursor>,
        limits: Limits,
    ) -> Result<Chunk> {
        let first_packet = after.map(|cursor| i64::from(cursor.first_packet));
        let flow_id = after.map(|cursor| cursor.flow_id);
        let mut statement = self.connection.prepare(
            "SELECT flows.flow_id,flows.source_id,flows.protocol,flows.a,flows.ap,flows.b,flows.bp,flows.first_packet,flows.last_packet,flows.packets,flows.frame_bytes,flows.payload_bytes,flows.scope_value FROM temp.l2_workbench_ip_pair_groups groups JOIN temp.l2_workbench_flow_stats flows ON groups.source=flows.source AND groups.scope=flows.scope AND groups.address_a=flows.address_a AND groups.address_b=flows.address_b WHERE groups.id=?1 AND (?2 IS NULL OR flows.first_packet>?2 OR (flows.first_packet=?2 AND flows.flow_id>?3)) ORDER BY flows.first_packet,flows.flow_id",
        )?;
        let mut rows = statement.query(params![pair.id, first_packet, flow_id])?;
        let mut chunk = Vec::new();
        let mut after = after;
        let mut bytes = 0_u64;
        let mut records = 0_u64;
        let mut oversized_flows = 0_u64;
        let mut exhausted = true;

        while let Some(row) = rows.next()? {
            let flow = Flow {
                id: row.get(0)?,
                source_id: row.get(1)?,
                protocol: row.get(2)?,
                endpoint_a: super::flows::ip(&row.get::<_, Vec<u8>>(3)?)?,
                port_a: row.get(4)?,
                endpoint_b: super::flows::ip(&row.get::<_, Vec<u8>>(5)?)?,
                port_b: row.get(6)?,
                first_packet: u32::try_from(row.get::<_, i64>(7)?)?,
                last_packet: u32::try_from(row.get::<_, i64>(8)?)?,
                packets: u64::try_from(row.get::<_, i64>(9)?)?,
                frame_bytes: u64::try_from(row.get::<_, i64>(10)?)?,
                payload_bytes: u64::try_from(row.get::<_, i64>(11)?)?,
                scope: serde_json::from_slice(&row.get::<_, Vec<u8>>(12)?)?,
            };
            let candidate_cursor = FlowCursor {
                first_packet: flow.first_packet,
                flow_id: flow.id,
            };
            if !fits(flow.packets, flow.frame_bytes, limits)? {
                if chunk.is_empty() {
                    after = Some(candidate_cursor);
                    oversized_flows = add(oversized_flows, 1)?;
                    continue;
                }
                exhausted = false;
                break;
            }
            let next_records = add(records, flow.packets)?;
            let next_bytes = add(bytes, flow.frame_bytes)?;
            if next_records > u64::try_from(limits.units)?
                || next_records > limits.frames
                || next_bytes > u64::try_from(limits.bytes)?
            {
                exhausted = false;
                break;
            }
            records = next_records;
            bytes = next_bytes;
            after = Some(candidate_cursor);
            chunk.push(flow);
        }

        Ok(Chunk {
            flows: chunk,
            after,
            oversized_flows,
            exhausted,
        })
    }
}

fn record_pair_start(coverage: &mut FlowCohortCoverage, pair: &PairKey, split: bool) -> Result<()> {
    if pair.flows < 2 {
        return Err(invalid("indexed IP-pair cohort has fewer than two flows"));
    }
    coverage.multi_flow_groups = add(coverage.multi_flow_groups, 1)?;
    coverage.selected_records = add(coverage.selected_records, pair.records)?;
    if split {
        coverage.split_groups = add(coverage.split_groups, 1)?;
    }
    Ok(())
}

fn record_pair_result(
    coverage: &mut FlowCohortCoverage,
    pair: &PairKey,
    retained: u64,
    complete: bool,
) -> Result<()> {
    if retained > pair.records {
        return Err(invalid(
            "cohort retained more records than the group selected",
        ));
    }
    coverage.retained_records = add(coverage.retained_records, retained)?;
    coverage.omitted_records = add(coverage.omitted_records, pair.records - retained)?;
    if complete {
        coverage.complete_groups = add(coverage.complete_groups, 1)?;
    } else {
        coverage.incomplete_groups = add(coverage.incomplete_groups, 1)?;
    }
    Ok(())
}

fn fits(records: u64, bytes: u64, limits: Limits) -> Result<bool> {
    Ok(records <= limits.frames
        && records <= u64::try_from(limits.units)?
        && bytes <= u64::try_from(limits.bytes)?)
}

fn chunk_record_count(flows: &[Flow]) -> Result<u64> {
    flows
        .iter()
        .try_fold(0_u64, |count, flow| add(count, flow.packets))
}

fn retained_records(result: &BuildResult) -> Result<u64> {
    result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .and_then(|node| node.details.get("retained_frames"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("cohort analysis is missing its retained record count"))
}

fn add(current: u64, increment: u64) -> Result<u64> {
    current
        .checked_add(increment)
        .ok_or_else(|| invalid("IP-pair cohort coverage count overflow"))
}
