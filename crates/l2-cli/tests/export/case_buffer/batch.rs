//! Exercise the production batch's actual spill decision and ordered restore

use super::{MIB, TestResult};
use crate::{
    arguments::{RecoveryOptions, RecoveryProfile},
    export::{
        processing::{PendingCase, process_case_batch},
        recovery_cache::RecoveryContext,
    },
    workbench::full_source::{
        FlowAnalysis, FullSourceItem, PerFlowCoverage, ReconstructionCaseOmissions,
    },
};
use l2_workbench::{
    evidence::Case,
    investigation::BuildResult,
    job::{BufferedCaseSnapshot, MemoryBudget},
    sha256,
    store::Flow,
};
use serde_json::json;
use std::{error::Error, net::IpAddr, path::Path};

fn pending_case(memory: &MemoryBudget, index: usize) -> Result<PendingCase, Box<dyn Error>> {
    let mut case = Case::with_memory_budget(memory)?;
    let source_bytes = b"synthetic source";
    let source_id = case.add_source(
        "source.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &sha256(source_bytes),
        None,
    )?;
    let payload = vec![u8::try_from(index + 1)?; 12 * MIB];
    case.add_bytes_node("opaque", &payload, Vec::new(), json!({"ordinal": index}))?;
    if index == 0 {
        // The first Case has extra protocol inputs so later Cases can finish first
        for ordinal in 0..1024 {
            case.add_bytes_node(
                "tcp_byte_run",
                b"framed input",
                Vec::new(),
                json!({"ordinal": ordinal}),
            )?;
        }
    }
    let flow = Flow {
        id: i64::try_from(index + 1)?,
        source_id,
        scope: json!({}),
        protocol: 6,
        endpoint_a: "192.0.2.1".parse::<IpAddr>()?,
        port_a: 1234,
        endpoint_b: "198.51.100.2".parse::<IpAddr>()?,
        port_b: 80,
        first_packet: 1,
        last_packet: 1,
        packets: 1,
        frame_bytes: 1,
        payload_bytes: 1,
    };
    let coverage = PerFlowCoverage {
        selected_records: 1,
        retained_records: 1,
        omitted_records: 0,
        retention_limits: Vec::new(),
        reconstruction_omissions: ReconstructionCaseOmissions::default(),
        complete: true,
    };
    PendingCase::new(FullSourceItem::Flow(Box::new(FlowAnalysis {
        flow,
        result: BuildResult {
            case,
            complete: true,
        },
        coverage,
    })))
}

fn recover_batch(
    root: &Path,
    workers: usize,
) -> Result<(Vec<String>, BufferedCaseSnapshot), Box<dyn Error>> {
    let memory = MemoryBudget::new(192 * u64::try_from(MIB)?);
    let options = RecoveryOptions {
        profile: RecoveryProfile::Fast,
        jobs: Some(workers),
        memory_limit: 192 * u64::try_from(MIB)?,
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let context = RecoveryContext {
        cache: None,
        job: None,
        memory: Some(&memory),
        options: &options,
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()?;
    let mut batch = (0..6)
        .map(|index| pending_case(&memory, index))
        .collect::<Result<Vec<_>, _>>()?;
    let mut identities = Vec::new();
    process_case_batch(&mut batch, &pool, root, &context, |recovered| {
        let FullSourceItem::Flow(flow) = recovered.item else {
            return Err("unexpected Case kind".into());
        };
        let digest = sha256(&flow.result.case.to_json()?);
        println!(
            "production_batch workers={workers} flow={} case_sha256={digest}",
            flow.flow.id
        );
        identities.push(digest);
        Ok(())
    })?;
    assert!(batch.is_empty());
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.used_bytes, 0);
    assert_eq!(snapshot.buffered_cases.current_cases, 0);
    assert_eq!(snapshot.buffered_cases.current_snapshot_bytes, 0);
    assert_eq!(std::fs::read_dir(root)?.count(), 0);
    Ok((identities, snapshot.buffered_cases))
}

#[test]
fn production_batch_spills_later_cases_and_preserves_serial_identities() -> TestResult {
    let root = tempfile::tempdir()?;
    let (serial, _) = recover_batch(root.path(), 1)?;
    let (parallel, observed) = recover_batch(root.path(), 3)?;
    assert_eq!(parallel, serial);
    assert_eq!(parallel.len(), 6);
    assert!(
        observed.spilled_cases > 0,
        "production batch did not select a spill"
    );
    assert!(observed.peak_snapshot_bytes <= 96 * u64::try_from(MIB)?);
    println!(
        "production_batch spilled_cases={} peak_cases={} peak_snapshot_bytes={} spilled_snapshot_bytes={}",
        observed.spilled_cases,
        observed.peak_cases,
        observed.peak_snapshot_bytes,
        observed.spilled_snapshot_bytes
    );
    Ok(())
}
