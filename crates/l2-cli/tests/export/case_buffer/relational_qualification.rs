//! Run the full relational fixture through production batch admission on demand

use crate::{
    arguments::{RecoveryOptions, RecoveryProfile},
    export::{
        processing::{CollectionPhases, PendingCase, RecoveredCase, process_case_batch},
        recovery_cache::RecoveryContext,
    },
    workbench::{
        build_session_relative_fixture_named,
        full_source::{FlowAnalysis, FullSourceItem, PerFlowCoverage, ReconstructionCaseOmissions},
    },
};
use l2_workbench::{
    investigation::BuildResult,
    job::{Counter, Job, MemoryBudget, MemoryError, PhaseOutcome, cache::Cache},
    store::Flow,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    error::Error,
    fs::{self, File},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const LOW_MEMORY: u64 = 64 * 1024 * 1024;
const MEDIUM_MEMORY: u64 = 128 * 1024 * 1024;
const CACHE_LIMIT: u64 = 128 * 1024 * 1024;

struct Qualification<'a> {
    cache_root: &'a Path,
    output: &'a Path,
    expected: &'a [u8],
    oracle: Option<&'a Path>,
    cases: usize,
}

#[test]
#[ignore = "long resource qualification, run with the L2_QUAL_* driver"]
fn full_relational_batch_matches_the_independent_fixture_and_fresh_recovery() -> TestResult {
    let action = std::env::var("L2_QUAL_ACTION")?;
    let output = PathBuf::from(std::env::var_os("L2_QUAL_OUTPUT").ok_or("missing output")?);
    if action == "fixture" {
        let fixture = build_session_relative_fixture_named("qualification-fixture")?;
        fs::write(output.join("expected.png"), &fixture.plaintext)?;
        println!(
            "fixture bytes={} sha256={}",
            fixture.plaintext.len(),
            l2_workbench::sha256(&fixture.plaintext)
        );
        return Ok(());
    }
    run_qualification(&action, &output)
}

fn run_qualification(action: &str, output: &Path) -> TestResult {
    let limit: u64 = std::env::var("L2_QUAL_LIMIT")?.parse()?;
    let workers: usize = std::env::var("L2_QUAL_WORKERS")?.parse()?;
    let cases: usize = std::env::var("L2_QUAL_CASES")?.parse()?;
    if !matches!(limit, LOW_MEMORY | MEDIUM_MEMORY | 536_870_912)
        || !matches!(workers, 1 | 2 | 4)
        || !matches!(cases, 1 | 4)
        || (cases == 1 && workers != 1)
        || !matches!(action, "no-cache" | "strict" | "optional")
    {
        return Err("unsupported qualification configuration".into());
    }
    let expected_path =
        PathBuf::from(std::env::var_os("L2_QUAL_EXPECTED").ok_or("missing expected artifact")?);
    let expected = fs::read(expected_path)?;
    let oracle = std::env::var_os("L2_QUAL_ORACLE").map(PathBuf::from);
    // A refused reference run can leave only an explicitly requested measurement
    // Artifact checks remain active and the receipt marks the absent comparison
    if action != "no-cache"
        && oracle.is_none()
        && !matches!(std::env::var("L2_QUAL_ALLOW_NO_ORACLE").as_deref(), Ok("1"))
    {
        return Err("cached runs require a fresh no-cache reference".into());
    }
    let cache_root = PathBuf::from(std::env::var_os("L2_QUAL_CACHE").ok_or("missing cache root")?);
    let expect_hits = std::env::var_os("L2_QUAL_EXPECT_HITS").is_some();
    let qualification = Qualification {
        cache_root: &cache_root,
        output,
        expected: &expected,
        oracle: oracle.as_deref(),
        cases,
    };
    let options = qualification_options(action, limit, workers)?;

    // Use the real job monitor so kernel pressure participates in admission
    let result = crate::recovery_job::run(&options, "relational qualification", |job| {
        let memory = job
            .memory_budget()
            .ok_or("job has no shared memory ledger")?;
        let result = exercise_batch(&options, memory, job, &qualification);
        let denial = result
            .as_ref()
            .err()
            .and_then(|error| crate::memory_error::find(error.as_ref()));
        let snapshot = job.snapshot()?;
        let receipt = json!({
            "action": action,
            "profile": format!("{:?}", options.profile),
            "compared_to_reference": qualification.oracle.is_some(),
            "workers": workers,
            "replica_cases": cases,
            "result": if result.is_ok() { "complete" } else if denial.is_some_and(|error| bounded_refusal(limit, error)) { "bounded_refusal" } else { "failed" },
            "error": result.as_ref().err().map(ToString::to_string),
            "memory_error": denial.map(|error| format!("{error:?}")),
            "job": snapshot,
        });
        serde_json::to_writer_pretty(File::create(output.join("result.json"))?, &receipt)?;

        if result.is_ok() && expect_hits {
            assert_eq!(
                snapshot
                    .counters
                    .get(&Counter::CacheHits)
                    .copied()
                    .unwrap_or(0),
                u64::try_from(cases)?,
                "warm run did not reuse each distinct Case"
            );
        }
        // Preserve a real bounded refusal instead of treating it as a cache miss
        if limit <= MEDIUM_MEMORY && denial.is_some_and(|error| bounded_refusal(limit, error)) {
            return Ok(true);
        }
        result.map(|()| true)
    })?;
    assert_eq!(result, crate::outcome::RunOutcome::Completed);
    Ok(())
}

fn qualification_options(action: &str, limit: u64, workers: usize) -> TestResult<RecoveryOptions> {
    let profile = match std::env::var("L2_QUAL_PROFILE").as_deref() {
        Ok("deep") => RecoveryProfile::Deep,
        Ok("normal") | Err(std::env::VarError::NotPresent) => RecoveryProfile::Normal,
        _ => return Err("unsupported qualification profile".into()),
    };
    Ok(RecoveryOptions {
        profile,
        memory_limit: limit,
        cache_max_bytes: CACHE_LIMIT,
        jobs: Some(workers),
        no_cache: action == "no-cache",
        strict_cache: action == "strict",
        quiet: true,
        ..RecoveryOptions::default()
    })
}

fn pending_case(
    memory: &MemoryBudget,
    index: usize,
    expected: &[u8],
    single: bool,
) -> TestResult<(PendingCase, String)> {
    // The single-case control keeps the original source; replicas get distinct sources
    let label = if single {
        "independent-relational-recovery".to_owned()
    } else {
        format!("independent-relational-recovery-{index}")
    };
    let mut fixture = build_session_relative_fixture_named(&label)?;
    assert_eq!(
        fixture.plaintext, expected,
        "fixture bytes changed before recovery"
    );
    fixture.case.add_bytes_node(
        "previous_recovery_output",
        b"preserved output",
        Vec::new(),
        json!({}),
    )?;
    fixture.case.admit_memory_budget(memory)?;
    let source_id = fixture
        .case
        .sources()
        .first()
        .ok_or("missing source")?
        .id
        .clone();
    let flow = Flow {
        id: i64::try_from(index + 1)?,
        source_id: source_id.clone(),
        scope: json!({"replica": index}),
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
    let pending = PendingCase::new(FullSourceItem::Flow(Box::new(FlowAnalysis {
        flow,
        result: BuildResult {
            case: fixture.case,
            complete: true,
        },
        coverage,
    })))?;
    Ok((pending, source_id))
}

fn exercise_batch(
    options: &RecoveryOptions,
    memory: &MemoryBudget,
    job: &Job,
    qualification: &Qualification<'_>,
) -> TestResult {
    let phases = CollectionPhases::start(Some(job))?;
    let cache = if options.no_cache {
        None
    } else {
        Some(Cache::open_at_with_memory_budget(
            qualification.cache_root.join("cache"),
            qualification.cache_root.join("state"),
            options.cache_max_bytes,
            memory.clone(),
        )?)
    };
    let context = RecoveryContext {
        cache: cache.as_ref(),
        job: Some(job),
        memory: Some(memory),
        options,
    };
    let workers = options.jobs.ok_or("missing worker count")?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()?;
    let mut emitted = 0;
    let mut sources = HashSet::new();
    for first in (0..qualification.cases).step_by(workers) {
        let mut batch = Vec::new();
        for index in first..(first + workers).min(qualification.cases) {
            let (pending, source) = pending_case(
                memory,
                index,
                qualification.expected,
                qualification.cases == 1,
            )?;
            assert!(sources.insert(source), "replica source identity was reused");
            batch.push(pending);
        }
        process_case_batch(
            &mut batch,
            &pool,
            qualification.output,
            &context,
            |recovered| {
                record_case_identity(recovered, emitted, qualification)?;
                emitted += 1;
                Ok(())
            },
        )?;
    }
    assert_eq!(
        emitted, qualification.cases,
        "not every fixture replica completed"
    );
    assert_eq!(
        sources.len(),
        qualification.cases,
        "not every source identity was distinct"
    );
    phases.finish(PhaseOutcome::Completed)?;
    Ok(())
}

fn record_case_identity(
    recovered: RecoveredCase,
    emitted: usize,
    qualification: &Qualification<'_>,
) -> TestResult {
    let FullSourceItem::Flow(flow) = recovered.item else {
        return Err("unexpected recovery case kind".into());
    };
    assert!(
        flow.result
            .case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == qualification.expected),
        "recovery did not retain the fixture's exact artifact"
    );
    let index = usize::try_from(flow.flow.id)?
        .checked_sub(1)
        .ok_or("invalid flow id")?;
    assert_eq!(index, emitted, "batch output was not in source order");
    // Hash the complete serialized Case without writing large observer files
    let mut digest = EvidenceDigest::default();
    flow.result.case.write_json(&mut digest)?;
    let identity = json!({
        "evidence_sha256": format!("{:x}", digest.hasher.finalize()),
        "evidence_bytes": digest.bytes,
        "coverage": recovered.recovery.coverage,
        "omissions": recovered.recovery.omissions,
    });
    if let Some(oracle) = qualification.oracle {
        let reference: serde_json::Value =
            serde_json::from_reader(File::open(oracle.join(format!("identity-{index}.json")))?)?;
        assert_eq!(
            identity, reference,
            "evidence or coverage differs from fresh recovery"
        );
    }
    serde_json::to_writer(
        File::create(qualification.output.join(format!("identity-{index}.json")))?,
        &identity,
    )?;
    Ok(())
}

fn bounded_refusal(limit: u64, error: MemoryError) -> bool {
    match error {
        MemoryError::Limit {
            limit: observed,
            used,
            requested,
        } => observed == limit && requested > limit.saturating_sub(used),
        MemoryError::Pressure {
            available,
            requested,
        } => requested > available,
        _ => false,
    }
}

#[derive(Default)]
struct EvidenceDigest {
    hasher: Sha256,
    bytes: u64,
}

impl Write for EvidenceDigest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| io::Error::other("evidence length overflow"))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
