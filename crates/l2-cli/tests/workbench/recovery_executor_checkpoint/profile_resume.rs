use super::*;
use crate::{
    arguments::RecoveryOptions,
    workbench::recovery_executor::{
        JobProgress, RecoveryExecutionOutcome, RecoveryExecutionPolicy, resume::RecoveryResume,
    },
};
use l2_workbench::{
    derivation::{Operation, Recipe},
    job::{
        Counter, Job, MemoryBudget, WorkSnapshot,
        cache::{Cache, SourceIdentity, StageKey},
    },
};
use serde_json::json;

const LIMIT: u64 = 256 * 1024 * 1024;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    native: Case,
    plan: RecoveryPlan,
    options: RecoveryOptions,
    key: StageKey,
    cache: Cache,
}

#[test]
fn normal_and_deep_resume_preserve_committed_work_and_exact_witnesses() -> TestResult {
    for profile in [RecoveryProfile::Normal, RecoveryProfile::Deep] {
        let temporary = tempfile::tempdir()?;
        let fixture = Fixture::new(temporary.path(), profile)?;
        let (expected_case, expected, expected_work) = fixture.reference()?;
        let committed = fixture.save_after_witness()?;
        let (actual_case, actual, actual_work) = fixture.resume()?;
        assert!(expected_case.blobs().iter().any(|blob| blob.bytes == b"AB"));
        assert!(
            expected_case
                .nodes()
                .iter()
                .any(|node| node.kind == "decoding_output")
        );
        assert_eq!(actual_case.to_json()?, expected_case.to_json()?);
        assert_eq!(actual.omissions, expected.omissions);
        assert_eq!(actual.resources, expected.resources);
        assert_eq!(actual.candidate_count, expected.candidate_count);
        assert_eq!(
            without_cache_hits(serde_json::to_value(&actual_work)?)?,
            without_cache_hits(serde_json::to_value(&expected_work)?)?
        );
        assert_eq!(actual_work.counter(Counter::CacheHits), 1);
        assert!(actual_work.counter(Counter::CandidatesExamined) >= committed);
    }
    Ok(())
}

impl Fixture {
    fn new(root: &std::path::Path, profile: RecoveryProfile) -> TestResult<Self> {
        let mut native = Case::new();
        native.add_bytes_node("http_body", b"4142", Vec::new(), json!({}))?;
        let plan = RecoveryPlan {
            recipes: vec![Recipe {
                steps: vec![Operation::HexDecode {}],
                constraints: Vec::new(),
            }],
            ..RecoveryPlan::default()
        };
        let options = RecoveryOptions {
            profile,
            memory_limit: LIMIT,
            cache_max_bytes: 64 * 1024 * 1024,
            strict_cache: true,
            ..RecoveryOptions::default()
        };
        let key = StageKey::new(
            "profile_checkpoint",
            1,
            "profile_checkpoint",
            &json!({}),
            &SourceIdentity::from_sha256("b".repeat(64))?,
            &[],
        )?;
        let cache = Cache::open_at(
            root.join("cache"),
            root.join("state"),
            options.cache_max_bytes,
        )?;
        Ok(Self {
            native,
            plan,
            options,
            key,
            cache,
        })
    }

    fn policy(&self, case: &Case) -> TestResult<RecoveryExecutionPolicy> {
        Ok(super::super::policy::policy_for_profile(
            case,
            self.options.profile,
            LIMIT,
        )?)
    }

    fn reference(&self) -> TestResult<(Case, RecoveryExecutionOutcome, WorkSnapshot)> {
        let mut case = self.native.try_clone()?;
        let memory = MemoryBudget::new(LIMIT);
        case.admit_memory_budget(&memory)?;
        let job = Job::with_memory_budget("profile reference", &memory);
        let scope = job.work_scope(self.key.as_str())?;
        let progress = JobProgress::new(scope.clone());
        let policy = self.policy(&case)?;
        let outcome = super::super::execute_internal(
            &mut case,
            &self.plan,
            &policy,
            false,
            Some(&progress),
            Some(&memory),
            None,
        )?;
        let work = scope.work_snapshot()?;
        Ok((case, outcome, work))
    }

    fn save_after_witness(&self) -> TestResult<u64> {
        let mut case = self.native.try_clone()?;
        let memory = MemoryBudget::new(LIMIT);
        case.admit_memory_budget(&memory)?;
        let job = Job::with_memory_budget("profile interrupted", &memory);
        let scope = job.work_scope(self.key.as_str())?;
        let progress = JobProgress::new(scope.clone());
        let policy = super::super::policy::resolve_policy(self.policy(&case)?)?;
        let mut lease = self.cache.lease(&self.key)?;
        let mut resume = RecoveryResume::new(&mut lease, &self.options, Some(&memory));
        resume.prepare(&mut case)?;
        let mut executor = super::super::new_executor(
            &mut case,
            &self.plan,
            policy,
            false,
            Some(&progress),
            Some(&memory),
        )?;
        let mut cursor = SchedulerCursor::default();
        for _ in 0..1_000 {
            assert!(
                step(&mut executor, &mut cursor)?,
                "no committed witness was reached"
            );
            if executor.case.blobs().iter().any(|blob| blob.bytes == b"AB") {
                let committed = scope.work_snapshot()?.counter(Counter::CandidatesExamined);
                assert!(committed > 0);
                resume.save(&executor, &cursor)?;
                return Ok(committed);
            }
        }
        Err("no committed witness was reached".into())
    }

    fn resume(&self) -> TestResult<(Case, RecoveryExecutionOutcome, WorkSnapshot)> {
        let mut case = self.native.try_clone()?;
        let memory = MemoryBudget::new(LIMIT);
        case.admit_memory_budget(&memory)?;
        let job = Job::with_memory_budget("profile resumed", &memory);
        let scope = job.work_scope(self.key.as_str())?;
        let progress = JobProgress::new(scope.clone());
        let policy = self.policy(&case)?;
        let mut lease = self.cache.lease(&self.key)?;
        let mut resume = RecoveryResume::new(&mut lease, &self.options, Some(&memory));
        let outcome = super::super::execute_internal(
            &mut case,
            &self.plan,
            &policy,
            false,
            Some(&progress),
            Some(&memory),
            Some(&mut resume),
        )?;
        let work = scope.work_snapshot()?;
        Ok((case, outcome, work))
    }
}
