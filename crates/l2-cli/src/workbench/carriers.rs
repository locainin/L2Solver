use super::{input, read_bounded};
use l2_workbench::{
    carrier::{
        self, Ambiguity, ClockSample, CompositionReceipt, CompositionRecipe, MAX_COMPOSITION_PARTS,
        MAX_INPUT_BYTES, MAX_RULES, MAX_SAMPLE_BYTES, MAX_SAMPLE_RANGES, MAX_SAMPLES, MAX_SOURCES,
        MAX_TOTAL_RANGES, Report, Rule, Sample, SourceReader,
    },
    derivation::{self, ConstraintStatus, DerivationReport, Recipe},
    evidence::{ByteMapping, SourceRange},
    hypothesis::{SearchPlan, SearchReport},
    measurement::Clock,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(super) const MAX_PLAN_BYTES: usize = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarrierPlan {
    pub(super) sources: Vec<SourcePlan>,
    pub(super) samples: Vec<SamplePlan>,
    pub(super) rules: Vec<Rule>,
    #[serde(default)]
    pub(super) composition: Option<CompositionRecipe>,
    #[serde(default)]
    pub(super) action: Option<CarrierAction>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourcePlan {
    pub(super) id: String,
    pub(super) length: u64,
    pub(super) path: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SamplePlan {
    pub(super) id: u64,
    pub(super) event_id: Option<String>,
    pub(super) sequence: Option<u64>,
    pub(super) length: usize,
    pub(super) mappings: Vec<MappingPlan>,
    #[serde(default)]
    pub(super) time: Option<ClockInput>,
    #[serde(default)]
    pub(super) ambiguity: Ambiguity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MappingPlan {
    pub(super) offset: usize,
    pub(super) range: SourceRange,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClockInput {
    pub(super) clock: ClockDefinition,
    pub(super) ticks: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClockDefinition {
    pub(super) id: String,
    pub(super) scope: String,
    pub(super) radix: u8,
    pub(super) exponent: u8,
    pub(super) offset_seconds: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CarrierAction {
    Search { plan: SearchPlan },
    Derive { recipe: Recipe },
}

struct OwnedSample {
    id: u64,
    event_id: Option<String>,
    sequence: Option<u64>,
    length: usize,
    mappings: Vec<ByteMapping>,
    time: Option<ClockSample>,
    ambiguity: Ambiguity,
}

impl OwnedSample {
    fn view(&self) -> Sample<'_> {
        Sample {
            id: self.id,
            event_id: self.event_id.as_deref(),
            sequence: self.sequence,
            length: self.length,
            mappings: &self.mappings,
            time: self.time.clone(),
            ambiguity: self.ambiguity,
        }
    }
}

struct ValidatedPlan {
    sources: Vec<SourcePlan>,
    samples: Vec<OwnedSample>,
    rules: Vec<Rule>,
    composition: Option<CompositionRecipe>,
    action: Option<CarrierAction>,
}

struct AnalysisOutcome {
    composition: Option<CompositionReceipt>,
    analysis: Option<Analysis>,
    complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ResultStatus {
    Complete,
    Partial,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
enum Analysis {
    Search(SearchReport),
    Derive {
        recipe: Recipe,
        derivation: DerivationReport,
    },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CarrierResult<'a> {
    status: ResultStatus,
    extraction: &'a Report,
    composition: Option<&'a CompositionReceipt>,
    analysis: Option<&'a Analysis>,
}

pub(super) fn validate_generated_plan_size(plan: &CarrierPlan) -> Result<(), Box<dyn Error>> {
    let mut counter = PlanSizeCounter {
        maximum: MAX_PLAN_BYTES,
        written: 0,
    };
    serde_json::to_writer(&mut counter, plan)?;
    Ok(())
}

struct PlanSizeCounter {
    maximum: usize,
    written: usize,
}

impl Write for PlanSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("generated carrier plan exceeds its existing byte limit")
            })?;
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Extract source-backed carrier values and optionally analyze their composition
pub(super) fn run(plan_path: &Path, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let plan_bytes = read_bounded(input::regular_no_follow(plan_path)?, MAX_PLAN_BYTES)?;
    let plan: CarrierPlan = serde_json::from_slice(&plan_bytes)?;
    let plan = validate_plan(plan)?;
    let mut sources = open_sources(&plan.sources, &plan.samples, plan_path)?;
    let samples: Vec<_> = plan.samples.iter().map(OwnedSample::view).collect();
    let extraction = carrier::extract(&mut sources, &samples, &plan.rules)?;
    let analysis_outcome = analyze(&extraction, &plan)?;
    let result = CarrierResult {
        status: if analysis_outcome.complete {
            ResultStatus::Complete
        } else {
            ResultStatus::Partial
        },
        extraction: &extraction,
        composition: analysis_outcome.composition.as_ref(),
        analysis: analysis_outcome.analysis.as_ref(),
    };
    serde_json::to_writer(output, &result)?;
    Ok(analysis_outcome.complete)
}

fn validate_plan(plan: CarrierPlan) -> Result<ValidatedPlan, Box<dyn Error>> {
    validate_plan_counts(&plan)?;
    let source_lengths = validate_sources(&plan.sources)?;
    let samples = validate_samples(&plan.samples, &source_lengths)?;
    validate_selection(
        plan.composition.as_ref(),
        plan.action.as_ref(),
        &plan.rules,
        &samples,
    )?;
    Ok(ValidatedPlan {
        sources: plan.sources,
        samples,
        rules: plan.rules,
        composition: plan.composition,
        action: plan.action,
    })
}

fn validate_plan_counts(plan: &CarrierPlan) -> Result<(), Box<dyn Error>> {
    if plan.sources.is_empty()
        || plan.sources.len() > MAX_SOURCES
        || plan.samples.is_empty()
        || plan.samples.len() > MAX_SAMPLES
        || plan.rules.is_empty()
        || plan.rules.len() > MAX_RULES
    {
        return Err("carrier plan exceeded a source, sample, or rule count limit".into());
    }
    let mut unique_rules = HashSet::with_capacity(plan.rules.len());
    if plan.rules.iter().any(|rule| !unique_rules.insert(rule)) {
        return Err("carrier rules must be unique".into());
    }
    if let Some(composition) = &plan.composition {
        if composition.parts.len() > MAX_COMPOSITION_PARTS {
            return Err("composition exceeded its part limit".into());
        }
        composition.validate()?;
    }
    Ok(())
}

fn validate_sources(sources: &[SourcePlan]) -> Result<HashMap<String, u64>, Box<dyn Error>> {
    let mut lengths = HashMap::with_capacity(sources.len());
    for source in sources {
        SourceReader::validate_identity(&source.id)?;
        let path_missing = source.path.as_os_str().is_empty();
        let identity_repeated = lengths.insert(source.id.clone(), source.length).is_some();
        if path_missing || identity_repeated {
            return Err("source paths must be present and source identities unique".into());
        }
    }
    Ok(lengths)
}

fn validate_samples(
    samples: &[SamplePlan],
    source_lengths: &HashMap<String, u64>,
) -> Result<Vec<OwnedSample>, Box<dyn Error>> {
    let mut ids = HashSet::with_capacity(samples.len());
    let mut total_bytes = 0_usize;
    let mut total_ranges = 0_usize;
    let mut total_mapped_bytes = 0_usize;
    let mut validated = Vec::with_capacity(samples.len());
    for sample in samples {
        let mapped_bytes = validate_sample(sample, source_lengths, &mut ids)?;
        total_bytes = add_limit(total_bytes, sample.length, MAX_INPUT_BYTES)?;
        total_ranges = add_limit(total_ranges, sample.mappings.len(), MAX_TOTAL_RANGES)?;
        total_mapped_bytes = add_limit(total_mapped_bytes, mapped_bytes, MAX_INPUT_BYTES)?;
        validated.push(own_sample(sample)?);
    }
    Ok(validated)
}

fn validate_sample(
    sample: &SamplePlan,
    source_lengths: &HashMap<String, u64>,
    ids: &mut HashSet<u64>,
) -> Result<usize, Box<dyn Error>> {
    if sample.id == 0 || !ids.insert(sample.id) {
        return Err("sample identities must be unique and nonzero".into());
    }
    if sample.length == 0 || sample.length > MAX_SAMPLE_BYTES {
        return Err("sample length is outside its fixed bound".into());
    }
    if sample.mappings.is_empty() || sample.mappings.len() > MAX_SAMPLE_RANGES {
        return Err("sample mapping count is outside its fixed bound".into());
    }
    validate_event(sample.event_id.as_deref())?;
    validate_mappings(sample, source_lengths)
}

fn validate_event(event_id: Option<&str>) -> Result<(), Box<dyn Error>> {
    if event_id.is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
    }) {
        return Err("event identity is empty, oversized, or contains controls".into());
    }
    Ok(())
}

fn validate_mappings(
    sample: &SamplePlan,
    source_lengths: &HashMap<String, u64>,
) -> Result<usize, Box<dyn Error>> {
    let mut intervals = Vec::with_capacity(sample.mappings.len());
    let mut total_mapped = 0_usize;
    for mapping in &sample.mappings {
        let source_length = source_lengths
            .get(&mapping.range.source)
            .ok_or("sample mapping referenced an undeclared source")?;
        validate_mapping(sample.length, mapping, *source_length)?;
        let length = usize::try_from(mapping.range.length)?;
        total_mapped = add_limit(total_mapped, length, MAX_INPUT_BYTES)?;
        let output_end = mapping
            .offset
            .checked_add(length)
            .ok_or("mapping output range overflowed")?;
        intervals.push((mapping.offset, output_end));
    }
    validate_coverage(sample.length, &mut intervals)?;
    Ok(total_mapped)
}

fn validate_mapping(
    sample_length: usize,
    mapping: &MappingPlan,
    source_length: u64,
) -> Result<(), Box<dyn Error>> {
    let output_length = usize::try_from(mapping.range.length)?;
    let output_end = mapping
        .offset
        .checked_add(output_length)
        .ok_or("mapping output range overflowed")?;
    let source_end = mapping
        .range
        .offset
        .checked_add(mapping.range.length)
        .ok_or("mapping source range overflowed")?;
    if mapping.range.length == 0
        || mapping.range.packet == Some(0)
        || output_end > sample_length
        || source_end > source_length
    {
        return Err("sample mapping referenced an invalid byte range".into());
    }
    Ok(())
}

fn validate_coverage(
    sample_length: usize,
    intervals: &mut [(usize, usize)],
) -> Result<(), Box<dyn Error>> {
    intervals.sort_unstable_by_key(|interval| interval.0);
    let mut covered = 0_usize;
    for (start, end) in intervals.iter().copied() {
        if start > covered {
            return Err("sample mappings left output bytes uncovered".into());
        }
        covered = covered.max(end);
    }
    if covered != sample_length {
        return Err("sample mappings left output bytes uncovered".into());
    }
    Ok(())
}

fn own_sample(sample: &SamplePlan) -> Result<OwnedSample, Box<dyn Error>> {
    let time = sample.time.as_ref().map(own_clock).transpose()?;
    let mappings = sample
        .mappings
        .iter()
        .map(|mapping| ByteMapping {
            offset: mapping.offset,
            range: mapping.range.clone(),
        })
        .collect();
    Ok(OwnedSample {
        id: sample.id,
        event_id: sample.event_id.clone(),
        sequence: sample.sequence,
        length: sample.length,
        mappings,
        time,
        ambiguity: sample.ambiguity,
    })
}

fn own_clock(input: &ClockInput) -> Result<ClockSample, Box<dyn Error>> {
    let clock = Clock::new(
        input.clock.id.clone(),
        input.clock.scope.clone(),
        input.clock.radix,
        input.clock.exponent,
        input.clock.offset_seconds,
    )?;
    Ok(ClockSample {
        clock,
        ticks: input.ticks,
    })
}

fn validate_selection(
    composition: Option<&CompositionRecipe>,
    action: Option<&CarrierAction>,
    rules: &[Rule],
    samples: &[OwnedSample],
) -> Result<(), Box<dyn Error>> {
    if action.is_some() && composition.is_none() {
        return Err("carrier analysis requires a composition recipe".into());
    }
    let Some(composition) = composition else {
        return Ok(());
    };
    let sample_ids = samples
        .iter()
        .map(|sample| sample.id)
        .collect::<HashSet<_>>();
    for part in &composition.parts {
        if !rules.contains(&part.rule)
            || part
                .sample_ids
                .iter()
                .any(|sample_id| !sample_ids.contains(sample_id))
        {
            return Err("composition selected an unrequested rule or sample".into());
        }
    }
    Ok(())
}

fn open_sources(
    sources: &[SourcePlan],
    samples: &[OwnedSample],
    plan_path: &Path,
) -> Result<Vec<SourceReader>, Box<dyn Error>> {
    let base = plan_path.parent().unwrap_or_else(|| Path::new("."));
    let requested = samples
        .iter()
        .flat_map(|sample| sample.mappings.iter())
        .map(|mapping| mapping.range.source.as_str())
        .collect::<HashSet<_>>();
    sources
        .iter()
        .filter(|source| requested.contains(source.id.as_str()))
        .map(|source| open_source(source, base))
        .collect()
}

fn open_source(source: &SourcePlan, base: &Path) -> Result<SourceReader, Box<dyn Error>> {
    let path = if source.path.is_absolute() {
        source.path.clone()
    } else {
        base.join(&source.path)
    };
    Ok(SourceReader::verify(
        source.id.clone(),
        source.length,
        input::regular_no_follow(&path)?,
    )?)
}

fn analyze(extraction: &Report, plan: &ValidatedPlan) -> Result<AnalysisOutcome, Box<dyn Error>> {
    let Some(recipe) = &plan.composition else {
        return Ok(AnalysisOutcome {
            composition: None,
            analysis: None,
            complete: extraction.complete,
        });
    };
    let composition = carrier::compose(extraction, recipe)?;
    if !composition.receipt().complete {
        return Ok(AnalysisOutcome {
            composition: Some(composition.receipt().clone()),
            analysis: None,
            complete: false,
        });
    }
    analyze_action(&composition, plan.action.as_ref())
}

fn analyze_action(
    composition: &carrier::CompositionOutcome,
    action: Option<&CarrierAction>,
) -> Result<AnalysisOutcome, Box<dyn Error>> {
    match action {
        None => Ok(AnalysisOutcome {
            composition: Some(composition.receipt().clone()),
            analysis: None,
            complete: true,
        }),
        Some(CarrierAction::Search { plan }) => {
            let result = carrier::search_composed(composition, plan)?;
            Ok(AnalysisOutcome {
                composition: Some(result.composition),
                complete: result.search.search_exhaustive_within_plan,
                analysis: Some(Analysis::Search(result.search)),
            })
        }
        Some(CarrierAction::Derive { recipe }) => {
            let result = carrier::derive_composed(composition, recipe)?;
            Ok(AnalysisOutcome {
                composition: Some(result.composition),
                complete: derivation_complete(&result.derivation),
                analysis: Some(Analysis::Derive {
                    recipe: result.recipe,
                    derivation: result.derivation,
                }),
            })
        }
    }
}

fn derivation_complete(report: &DerivationReport) -> bool {
    report.status == derivation::DerivationStatus::Completed
        && report
            .constraints
            .iter()
            .all(|constraint| constraint.status == ConstraintStatus::Satisfied)
}

fn add_limit(current: usize, amount: usize, maximum: usize) -> Result<usize, Box<dyn Error>> {
    let total = current
        .checked_add(amount)
        .filter(|total| *total <= maximum)
        .ok_or("carrier plan exceeded a fixed byte or range limit")?;
    Ok(total)
}
