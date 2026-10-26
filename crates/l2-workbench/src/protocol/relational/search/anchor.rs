use super::{
    super::model::{
        RelationalByteRangeLocator, RelationalCoordinateBasis, RelationalLengthField,
        RelationalRecordSample, RelationalTransformError, RelationalTransformLimits,
    },
    input::{SelectorIndex, SessionGroup},
    locator::LocatorCandidate,
};
use crate::{
    integer::decode_unsigned,
    job::{Counter, Job, Phase},
    protocol::{
        ByteRange, MessageRole, MessageSample,
        observation::{
            ObservationInput, ObservationLimits, ObservationPlan, ObservationProvenance,
            RegionObservation, SampleRange, observe,
        },
    },
};
use std::collections::BTreeMap;

pub(super) struct AnchoredPayloadSearch {
    pub(super) candidates: Vec<LocatorCandidate>,
    pub(super) complete: bool,
    pub(super) work_limited: bool,
    pub(super) locator_limited: bool,
    pub(super) work_bytes: usize,
}

struct SeedView<'a> {
    sample_index: usize,
    sample: u64,
    bytes: &'a [u8],
    context: crate::protocol::MessageContext,
    seed_end: usize,
    source_range: ByteRange,
    identity: String,
    omitted_tail_bytes: bool,
}

#[derive(Clone, Copy)]
struct SeedViewRequest {
    seed_length: usize,
    declared_length: RelationalLengthField,
    observation_span: usize,
    requested_span: usize,
}

#[derive(Clone)]
struct RepeatedMarker {
    range: ByteRange,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct CachedAnchorMarkers {
    markers: Vec<RepeatedMarker>,
    complete: bool,
    work_limited: bool,
    locator_limited: bool,
}

type AnchorSignature = (crate::protocol::Direction, Vec<(usize, usize)>);

struct AnchorScanner<'input, 'bytes> {
    samples: &'input [RelationalRecordSample<'bytes>],
    groups: &'input [SessionGroup],
    indexes: &'input [SelectorIndex],
    limits: RelationalTransformLimits,
    maximum_candidates: usize,
    marker_width: usize,
    observation_span: usize,
    requested_span: usize,
    job: Option<&'input Job>,
    result: AnchoredPayloadSearch,
    observations: BTreeMap<AnchorSignature, CachedAnchorMarkers>,
    observation_cache_bytes: usize,
    last_seed_progress_update: usize,
    last_locator_progress_update: usize,
    locator_attempts: usize,
}

/// Find bounded payload locators relative to repeated regions after fixed declared seeds
pub(super) fn anchored_payload_locators(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    seed_locators: &[LocatorCandidate],
    limits: RelationalTransformLimits,
    maximum_candidates: usize,
    job: Option<&Job>,
) -> Result<AnchoredPayloadSearch, RelationalTransformError> {
    let maximum_width = ObservationLimits::default().max_region_width;
    let marker_width = limits.max_marker_bytes.min(maximum_width);
    let requested_span = relative_observation_span(limits, marker_width);
    let maximum_observation_span = ObservationLimits::default().max_message_bytes;
    let observation_span = requested_span.min(maximum_observation_span);
    let mut result = AnchoredPayloadSearch {
        candidates: Vec::new(),
        complete: limits.max_marker_bytes <= maximum_width,
        work_limited: false,
        locator_limited: limits.max_marker_bytes > maximum_width,
        work_bytes: 0,
    };
    result
        .candidates
        .try_reserve(maximum_candidates.min(seed_locators.len()))
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    if maximum_candidates == 0 && !seed_locators.is_empty() {
        result.complete = false;
        result.locator_limited = true;
        return Ok(result);
    }
    if marker_width == 0 || groups.is_empty() || observation_span == 0 {
        return Ok(result);
    }

    let mut scanner = AnchorScanner {
        samples,
        groups,
        indexes,
        limits,
        maximum_candidates,
        marker_width,
        observation_span,
        requested_span,
        job,
        result,
        observations: BTreeMap::new(),
        observation_cache_bytes: 0,
        last_seed_progress_update: 0,
        last_locator_progress_update: 0,
        locator_attempts: 0,
    };
    scanner.run(seed_locators)?;
    Ok(scanner.result)
}

impl AnchorScanner<'_, '_> {
    fn run(&mut self, seed_locators: &[LocatorCandidate]) -> Result<(), RelationalTransformError> {
        for (seed_index, seed_locator) in seed_locators.iter().enumerate() {
            self.report_seed_progress(seed_index)?;
            let Some(views) = seed_views(
                self.samples,
                self.groups,
                self.indexes,
                seed_locator,
                self.observation_span,
                self.requested_span,
            )?
            else {
                continue;
            };
            if views.iter().any(|view| view.omitted_tail_bytes) {
                self.result.complete = false;
                self.result.locator_limited = true;
            }
            let signature = anchor_signature(seed_locator.selector.direction, &views);
            let Some(cached) = self.cached_markers(&views, signature)? else {
                break;
            };
            if !cached.complete {
                self.result.complete = false;
            }
            self.result.work_limited |= cached.work_limited;
            self.result.locator_limited |= cached.locator_limited;
            let last_observed_offset = views
                .iter()
                .map(|view| view.bytes.len())
                .min()
                .unwrap_or_default()
                .saturating_sub(1)
                .min(self.limits.max_locator_offset);
            if !self.scan_markers(
                seed_index,
                seed_locator,
                &views,
                cached.markers,
                last_observed_offset,
            )? {
                break;
            }
        }
        Ok(())
    }

    fn report_seed_progress(&mut self, seed_index: usize) -> Result<(), RelationalTransformError> {
        let Some(job) = self.job else {
            return Ok(());
        };
        job.check_cancelled()
            .map_err(RelationalTransformError::from)?;
        if seed_index == 0 || seed_index.saturating_sub(self.last_seed_progress_update) >= 128 {
            match job.set_current(
                Phase::TransformDiscovery,
                format!("observing anchored seed boundaries: {seed_index}"),
            ) {
                Ok(()) | Err(crate::job::JobError::PhaseNotInProgress(_)) => {
                    self.last_seed_progress_update = seed_index;
                }
                Err(error) => return Err(RelationalTransformError::from(error)),
            }
        }
        Ok(())
    }

    fn cached_markers(
        &mut self,
        views: &[SeedView<'_>],
        signature: AnchorSignature,
    ) -> Result<Option<CachedAnchorMarkers>, RelationalTransformError> {
        if let Some(cached) = self.observations.get(&signature) {
            return Ok(Some(cached.clone()));
        }
        let Some(remaining_work) = self
            .limits
            .max_work_bytes
            .checked_sub(self.result.work_bytes)
        else {
            self.result.complete = false;
            self.result.work_limited = true;
            return Ok(None);
        };
        let input_bytes = views
            .iter()
            .try_fold(0_usize, |total, view| total.checked_add(view.bytes.len()));
        let Some(input_bytes) = input_bytes else {
            self.result.complete = false;
            self.result.work_limited = true;
            return Ok(None);
        };
        if input_bytes >= remaining_work {
            self.result.complete = false;
            self.result.work_limited = true;
            return Ok(None);
        }
        if let Some(job) = self.job {
            job.check_cancelled()
                .map_err(RelationalTransformError::from)?;
        }
        let (observation, requested_ranges_complete) = observe_seed_tails(
            views,
            self.limits,
            self.marker_width,
            remaining_work - input_bytes,
            self.job,
        )?;
        let pass_work = observation
            .coverage
            .input_bytes_seen
            .checked_add(observation.coverage.work_units)
            .ok_or(RelationalTransformError::InvalidPlan(
                "anchor observation work accounting overflowed",
            ))?;
        self.result.work_bytes = self.result.work_bytes.checked_add(pass_work).ok_or(
            RelationalTransformError::InvalidPlan("anchor observation work accounting overflowed"),
        )?;
        if self.result.work_bytes > self.limits.max_work_bytes {
            self.result.complete = false;
            self.result.work_limited = true;
            return Ok(None);
        }
        let observation_work_limited = observation.coverage.omitted_work_units > 0
            || observation.coverage.omitted_input_bytes > 0;
        let observation_locators_limited =
            !requested_ranges_complete || !region_coverage_complete(observation.coverage);
        self.result.work_limited |= observation_work_limited;
        self.result.locator_limited |= observation_locators_limited;
        self.record_observation_work(pass_work)?;

        let cached = CachedAnchorMarkers {
            markers: repeated_markers(&observation, views),
            complete: !observation_work_limited
                && !observation_locators_limited
                && views.iter().all(|view| !view.omitted_tail_bytes),
            work_limited: observation_work_limited,
            locator_limited: observation_locators_limited
                || views.iter().any(|view| view.omitted_tail_bytes),
        };
        self.retain_cached_markers(signature, &cached);
        Ok(Some(cached))
    }

    fn record_observation_work(&self, pass_work: usize) -> Result<(), RelationalTransformError> {
        let Some(job) = self.job else {
            return Ok(());
        };
        job.record_work(
            Phase::TransformDiscovery,
            Counter::Bytes,
            u64::try_from(pass_work).map_err(|_| {
                RelationalTransformError::InvalidPlan("anchor observation work counter overflowed")
            })?,
        )
        .map_err(RelationalTransformError::from)
    }

    fn retain_cached_markers(&mut self, signature: AnchorSignature, cached: &CachedAnchorMarkers) {
        let cache_cost = anchor_cache_cost(&signature, cached);
        if cache_cost
            <= ObservationLimits::default()
                .max_report_bytes
                .saturating_sub(self.observation_cache_bytes)
        {
            self.observation_cache_bytes = self.observation_cache_bytes.saturating_add(cache_cost);
            self.observations.insert(signature, cached.clone());
        }
    }

    fn scan_markers(
        &mut self,
        seed_index: usize,
        seed_locator: &LocatorCandidate,
        views: &[SeedView<'_>],
        markers: Vec<RepeatedMarker>,
        last_observed_offset: usize,
    ) -> Result<bool, RelationalTransformError> {
        let mut last_marker_progress = 0_usize;
        for (marker_index, marker) in markers.into_iter().enumerate() {
            let markers_examined = marker_index.saturating_add(1);
            self.report_marker_progress(markers_examined, &mut last_marker_progress)?;
            let Some(marker_end) = marker.range.start.checked_add(marker.bytes.len()) else {
                self.result.complete = false;
                continue;
            };
            if marker_end > last_observed_offset {
                continue;
            }
            if !self.scan_marker_values(
                seed_index,
                seed_locator,
                views,
                &marker,
                marker_end,
                last_observed_offset,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn report_marker_progress(
        &self,
        markers_examined: usize,
        last_marker_progress: &mut usize,
    ) -> Result<(), RelationalTransformError> {
        let Some(job) = self.job else {
            return Ok(());
        };
        job.check_cancelled()
            .map_err(RelationalTransformError::from)?;
        if markers_examined == 1 || markers_examined.saturating_sub(*last_marker_progress) >= 128 {
            match job.set_current(
                Phase::TransformDiscovery,
                format!("checking anchored marker ranges: {markers_examined}"),
            ) {
                Ok(()) | Err(crate::job::JobError::PhaseNotInProgress(_)) => {
                    *last_marker_progress = markers_examined;
                }
                Err(error) => return Err(RelationalTransformError::from(error)),
            }
        }
        Ok(())
    }

    fn scan_marker_values(
        &mut self,
        seed_index: usize,
        seed_locator: &LocatorCandidate,
        views: &[SeedView<'_>],
        marker: &RepeatedMarker,
        marker_end: usize,
        last_value_offset: usize,
    ) -> Result<bool, RelationalTransformError> {
        for value_offset in marker_end..=last_value_offset {
            if self.locator_attempts == self.maximum_candidates {
                self.result.complete = false;
                self.result.locator_limited = true;
                return Ok(false);
            }
            self.locator_attempts = self.locator_attempts.checked_add(1).ok_or(
                RelationalTransformError::InvalidPlan("anchored locator attempt count overflowed"),
            )?;
            self.report_locator_progress()?;
            if views.iter().all(|view| {
                view.seed_end
                    .checked_add(value_offset)
                    .is_some_and(|absolute_offset| {
                        absolute_offset <= self.limits.max_locator_offset
                    })
            }) {
                // The seed selector already identifies this sample, so the absolute
                // payload domain can express the same byte start without an anchor
                continue;
            }
            let locator = RelationalByteRangeLocator {
                coordinate_basis: RelationalCoordinateBasis::SeedRangeEndV1,
                direction: seed_locator.selector.direction,
                marker_offset: marker.range.start,
                marker: marker.bytes.clone(),
                value_offset,
                value_length: None,
                declared_length: None,
            };
            self.result
                .candidates
                .push(LocatorCandidate::anchored_payload(
                    seed_index,
                    seed_locator.selector.clone(),
                    locator,
                ));
        }
        Ok(true)
    }

    fn report_locator_progress(&mut self) -> Result<(), RelationalTransformError> {
        let Some(job) = self.job else {
            return Ok(());
        };
        job.check_cancelled()
            .map_err(RelationalTransformError::from)?;
        if self.locator_attempts == 1
            || self
                .locator_attempts
                .saturating_sub(self.last_locator_progress_update)
                >= 128
        {
            match job.set_current(
                Phase::TransformDiscovery,
                format!(
                    "checking anchored payload offsets: {}",
                    self.locator_attempts
                ),
            ) {
                Ok(()) | Err(crate::job::JobError::PhaseNotInProgress(_)) => {
                    self.last_locator_progress_update = self.locator_attempts;
                }
                Err(error) => return Err(RelationalTransformError::from(error)),
            }
        }
        Ok(())
    }
}

fn anchor_cache_cost(
    signature: &(crate::protocol::Direction, Vec<(usize, usize)>),
    cached: &CachedAnchorMarkers,
) -> usize {
    std::mem::size_of_val(signature)
        .saturating_add(
            signature
                .1
                .len()
                .saturating_mul(std::mem::size_of::<(usize, usize)>()),
        )
        .saturating_add(std::mem::size_of_val(cached))
        .saturating_add(cached.markers.iter().fold(0_usize, |total, marker| {
            total
                .saturating_add(std::mem::size_of_val(marker))
                .saturating_add(marker.bytes.len())
        }))
}

fn anchor_signature(
    direction: crate::protocol::Direction,
    views: &[SeedView<'_>],
) -> (crate::protocol::Direction, Vec<(usize, usize)>) {
    (
        direction,
        views
            .iter()
            .map(|view| (view.sample_index, view.seed_end))
            .collect(),
    )
}

fn relative_observation_span(limits: RelationalTransformLimits, marker_width: usize) -> usize {
    let marker_end = limits.max_marker_offset.saturating_add(marker_width);
    let payload_end = limits.max_locator_offset.saturating_add(1);
    marker_end.max(payload_end)
}

const fn region_coverage_complete(
    coverage: crate::protocol::observation::ObservationCoverage,
) -> bool {
    coverage.omitted_samples == 0
        && coverage.omitted_contexts == 0
        && coverage.omitted_context_bytes == 0
        && coverage.omitted_origins == 0
        && coverage.omitted_origin_checks == 0
        && coverage.omitted_region_ranges == 0
        && coverage.omitted_region_values == 0
        && coverage.omitted_region_occurrences == 0
        && coverage.unscoped_region_occurrences == 0
        && coverage.untestable_region_occurrences == 0
}

fn seed_views<'a>(
    samples: &[RelationalRecordSample<'a>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    seed_locator: &LocatorCandidate,
    observation_span: usize,
    requested_span: usize,
) -> Result<Option<Vec<SeedView<'a>>>, RelationalTransformError> {
    let Some(seed_length) = seed_locator
        .locator
        .value_length
        .filter(|length| *length > 0)
    else {
        return Ok(None);
    };
    let Some(declared_length) = seed_locator.locator.declared_length else {
        return Ok(None);
    };
    if seed_locator.locator.coordinate_basis != RelationalCoordinateBasis::MessageStartV1 {
        return Ok(None);
    }
    let mut views = Vec::new();
    views
        .try_reserve_exact(groups.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let request = SeedViewRequest {
        seed_length,
        declared_length,
        observation_span,
        requested_span,
    };
    for group_index in 0..groups.len() {
        let Some(view) = seed_view_for_group(samples, indexes, group_index, seed_locator, request)
        else {
            return Ok(None);
        };
        views.push(view);
    }
    Ok(Some(views))
}

fn seed_view_for_group<'a>(
    samples: &[RelationalRecordSample<'a>],
    indexes: &[SelectorIndex],
    group_index: usize,
    seed_locator: &LocatorCandidate,
    request: SeedViewRequest,
) -> Option<SeedView<'a>> {
    let selected = indexes
        .get(group_index)
        .and_then(|index| index.get(&seed_locator.selector))
        .filter(|selected| selected.len() == 1)?;
    let sample_index = selected.first().copied()?;
    let sample = samples.get(sample_index)?;
    if sample.context.direction != seed_locator.locator.direction {
        return None;
    }
    let seed_end = seed_locator
        .locator
        .value_offset
        .checked_add(request.seed_length)?;
    let seed_bytes = sample
        .bytes
        .get(seed_locator.locator.value_offset..seed_end)?;
    let field = request.declared_length;
    let field_end = field.offset.checked_add(field.width.byte_length())?;
    let field_bytes = sample.bytes.get(field.offset..field_end)?;
    if decode_unsigned(
        field_bytes,
        field.byte_order == crate::protocol::ByteOrder::LittleEndian,
    ) != u64::try_from(seed_bytes.len()).ok()
    {
        return None;
    }
    let tail_start = seed_end;
    let available_tail_length = sample.bytes.len().saturating_sub(tail_start);
    let requested_tail_end = tail_start.saturating_add(request.observation_span);
    let tail_end = sample.bytes.len().min(requested_tail_end);
    let tail = sample.bytes.get(tail_start..tail_end)?;
    if tail.is_empty() {
        return None;
    }
    Some(SeedView {
        sample_index,
        sample: sample.sample,
        bytes: tail,
        context: sample.context.clone(),
        seed_end,
        source_range: ByteRange {
            start: tail_start,
            end: tail_end,
        },
        identity: format!("relational-message-{}", sample.sample),
        omitted_tail_bytes: request.requested_span > request.observation_span
            && available_tail_length > request.observation_span,
    })
}

fn observe_seed_tails(
    views: &[SeedView<'_>],
    limits: RelationalTransformLimits,
    marker_width: usize,
    observation_work_limit: usize,
    job: Option<&Job>,
) -> Result<(crate::protocol::observation::ObservationReport, bool), RelationalTransformError> {
    let defaults = ObservationLimits::default();
    let span = views
        .iter()
        .map(|view| view.bytes.len())
        .max()
        .unwrap_or_default();
    let mut observation_limits = defaults;
    observation_limits.max_samples = defaults.max_samples.min(views.len());
    observation_limits.max_message_bytes = defaults.max_message_bytes.min(span);
    observation_limits.max_total_bytes = defaults
        .max_total_bytes
        .min(span.saturating_mul(views.len()));
    observation_limits.max_prefix_offset = 0;
    observation_limits.max_hypotheses = 14;
    observation_limits.max_work_units = defaults.max_work_units.min(observation_work_limit);
    observation_limits.max_region_width = defaults.max_region_width.min(marker_width);
    let inputs = observation_inputs(views)?;
    let (region_ranges, ranges_complete) = seed_tail_ranges(views, limits, marker_width, job)?;
    let report = observe(
        &inputs,
        &ObservationPlan {
            region_ranges,
            limits: observation_limits,
        },
    )
    .map_err(|_| RelationalTransformError::InvalidPlan("seed-relative byte observation failed"))?;
    Ok((report, ranges_complete))
}

fn observation_inputs<'view, 'data: 'view>(
    views: &'view [SeedView<'data>],
) -> Result<Vec<ObservationInput<'view>>, RelationalTransformError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(views.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for view in views {
        inputs.push(view_sample(view, &view.identity));
    }
    Ok(inputs)
}

fn seed_tail_ranges(
    views: &[SeedView<'_>],
    limits: RelationalTransformLimits,
    marker_width: usize,
    job: Option<&Job>,
) -> Result<(Vec<SampleRange>, bool), RelationalTransformError> {
    let maximum_region_ranges = ObservationLimits::default().max_region_ranges;
    let mut region_ranges = Vec::new();
    region_ranges
        .try_reserve(maximum_region_ranges.min(views.len().saturating_mul(32)))
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut ranges_complete = true;
    let common_tail_length = views
        .iter()
        .map(|view| view.bytes.len())
        .min()
        .unwrap_or_default();
    if common_tail_length == 0 {
        return Ok((region_ranges, ranges_complete));
    }
    let last_marker_offset = limits
        .max_marker_offset
        .min(common_tail_length.saturating_sub(1));
    'regions: for marker_offset in 0..=last_marker_offset {
        if let Some(job) = job {
            job.check_cancelled()
                .map_err(RelationalTransformError::from)?;
            if marker_offset == 0 || marker_offset % 128 == 0 {
                match job.set_current(
                    Phase::TransformDiscovery,
                    format!("observing anchored marker ranges: {marker_offset}"),
                ) {
                    Ok(()) | Err(crate::job::JobError::PhaseNotInProgress(_)) => {}
                    Err(error) => return Err(RelationalTransformError::from(error)),
                }
            }
        }
        let available_width = common_tail_length.saturating_sub(marker_offset);
        for width in 1..=marker_width.min(available_width) {
            let Some(end) = marker_offset.checked_add(width) else {
                ranges_complete = false;
                break 'regions;
            };
            let additional_ranges = views.len();
            if region_ranges.len().saturating_add(additional_ranges) > maximum_region_ranges {
                ranges_complete = false;
                break 'regions;
            }
            region_ranges
                .try_reserve_exact(additional_ranges)
                .map_err(|_| RelationalTransformError::AllocationFailed)?;
            region_ranges.extend(views.iter().map(|view| SampleRange {
                sample: view.sample,
                range: ByteRange {
                    start: marker_offset,
                    end,
                },
            }));
        }
    }
    Ok((region_ranges, ranges_complete))
}

fn view_sample<'view, 'data: 'view>(
    view: &'view SeedView<'data>,
    identity: &'view str,
) -> ObservationInput<'view> {
    ObservationInput {
        message: MessageSample {
            sample: view.sample,
            role: MessageRole::Unclassified,
            bytes: view.bytes,
            context: Some(view.context.clone()),
        },
        provenance: ObservationProvenance::Derived {
            identity,
            range: view.source_range,
        },
    }
}

fn repeated_markers(
    report: &crate::protocol::observation::ObservationReport,
    views: &[SeedView<'_>],
) -> Vec<RepeatedMarker> {
    let expected_samples: Vec<u64> = views.iter().map(|view| view.sample).collect();
    let mut ranges: Vec<ByteRange> = report.regions.iter().map(|region| region.range).collect();
    ranges.sort_unstable();
    ranges.dedup();
    ranges
        .into_iter()
        .filter_map(|range| {
            repeated_region_value(
                &report.regions,
                &report.byte_observations,
                range,
                &expected_samples,
            )
            .map(|bytes| RepeatedMarker { range, bytes })
        })
        .collect()
}

fn repeated_region_value(
    regions: &[RegionObservation],
    observations: &[crate::protocol::observation::ByteObservation],
    range: ByteRange,
    expected_samples: &[u64],
) -> Option<Vec<u8>> {
    let mut sample_values = BTreeMap::new();
    for region in regions.iter().filter(|region| region.range == range) {
        for value in &region.values {
            for observation_index in &value.observation_indices {
                let observation = observations.get(*observation_index)?;
                if observation.range != range || observation.bytes != value.bytes {
                    return None;
                }
                if expected_samples.contains(&observation.sample) {
                    sample_values.insert(observation.sample, value.bytes.as_slice());
                }
            }
        }
    }
    let first = *sample_values.values().next()?;
    (sample_values.len() == expected_samples.len()
        && expected_samples.iter().all(|sample| {
            sample_values
                .get(sample)
                .is_some_and(|value| **value == *first)
        }))
    .then(|| first.to_vec())
}
