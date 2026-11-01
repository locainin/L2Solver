use super::super::SCHEDULE_CONSTRUCTIONS;
use super::{
    LocatorPairSchedule, PairStage, RelationalCandidateEvaluation, RelationalCursorError,
    RelationalRecordSample, RelationalRestoreBudget, RelationalSearchCursor,
    RelationalSearchSession, RelationalSearchStep, RelationalTransformEvaluationOptions,
    RelationalTransformPlan, SavedSchedule,
};
use crate::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{Direction, MessageContext, RelationalCounterReset, RelationalParserScope},
};
use std::{cmp::Reverse, convert::Infallible, error::Error};

const fn records() -> [[u8; 4]; 8] {
    [
        [0x31, 1, 2, 3],
        [0x82, 4, 5, 6],
        [0x31, 3, 4, 5],
        [0x82, 6, 7, 8],
        [0x31, 5, 6, 7],
        [0x82, 8, 9, 10],
        [0x31, 7, 8, 9],
        [0x82, 10, 11, 12],
    ]
}

fn samples(records: &[[u8; 4]]) -> Result<Vec<RelationalRecordSample<'_>>, Box<dyn Error>> {
    let samples: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let session = u64::try_from(index / 2 + 1)?;
            Ok(RelationalRecordSample {
                sample: u64::try_from(index + 1)?,
                context: MessageContext {
                    source: "source".to_owned(),
                    scope: "scope".to_owned(),
                    session,
                    direction: if index % 2 == 0 {
                        Direction::FirstToSecond
                    } else {
                        Direction::SecondToFirst
                    },
                },
                session_order: session,
                bytes,
            })
        })
        .collect::<Result<_, std::num::TryFromIntError>>()?;
    Ok(samples)
}

fn plan() -> RelationalTransformPlan {
    let mut plan = RelationalTransformPlan {
        parser_scope: RelationalParserScope::AcrossSessions,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![SeedCounterOrder::SeedThenCounter],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::Continuous],
        ..RelationalTransformPlan::default()
    };
    plan.limits.max_marker_bytes = 1;
    plan.limits.max_marker_offset = 0;
    plan.limits.max_seed_bytes = 2;
    plan.limits.max_locator_offset = 2;
    plan.limits.max_locator_candidates = 64;
    plan.limits.max_candidates = 1_000;
    plan
}

const fn evaluate() -> RelationalCandidateEvaluation<()> {
    RelationalCandidateEvaluation {
        priority: 0,
        work_bytes: 0,
        assessment: (),
    }
}

#[test]
fn absolute_stage_slices_reuse_one_scheduler_preparation() -> Result<(), Box<dyn Error>> {
    let records = records();
    let samples = samples(&records)?;
    let plan = plan();
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    SCHEDULE_CONSTRUCTIONS.with(|count| count.set(0));
    let mut cursor = None;
    let mut preparations = None;
    let mut absolute_pauses = 0;
    for _ in 0..2_000 {
        let RelationalSearchStep::Paused(saved) =
            session.step(cursor, 1, |_, _, _, _| Ok::<_, Infallible>(evaluate()))?
        else {
            break;
        };
        if matches!(saved.position.stage, super::PairStage::Absolute { .. }) {
            let current = SCHEDULE_CONSTRUCTIONS.with(std::cell::Cell::get);
            let first = *preparations.get_or_insert(current);
            assert_eq!(
                current, first,
                "a live slice rebuilt its absolute scheduler"
            );
            absolute_pauses += 1;
            if absolute_pauses == 5 {
                break;
            }
        }
        cursor = Some(saved);
    }
    assert_eq!(
        absolute_pauses, 5,
        "fixture did not exercise several absolute slices"
    );
    Ok(())
}

fn absolute_boundary(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
) -> Result<RelationalSearchCursor<()>, Box<dyn Error>> {
    let mut session = RelationalSearchSession::new(
        samples,
        plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let mut cursor = None;
    for _ in 0..2_000 {
        let RelationalSearchStep::Paused(saved) =
            session.step(cursor, 1, |_, _, _, _| Ok::<_, Infallible>(evaluate()))?
        else {
            return Err("fixture completed before absolute scheduling".into());
        };
        if matches!(saved.position.stage, PairStage::Absolute { .. }) {
            return Ok(saved);
        }
        cursor = Some(saved);
    }
    Err("fixture did not reach absolute scheduling".into())
}

fn snapshot(schedule: &LocatorPairSchedule) -> SavedSchedule {
    SavedSchedule {
        initial_pair_cursor: schedule.initial_pair_cursor,
        stream_cursor: schedule.stream_cursor,
        pairs_returned: schedule.pairs_returned,
        header: schedule.header_aligned.pending.clone().into_vec(),
        aligned: schedule.aligned.pending.clone().into_vec(),
        fallback: schedule.fallback.pending.clone().into_vec(),
    }
}

#[test]
fn scheduler_prefix_rejects_an_advanced_but_in_range_heap_row() -> Result<(), Box<dyn Error>> {
    let records = records();
    let samples = samples(&records)?;
    let plan = plan();
    let cursor = absolute_boundary(&samples, &plan)?;
    let schedule = cursor.schedule.as_ref().ok_or("missing schedule")?;
    let mut forged = snapshot(schedule);
    let mut advanced = false;
    for (entries, stream) in [
        (&mut forged.header, &schedule.header_aligned),
        (&mut forged.aligned, &schedule.aligned),
        (&mut forged.fallback, &schedule.fallback),
    ] {
        for Reverse(entry) in entries {
            let row = *stream.rows.get(entry.row_index).ok_or("missing row")?;
            let Some(next) =
                schedule
                    .domain
                    .next_payload_order(row, stream.kind, entry.payload_order_index + 1)
            else {
                continue;
            };
            let payload = schedule
                .domain
                .payloads
                .get(next)
                .ok_or("missing payload")?;
            entry.payload_order_index = next;
            entry.payload_index = payload.candidate_index;
            entry.pair_rank = entry.seed_index + entry.payload_index;
            advanced = true;
            break;
        }
        if advanced {
            break;
        }
    }
    assert!(advanced, "fixture has no row with a later valid payload");
    let mut work = RelationalRestoreBudget::new(usize::MAX, 100_000);
    let result = forged.restore::<Infallible>(
        &cursor.prepared.seed_locators,
        &cursor.prepared.payload_locators,
        cursor.position.current.as_ref(),
        None,
        &mut work,
    );
    assert!(matches!(
        result,
        Err(RelationalCursorError::InvalidCheckpoint)
    ));
    Ok(())
}

#[test]
fn scheduler_prefix_accepts_a_genuinely_exhausted_row() -> Result<(), Box<dyn Error>> {
    let records = records();
    let samples = samples(&records)?;
    let plan = plan();
    let cursor = absolute_boundary(&samples, &plan)?;
    let mut schedule = LocatorPairSchedule::new(
        &cursor.prepared.seed_locators,
        &cursor.prepared.payload_locators,
    )?;
    let mut exhausted_row = false;
    while schedule.next().is_some() {
        let streams = [
            &schedule.header_aligned,
            &schedule.aligned,
            &schedule.fallback,
        ];
        if streams
            .iter()
            .any(|stream| stream.pending.len() < stream.rows.len())
            && streams.iter().any(|stream| !stream.pending.is_empty())
        {
            exhausted_row = true;
            break;
        }
    }
    assert!(
        exhausted_row,
        "fixture did not exhaust a row before the whole schedule"
    );
    let saved = snapshot(&schedule);
    let steps = saved.pairs_returned;
    let mut work = RelationalRestoreBudget::new(usize::MAX, 100_000);
    let _restored = saved.restore::<Infallible>(
        &cursor.prepared.seed_locators,
        &cursor.prepared.payload_locators,
        None,
        None,
        &mut work,
    )?;
    assert_eq!(work.schedule_steps(), steps);
    Ok(())
}
