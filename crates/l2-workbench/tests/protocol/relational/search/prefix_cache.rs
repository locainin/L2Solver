use super::{PrefixProbeCache, PrefixSelectionIdentity, PrefixSessionSelection};
use crate::derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder};
use crate::protocol::relational::model::{RelationalSha256CounterXor, RelationalTransformError};
use crate::protocol::relational::search::probe::PrefixProbeScore;

#[test]
fn scoring_falls_back_when_selection_or_score_storage_is_full()
-> Result<(), RelationalTransformError> {
    for keep_selection in [false, true] {
        let mut cache = PrefixProbeCache::new(usize::MAX);
        let selection = selection(0, 3);
        if keep_selection {
            assert!(cache.intern_selection(selection.clone()).is_some());
            cache.maximum_bytes = cache.retained_bytes;
        } else {
            cache.maximum_bytes = 0;
        }

        let mut attempts = 0;
        for _ in 0..2 {
            let (score, reused) =
                cache.score_or_compute(Some(selection.clone()), operation(), || {
                    attempts += 1;
                    Ok(Some(complete_score()))
                })?;
            assert!(!reused);
            assert_eq!(score.map(|score| score.novelty), Some(2));
        }
        assert_eq!(
            attempts, 2,
            "a full cache must compute every requested score"
        );
    }
    Ok(())
}

#[test]
fn incomplete_scores_are_recomputed_and_complete_scores_are_reused()
-> Result<(), RelationalTransformError> {
    let mut cache = PrefixProbeCache::new(usize::MAX);
    let selection = selection(0, 3);
    let mut attempts = 0;
    let (score, reused) = cache.score_or_compute(Some(selection.clone()), operation(), || {
        attempts += 1;
        Ok(Some(PrefixProbeScore {
            novelty: 0,
            work_bytes: 1,
            complete: false,
        }))
    })?;
    assert!(!reused);
    assert!(score.is_some_and(|score| !score.complete));

    let (score, reused) = cache.score_or_compute(Some(selection.clone()), operation(), || {
        attempts += 1;
        Ok(Some(complete_score()))
    })?;
    assert!(!reused);
    assert!(score.is_some_and(|score| score.complete));

    let (score, reused) = cache.score_or_compute(Some(selection), operation(), || {
        attempts += 1;
        Ok(None)
    })?;
    assert!(reused);
    assert_eq!(score.map(|score| score.novelty), Some(2));
    assert_eq!(attempts, 2);
    Ok(())
}

#[test]
fn empty_or_failed_computations_are_never_cached() -> Result<(), RelationalTransformError> {
    let mut cache = PrefixProbeCache::new(usize::MAX);
    let selection = selection(0, 3);
    let (score, reused) =
        cache.score_or_compute(Some(selection.clone()), operation(), || Ok(None))?;
    assert!(!reused);
    assert!(score.is_none());

    let error = cache.score_or_compute(Some(selection.clone()), operation(), || {
        Err(RelationalTransformError::InvalidPlan("test failure"))
    });
    assert!(error.is_err());

    let (score, reused) =
        cache.score_or_compute(Some(selection), operation(), || Ok(Some(complete_score())))?;
    assert!(!reused);
    assert_eq!(score.map(|score| score.novelty), Some(2));
    Ok(())
}

#[test]
fn operation_fields_each_separate_cached_scores() -> Result<(), RelationalTransformError> {
    let mut cache = PrefixProbeCache::new(usize::MAX);
    let selection = selection(0, 3);
    let baseline = RelationalSha256CounterXor {
        counter_width: CounterWidth::FourBytes,
        ..operation()
    };
    let variants = [
        baseline,
        RelationalSha256CounterXor {
            initial_counter: 2,
            ..baseline
        },
        RelationalSha256CounterXor {
            counter_width: CounterWidth::TwoBytes,
            ..baseline
        },
        RelationalSha256CounterXor {
            counter_byte_order: CounterByteOrder::LittleEndian,
            ..baseline
        },
        RelationalSha256CounterXor {
            seed_order: SeedCounterOrder::CounterThenSeed,
            ..baseline
        },
    ];
    let mut attempts = 0;
    for variant in variants {
        let (score, reused) = cache.score_or_compute(Some(selection.clone()), variant, || {
            attempts += 1;
            Ok(Some(complete_score()))
        })?;
        assert!(!reused);
        assert!(score.is_some());
    }
    assert_eq!(attempts, variants.len());
    let (_, reused) = cache.score_or_compute(Some(selection), baseline, || Ok(None))?;
    assert!(reused);
    Ok(())
}

#[test]
fn full_cache_keeps_existing_scores_and_declines_new_entries()
-> Result<(), RelationalTransformError> {
    let mut cache = PrefixProbeCache::new(usize::MAX);
    let first = selection(0, 3);
    let (_, reused) = cache.score_or_compute(Some(first.clone()), operation(), || {
        Ok(Some(complete_score()))
    })?;
    assert!(!reused);
    cache.maximum_bytes = cache.retained_bytes;

    let (_, reused) = cache.score_or_compute(Some(selection(0, 4)), operation(), || {
        Ok(Some(complete_score()))
    })?;
    assert!(!reused);
    let (_, reused) = cache.score_or_compute(Some(first), operation(), || Ok(None))?;
    assert!(reused);
    Ok(())
}

#[test]
fn ordered_training_samples_and_ranges_each_separate_cached_scores()
-> Result<(), RelationalTransformError> {
    let mut cache = PrefixProbeCache::new(usize::MAX);
    let first_record = session_selection(0, 3);
    let second_record = session_selection(1, 3);
    let first = PrefixSelectionIdentity(vec![first_record]);
    let changed_prefix = PrefixSelectionIdentity(vec![PrefixSessionSelection {
        prefix_end: 3,
        ..first_record
    }]);
    let changed_seed = PrefixSelectionIdentity(vec![PrefixSessionSelection {
        seed_end: 2,
        ..first_record
    }]);
    let ordered = PrefixSelectionIdentity(vec![first_record, second_record]);
    let reversed = PrefixSelectionIdentity(vec![second_record, first_record]);
    let variants = [
        first.clone(),
        PrefixSelectionIdentity(vec![second_record]),
        selection(0, 4),
        changed_prefix,
        changed_seed,
        ordered,
        reversed,
    ];
    for variant in variants {
        let (_, reused) =
            cache.score_or_compute(Some(variant), operation(), || Ok(Some(complete_score())))?;
        assert!(!reused);
    }
    let (_, reused) = cache.score_or_compute(Some(first), operation(), || Ok(None))?;
    assert!(reused);
    Ok(())
}

fn selection(sample_index: usize, payload_end: usize) -> PrefixSelectionIdentity {
    PrefixSelectionIdentity(vec![session_selection(sample_index, payload_end)])
}

fn session_selection(sample_index: usize, payload_end: usize) -> PrefixSessionSelection {
    PrefixSessionSelection {
        session_index: 0,
        seed_sample_index: sample_index,
        seed_start: 0,
        seed_end: 1,
        payload_sample_index: sample_index,
        payload_start: 1,
        payload_end,
        prefix_end: 2,
    }
}

fn complete_score() -> PrefixProbeScore {
    PrefixProbeScore {
        novelty: 2,
        work_bytes: 4,
        complete: true,
    }
}

fn operation() -> RelationalSha256CounterXor {
    RelationalSha256CounterXor {
        initial_counter: 1,
        counter_width: CounterWidth::OneByte,
        counter_byte_order: CounterByteOrder::BigEndian,
        seed_order: SeedCounterOrder::SeedThenCounter,
    }
}
