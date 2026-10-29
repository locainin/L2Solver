use std::error::Error;

use l2_lab::discovery::{Expectation, Observed, Protocol};
use l2_lab::{Cancellation, ObservationMode, RunOptions};
use l2_scenario::{Cleanup, StopReason};
use l2_segmentation::EvaluationStatus;

use super::support::{CDP_GOLDEN, budget, cdp_identity, lab, lldp, lldp_identity, probe};

#[test]
fn lldp_and_cdp_healthy_receivers_observe_expected_identity_and_repeat()
-> Result<(), Box<dyn Error>> {
    let lldp_bytes = lldp(120)?;
    let probes = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &lldp_bytes,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            2,
            2,
            Protocol::Cdp,
            CDP_GOLDEN,
            Expectation::Accepted(cdp_identity()),
        )?,
    ];
    let lab = lab(&probes)?;
    let first = lab.run(budget()?, RunOptions::default())?;
    let second = lab.run(budget()?, RunOptions::default())?;
    assert_eq!(
        first, second,
        "same recorded run and schedule must replay exactly"
    );
    assert_eq!(first.status(), EvaluationStatus::Pass);
    assert_eq!(first.execution().stop_reason(), StopReason::Exhausted);
    assert_eq!(first.execution().packets(), 2);
    assert_eq!(
        first.execution().bytes(),
        u64::try_from(lldp_bytes.len() + CDP_GOLDEN.len())?
    );
    assert_eq!(first.execution().cleanup(), Cleanup::Confirmed);
    assert_eq!(first.cleanup_state(), Some((0, 0)));
    for (index, (observation, check)) in first.observations().iter().zip(first.checks()).enumerate()
    {
        assert_eq!(check.status(), EvaluationStatus::Pass);
        assert_eq!(check.evidence(), Some(observation.reference()));
        assert_eq!(observation.reference().source(), first.source());
        assert_eq!(
            observation.reference().packet_number(),
            u64::try_from(index + 1)?
        );
        assert_eq!(observation.before(), None);
    }
    let first_observation = first.observations().first().ok_or("missing LLDP capture")?;
    assert_eq!(first_observation.frame(), lldp_bytes);
    assert_eq!(
        first_observation.observed(),
        Observed::Accepted(lldp_identity())
    );
    assert_eq!(first_observation.after(), Some(lldp_identity()));
    let cdp_observation = first.observations().get(1).ok_or("missing CDP capture")?;
    assert_eq!(cdp_observation.frame(), CDP_GOLDEN);
    assert_eq!(
        cdp_observation.observed(),
        Observed::Accepted(cdp_identity())
    );
    Ok(())
}

#[test]
fn missing_and_lossy_observers_cannot_prove_receiver_behavior_or_cleanup()
-> Result<(), Box<dyn Error>> {
    let wire = lldp(120)?;
    let probes = [probe(
        1,
        1,
        Protocol::Lldp,
        &wire,
        Expectation::Accepted(lldp_identity()),
    )?];
    let lab = lab(&probes)?;
    for mode in [ObservationMode::Unavailable, ObservationMode::Dropped] {
        let run = lab.run(budget()?, RunOptions::new(mode, Cancellation::Never))?;
        assert_eq!(run.status(), EvaluationStatus::Inconclusive);
        assert_eq!(run.observation_mode(), mode);
        assert!(run.observations().is_empty());
        assert_eq!(
            run.checks().first().map(|check| check.evidence()),
            Some(None)
        );
        assert_eq!(run.execution().cleanup(), Cleanup::Unconfirmed);
        assert_eq!(run.cleanup_state(), None);
    }
    Ok(())
}

#[test]
fn cancellation_restores_observed_neighbor_state_and_retains_prior_failure()
-> Result<(), Box<dyn Error>> {
    let wire = lldp(120)?;
    let probes = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            2,
            2,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
    ];
    let subject = lab(&probes)?;
    for count in [0, 1] {
        let run = subject.run(
            budget()?,
            RunOptions::new(ObservationMode::Healthy, Cancellation::After(count)),
        )?;
        assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
        assert_eq!(run.execution().packets(), count);
        assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
        assert_eq!(run.cleanup_state(), Some((0, 0)));
        assert_eq!(run.status(), EvaluationStatus::Inconclusive);
    }
    let wrong = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(l2_lab::discovery::Identity::new(
                b"\x07other",
                super::support::LLDP_PORT,
            )),
        )?,
        probe(
            2,
            2,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
    ];
    let run = lab(&wrong)?.run(
        budget()?,
        RunOptions::new(ObservationMode::Healthy, Cancellation::After(1)),
    )?;
    assert_eq!(
        run.status(),
        EvaluationStatus::Fail,
        "a cancellation cannot erase a witnessed violation"
    );
    Ok(())
}

#[test]
fn capture_digest_covers_frame_and_observed_neighbor_transition() -> Result<(), Box<dyn Error>> {
    use super::support::{LLDP_DEVICE, LLDP_PORT, receiver, run_id, source};
    use sha2::{Digest, Sha256};

    let wire = lldp(120)?;
    let probes = [probe(
        1,
        7,
        Protocol::Lldp,
        &wire,
        Expectation::Accepted(lldp_identity()),
    )?];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    let mut expected = b"l2solver-discovery-capture-v1\0".to_vec();
    expected.extend_from_slice(run_id()?.as_bytes());
    expected.extend_from_slice(receiver()?.as_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&7_u64.to_be_bytes());
    expected.extend_from_slice(source()?.as_bytes());
    expected.push(1);
    expected.extend_from_slice(&u16::try_from(wire.len())?.to_be_bytes());
    expected.extend_from_slice(&wire);
    expected.push(1); // Accepted transition and its reported identity
    for part in [LLDP_DEVICE, LLDP_PORT] {
        expected.extend_from_slice(&u16::try_from(part.len())?.to_be_bytes());
        expected.extend_from_slice(part);
    }
    expected.push(0); // No prior neighbor
    expected.push(1); // The learned neighbor is present after delivery
    for part in [LLDP_DEVICE, LLDP_PORT] {
        expected.extend_from_slice(&u16::try_from(part.len())?.to_be_bytes());
        expected.extend_from_slice(part);
    }
    assert_eq!(run.capture_bytes()?, expected);
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    assert_eq!(*run.source().as_bytes(), digest);
    Ok(())
}

#[test]
fn scheduler_orders_by_virtual_time_then_sequence() -> Result<(), Box<dyn Error>> {
    let wire = lldp(120)?;
    let probes = [
        probe(
            3,
            4,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            2,
            1,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            1,
            1,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?,
    ];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    let sequence: Vec<u64> = run
        .observations()
        .iter()
        .map(|observation| observation.sequence())
        .collect();
    assert_eq!(sequence, [1, 2, 3]);
    assert_eq!(run.execution().elapsed_millis(), 4);
    assert_eq!(run.status(), EvaluationStatus::Pass);
    Ok(())
}
