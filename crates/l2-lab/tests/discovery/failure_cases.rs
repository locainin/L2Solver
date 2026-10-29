use std::error::Error;

use l2_lab::discovery::{Expectation, Identity, Observed, Protocol};
use l2_lab::{Cancellation, ObservationMode, RunOptions};
use l2_segmentation::EvaluationStatus;

use super::support::{CDP_GOLDEN, CDP_PORT, LLDP_PORT, budget, lab, lldp, lldp_identity, probe};

#[test]
fn conflicting_device_or_port_identity_is_a_witnessed_failure() -> Result<(), Box<dyn Error>> {
    let lldp_bytes = lldp(120)?;
    let probes = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &lldp_bytes,
            Expectation::Accepted(Identity::new(b"\x07wrong-device", LLDP_PORT)),
        )?,
        probe(
            2,
            2,
            Protocol::Cdp,
            CDP_GOLDEN,
            Expectation::Accepted(Identity::new(b"switch-a", b"other-port")),
        )?,
    ];
    let lab = lab(&probes)?;
    let run = lab.run(budget()?, RunOptions::default())?;
    assert_eq!(run.status(), EvaluationStatus::Fail);
    assert!(
        run.checks()
            .iter()
            .all(|check| check.status() == EvaluationStatus::Fail && check.evidence().is_some())
    );
    assert_eq!(
        run.observations()
            .first()
            .map(|observation| observation.observed()),
        Some(Observed::Accepted(lldp_identity()))
    );
    assert_eq!(
        run.observations()
            .get(1)
            .and_then(|observation| observation.after())
            .map(Identity::port),
        Some(CDP_PORT)
    );
    for mode in [ObservationMode::Unavailable, ObservationMode::Dropped] {
        let run = lab.run(budget()?, RunOptions::new(mode, Cancellation::Never))?;
        assert_eq!(run.status(), EvaluationStatus::Inconclusive);
    }
    Ok(())
}

#[test]
fn malformed_frame_is_rejected_without_overwriting_neighbor_state() -> Result<(), Box<dyn Error>> {
    let valid = lldp(120)?;
    let truncated = valid.get(..valid.len() - 1).ok_or("fixture too short")?;
    let probes = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &valid,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(2, 2, Protocol::Lldp, truncated, Expectation::Rejected)?,
    ];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    assert_eq!(run.status(), EvaluationStatus::Pass);
    let observed = run
        .observations()
        .get(1)
        .ok_or("missing rejection evidence")?;
    assert_eq!(observed.observed(), Observed::Rejected);
    assert_eq!(observed.before(), Some(lldp_identity()));
    assert_eq!(observed.after(), observed.before());
    Ok(())
}

#[test]
fn lldp_withdrawal_and_expiry_follow_virtual_time() -> Result<(), Box<dyn Error>> {
    let short = lldp(1)?;
    let refresh = lldp(120)?;
    let shutdown = lldp(0)?;
    let probes = [
        probe(
            1,
            1,
            Protocol::Lldp,
            &short,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            2,
            1001,
            Protocol::Lldp,
            &refresh,
            Expectation::Accepted(lldp_identity()),
        )?,
        probe(
            3,
            1002,
            Protocol::Lldp,
            &shutdown,
            Expectation::Withdrawn(lldp_identity()),
        )?,
    ];
    let run = lab(&probes)?.run(budget()?, RunOptions::default())?;
    assert_eq!(run.status(), EvaluationStatus::Pass);
    assert_eq!(
        run.observations().get(1).and_then(|item| item.before()),
        None,
        "the old entry expires at its deadline"
    );
    let withdrawal = run
        .observations()
        .get(2)
        .ok_or("missing shutdown observation")?;
    assert_eq!(withdrawal.before(), Some(lldp_identity()));
    assert_eq!(withdrawal.after(), None);
    assert_eq!(withdrawal.observed(), Observed::Withdrawn(lldp_identity()));
    Ok(())
}

#[test]
fn resource_limits_and_duplicate_sequences_reject_before_dispatch() -> Result<(), Box<dyn Error>> {
    use super::support::{receiver, run_id};
    use l2_lab::discovery::{DiscoveryError, DiscoveryLab, MAX_FRAME_BYTES, MAX_PROBES};
    use l2_onpath::Budget;
    use l2_scenario::AdmissionError;

    let wire = lldp(120)?;
    let one = probe(
        1,
        1,
        Protocol::Lldp,
        &wire,
        Expectation::Accepted(lldp_identity()),
    )?;
    let two = probe(
        2,
        2,
        Protocol::Lldp,
        &wire,
        Expectation::Accepted(lldp_identity()),
    )?;
    let probes = [one, two];
    let subject = lab(&probes)?;
    for (limit, expected) in [
        (Budget::new(1, 10_000, 100)?, AdmissionError::PacketLimit),
        (Budget::new(2, 1, 100)?, AdmissionError::ByteLimit),
        (Budget::new(2, 10_000, 1)?, AdmissionError::DurationLimit),
    ] {
        assert!(
            matches!(subject.run(limit, RunOptions::default()), Err(DiscoveryError::Admission(actual)) if actual == expected)
        );
    }
    let duplicate = [one, one];
    assert!(matches!(
        lab(&duplicate)?.run(budget()?, RunOptions::default()),
        Err(DiscoveryError::Admission(AdmissionError::DuplicateSequence))
    ));
    let excessive = vec![one; MAX_PROBES + 1];
    assert!(matches!(
        DiscoveryLab::new(run_id()?, receiver()?, &excessive),
        Err(DiscoveryError::ProbeLimit)
    ));
    let long = vec![0; MAX_FRAME_BYTES + 1];
    let too_long = [probe(1, 1, Protocol::Lldp, &long, Expectation::Rejected)?];
    assert!(matches!(
        DiscoveryLab::new(run_id()?, receiver()?, &too_long),
        Err(DiscoveryError::FrameLimit)
    ));
    let empty = [probe(1, 1, Protocol::Lldp, &[], Expectation::Rejected)?];
    assert!(matches!(
        DiscoveryLab::new(run_id()?, receiver()?, &empty),
        Err(DiscoveryError::FrameLimit)
    ));
    let invalid_id = [probe(
        1,
        1,
        Protocol::Cdp,
        CDP_GOLDEN,
        Expectation::Accepted(Identity::new(&[], b"port")),
    )?];
    assert!(matches!(
        DiscoveryLab::new(run_id()?, receiver()?, &invalid_id),
        Err(DiscoveryError::IdentityLimit)
    ));
    let same = [l2_lab::discovery::Probe::new(
        1,
        1,
        receiver()?,
        Protocol::Lldp,
        &wire,
        Expectation::Rejected,
    )];
    assert!(matches!(
        DiscoveryLab::new(run_id()?, receiver()?, &same),
        Err(DiscoveryError::SameAgent)
    ));
    Ok(())
}

#[test]
fn exact_probe_byte_and_time_limits_allow_the_complete_workload() -> Result<(), Box<dyn Error>> {
    use l2_lab::discovery::MAX_PROBES;
    use l2_onpath::Budget;

    let wire = lldp(120)?;
    let mut probes = Vec::new();
    for number in 1..=MAX_PROBES {
        let sequence = u64::try_from(number)?;
        probes.push(probe(
            sequence,
            sequence,
            Protocol::Lldp,
            &wire,
            Expectation::Accepted(lldp_identity()),
        )?);
    }
    let packets = u64::try_from(MAX_PROBES)?;
    let bytes = packets * u64::try_from(wire.len())?;
    let run = lab(&probes)?.run(Budget::new(packets, bytes, packets)?, RunOptions::default())?;
    assert_eq!(run.status(), EvaluationStatus::Pass);
    assert_eq!(run.execution().packets(), packets);
    assert_eq!(run.execution().bytes(), bytes);
    assert_eq!(run.execution().elapsed_millis(), packets);
    assert_eq!(run.observations().len(), MAX_PROBES);
    Ok(())
}
