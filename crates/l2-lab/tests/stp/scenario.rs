use std::error::Error;

use l2_lab::{
    ObservationMode,
    stp::{
        Bridge, BridgeState, CleanupMode, Error as StpError, Guard, GuardExpectation, Options,
        Port, PortState,
    },
};
use l2_scenario::{Cleanup, StopReason};
use l2_segmentation::EvaluationStatus;
use sha2::{Digest, Sha256};

use super::support::{budget, frame, hostile, local, scenario, trusted};

#[test]
fn bpdu_guard_preserves_root_disables_edge_and_restores_state() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::BpduGuard)?;
    let before = bridge.state();
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::BpduGuard),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Pass);
    assert_eq!(
        report.after_control().map(BridgeState::root),
        Some(trusted())
    );
    assert_eq!(
        report.after_control().and_then(BridgeState::root_port),
        Some(Port::Trusted)
    );
    assert_eq!(
        report.after_attack().map(BridgeState::root),
        Some(trusted())
    );
    assert_eq!(
        report.after_attack().map(BridgeState::edge),
        Some(PortState::Disabled)
    );
    assert_eq!(report.after_cleanup(), Some(before));
    assert_eq!(bridge.state(), before);
    assert_eq!(report.execution().cleanup(), Cleanup::Confirmed);
    assert_eq!(report.capture().records().len(), 2);
    Ok(())
}

#[test]
fn root_guard_blocks_superior_rapid_bpdu_and_keeps_control_root() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), true)?;
    let attack = frame(hostile(), true)?;
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Pass);
    assert_eq!(
        report.after_control().map(BridgeState::root),
        Some(trusted())
    );
    assert_eq!(
        report.after_attack().map(BridgeState::root),
        Some(trusted())
    );
    assert_eq!(
        report.after_attack().map(BridgeState::edge),
        Some(PortState::RootInconsistent)
    );
    Ok(())
}

#[test]
fn unguarded_superior_bpdu_changes_root_and_fails() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), true)?;
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Fail);
    assert_eq!(
        report.after_control().map(BridgeState::root),
        Some(trusted())
    );
    assert_eq!(
        report.after_attack().map(BridgeState::root),
        Some(hostile())
    );
    assert_eq!(
        bridge.state().root(),
        local(),
        "cleanup must restore the actual model state"
    );
    Ok(())
}

#[test]
fn observed_root_takeover_remains_failure_when_cleanup_is_unconfirmed() -> Result<(), Box<dyn Error>>
{
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let options = Options::new(
        ObservationMode::Healthy,
        l2_lab::Cancellation::Never,
        CleanupMode::Skip,
    );
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        options,
    )?;
    assert_eq!(report.status(), EvaluationStatus::Fail);
    assert_eq!(report.execution().cleanup(), Cleanup::Unconfirmed);
    assert_eq!(bridge.state().root(), hostile());
    bridge.restore();
    Ok(())
}

#[test]
fn different_guard_behavior_does_not_satisfy_the_expected_guard() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::BpduGuard),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(
        report.after_attack().map(BridgeState::edge),
        Some(PortState::RootInconsistent)
    );
    assert_eq!(report.status(), EvaluationStatus::Fail);
    Ok(())
}

#[test]
fn lost_observer_cannot_prove_protection_or_cleanup() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    for observer in [ObservationMode::Unavailable, ObservationMode::Dropped] {
        let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
        let options = Options::new(observer, l2_lab::Cancellation::Never, CleanupMode::Restore);
        let report = bridge.run(
            &scenario(&control, &attack, GuardExpectation::RootGuard),
            budget()?,
            options,
        )?;
        assert_eq!(report.status(), EvaluationStatus::Inconclusive);
        assert!(report.after_attack().is_none());
        assert!(report.after_cleanup().is_none());
        assert_eq!(report.execution().cleanup(), Cleanup::Unconfirmed);
        assert!(report.capture().records().is_empty());
        assert_eq!(
            bridge.state().root(),
            local(),
            "restoration still runs with missing observation"
        );
    }
    Ok(())
}

#[test]
fn padded_ethernet_bpdus_keep_exact_bytes_in_capture_and_budget() -> Result<(), Box<dyn Error>> {
    let mut control = frame(trusted(), false)?;
    let mut attack = frame(hostile(), true)?;
    control.resize(60, 0xa5);
    attack.resize(60, 0x5a);
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        l2_onpath::Budget::new(2, 120, 2)?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Pass);
    assert_eq!(report.execution().bytes(), 120);
    for record in report.capture().records() {
        let expected = match record.port() {
            Port::Trusted => &control,
            Port::Edge => &attack,
        };
        assert_eq!(record.frame(), expected);
        assert!(!l2_core::decode(record.frame())?.padding.is_empty());
    }
    Ok(())
}

#[test]
fn maximum_frame_size_is_accepted_and_one_byte_more_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut control = frame(trusted(), false)?;
    let mut attack = frame(hostile(), true)?;
    control.resize(128, 0xa5);
    attack.resize(128, 0x5a);
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let before = bridge.state();
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        l2_onpath::Budget::new(2, 256, 2)?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Pass);
    assert_eq!(report.execution().bytes(), 256);
    assert_eq!(bridge.state(), before);
    for record in report.capture().records() {
        let expected = match record.port() {
            Port::Trusted => &control,
            Port::Edge => &attack,
        };
        assert_eq!(record.frame(), expected);
    }

    // Both oversized frames retain a valid BPDU in their declared payload
    let mut oversized_control = control.clone();
    oversized_control.push(0xa6);
    let mut oversized_attack = attack.clone();
    oversized_attack.push(0x5b);
    for (first, second) in [
        (oversized_control.as_slice(), attack.as_slice()),
        (control.as_slice(), oversized_attack.as_slice()),
    ] {
        let oversized = if first.len() == 129 { first } else { second };
        assert!(l2_codecs::decode_stp(l2_core::decode(oversized)?.payload).is_ok());
        assert!(matches!(
            bridge.run(
                &scenario(first, second, GuardExpectation::RootGuard),
                l2_onpath::Budget::new(2, 258, 2)?,
                Options::default(),
            ),
            Err(StpError::InvalidFrame)
        ));
        assert_eq!(bridge.state(), before);
    }
    Ok(())
}

#[test]
fn report_retains_guard_expectation_and_observation_conditions() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        Options::new(
            ObservationMode::Dropped,
            l2_lab::Cancellation::Never,
            CleanupMode::Restore,
        ),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Inconclusive);
    assert_eq!(report.guard(), Guard::None);
    assert_eq!(report.expected_guard(), GuardExpectation::RootGuard);
    assert_eq!(report.expected_root(), trusted());
    assert_eq!(report.observation_mode(), ObservationMode::Dropped);
    Ok(())
}

#[test]
fn dropping_valid_control_does_not_prove_guard_protection() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::DropAll)?;
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(report.status(), EvaluationStatus::Inconclusive);
    assert_eq!(report.after_control().map(BridgeState::root), Some(local()));
    Ok(())
}

#[test]
fn cancellation_and_restore_fault_do_not_claim_clean_success() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    for count in [0, 1] {
        let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
        let options = Options::new(
            ObservationMode::Healthy,
            l2_lab::Cancellation::After(count),
            CleanupMode::Restore,
        );
        let report = bridge.run(
            &scenario(&control, &attack, GuardExpectation::RootGuard),
            budget()?,
            options,
        )?;
        assert_eq!(report.status(), EvaluationStatus::Inconclusive);
        assert_eq!(report.execution().stop_reason(), StopReason::Cancelled);
        assert_eq!(report.execution().packets(), count);
        assert_eq!(report.execution().cleanup(), Cleanup::Confirmed);
        assert_eq!(bridge.state().root(), local());
    }
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let options = Options::new(
        ObservationMode::Healthy,
        l2_lab::Cancellation::Never,
        CleanupMode::Skip,
    );
    let report = bridge.run(
        &scenario(&control, &attack, GuardExpectation::RootGuard),
        budget()?,
        options,
    )?;
    assert_eq!(report.status(), EvaluationStatus::Inconclusive);
    assert_eq!(report.execution().cleanup(), Cleanup::Unconfirmed);
    assert_ne!(bridge.state().root(), local());
    assert!(
        bridge
            .run(
                &scenario(&control, &attack, GuardExpectation::RootGuard),
                budget()?,
                Options::default()
            )
            .is_err(),
        "dirty state must reject another run"
    );
    let restored = bridge.restore();
    assert_eq!(restored.root(), local());
    assert_eq!(bridge.restore(), restored, "restoration is idempotent");
    Ok(())
}

#[test]
fn invalid_bpdu_and_insufficient_budget_do_not_change_state() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let before = bridge.state();
    let truncated = attack
        .get(..attack.len() - 1)
        .ok_or("missing truncated frame")?;
    assert!(
        bridge
            .run(
                &scenario(&control, truncated, GuardExpectation::RootGuard),
                budget()?,
                Options::default()
            )
            .is_err()
    );
    assert_eq!(bridge.state(), before);
    assert!(
        bridge
            .run(
                &scenario(&control, &attack, GuardExpectation::RootGuard),
                l2_onpath::Budget::new(1, 256, 2)?,
                Options::default()
            )
            .is_err()
    );
    assert_eq!(bridge.state(), before);
    Ok(())
}

#[test]
fn same_synthetic_source_on_both_ports_is_rejected_before_dispatch() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let mut attack = frame(hostile(), false)?;
    attack
        .get_mut(6..12)
        .ok_or("missing Ethernet source")?
        .copy_from_slice(&trusted().mac);
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let before = bridge.state();
    assert!(
        bridge
            .run(
                &scenario(&control, &attack, GuardExpectation::RootGuard),
                budget()?,
                Options::default()
            )
            .is_err()
    );
    assert_eq!(bridge.state(), before);
    Ok(())
}

#[test]
fn byte_level_root_change_that_is_not_superior_is_rejected() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let mut attack = frame(hostile(), false)?;
    attack
        .get_mut(22..24)
        .ok_or("missing root priority")?
        .copy_from_slice(&0x9000_u16.to_be_bytes());
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let before = bridge.state();
    assert!(
        bridge
            .run(
                &scenario(&control, &attack, GuardExpectation::RootGuard),
                budget()?,
                Options::default()
            )
            .is_err()
    );
    assert_eq!(bridge.state(), before);
    Ok(())
}

#[test]
fn equal_root_from_a_distinct_sender_is_not_a_superior_advertisement() -> Result<(), Box<dyn Error>>
{
    let control = frame(trusted(), false)?;
    let mut attack = frame(hostile(), false)?;
    let root = control.get(22..30).ok_or("missing trusted root")?;
    attack
        .get_mut(22..30)
        .ok_or("missing test root")?
        .copy_from_slice(root);
    let control_frame = l2_core::decode(&control)?;
    let attack_frame = l2_core::decode(&attack)?;
    assert_ne!(control_frame.source, attack_frame.source);
    assert_eq!(
        l2_codecs::decode_stp(attack_frame.payload)?.root,
        Some(trusted())
    );
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let before = bridge.state();
    assert!(matches!(
        bridge.run(
            &scenario(&control, &attack, GuardExpectation::RootGuard),
            budget()?,
            Options::default(),
        ),
        Err(StpError::InvalidScenario)
    ));
    assert_eq!(bridge.state(), before);
    Ok(())
}

#[test]
fn malformed_or_extended_bpdu_never_changes_bridge_state() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), false)?;
    let mut invalid_llc = attack.clone();
    *invalid_llc.get_mut(15).ok_or("missing LLC byte")? = 0;
    let mut expired = attack.clone();
    expired
        .get_mut(46..48)
        .ok_or("missing max age")?
        .copy_from_slice(&0_u16.to_be_bytes());
    let mut unsupported = attack.clone();
    *unsupported.get_mut(19).ok_or("missing protocol version")? = 3;
    let mut invalid_sender = attack.clone();
    invalid_sender
        .get_mut(36..42)
        .ok_or("missing sender bridge MAC")?
        .fill(0);
    let mut extension = attack;
    extension.push(1);
    let length = u16::try_from(extension.len() - 14)?;
    extension
        .get_mut(12..14)
        .ok_or("missing Ethernet length")?
        .copy_from_slice(&length.to_be_bytes());
    let mut bridge = Bridge::new(local(), Guard::None)?;
    let before = bridge.state();
    for invalid in [invalid_llc, expired, unsupported, invalid_sender, extension] {
        assert!(
            bridge
                .run(
                    &scenario(&control, &invalid, GuardExpectation::RootGuard),
                    budget()?,
                    Options::default()
                )
                .is_err()
        );
        assert_eq!(bridge.state(), before);
    }
    Ok(())
}

#[test]
fn replay_and_packet_references_match_exact_virtual_capture() -> Result<(), Box<dyn Error>> {
    let control = frame(trusted(), false)?;
    let attack = frame(hostile(), true)?;
    let mut bridge = Bridge::new(local(), Guard::RootGuard)?;
    let plan = scenario(&control, &attack, GuardExpectation::RootGuard);
    let first = bridge.run(&plan, budget()?, Options::default())?;
    let second = bridge.run(&plan, budget()?, Options::default())?;
    assert_eq!(first, second);
    let digest: [u8; 32] = Sha256::digest(first.capture().bytes()?).into();
    assert_eq!(*first.capture().source().as_bytes(), digest);
    for (index, record) in first.capture().records().iter().enumerate() {
        assert_eq!(record.reference().source(), first.capture().source());
        assert_eq!(
            record.reference().packet_number(),
            u64::try_from(index + 1)?
        );
        let ethernet = l2_core::decode(record.frame())?;
        assert!(l2_codecs::decode_stp(ethernet.payload).is_ok());
        let expected = match record.port() {
            Port::Trusted => &control,
            Port::Edge => &attack,
        };
        assert_eq!(record.frame(), expected);
    }
    Ok(())
}
