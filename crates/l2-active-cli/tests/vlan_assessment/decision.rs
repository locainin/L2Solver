use std::{error::Error, time::Duration};

use l2_active::{Limits, PreSendUsage};

use super::{
    arp_fixture,
    decision::{self, Claim},
    engine::{Assessment, Attempt, SkipReason, Step},
    report_fixture::report,
};

fn step(senders: &[[u8; 6]]) -> Result<Step, Box<dyn Error>> {
    Ok(Step::Attempted {
        limits: Limits::new(Duration::from_millis(20), 10, 1_000)?,
        outcome: Attempt::Report {
            report: report(senders, Some(PreSendUsage::new(0, 0)))?,
            close_error: None,
        },
    })
}

#[test]
fn matching_test_claim_is_observed_even_with_an_unexpected_identity() -> Result<(), Box<dyn Error>>
{
    let result = Assessment {
        before: step(&[arp_fixture::REMOTE_MAC])?,
        test: step(&[arp_fixture::OTHER_MAC, arp_fixture::REMOTE_MAC])?,
        after: step(&[arp_fixture::REMOTE_MAC])?,
    };
    assert_eq!(decision::test_claim(&result), Claim::ExpectedObserved);
    assert!(decision::controls_observed(&result));
    Ok(())
}

#[test]
fn silence_and_unexpected_only_claims_are_both_inconclusive() -> Result<(), Box<dyn Error>> {
    let cases: [&[[u8; 6]]; 2] = [&[], &[arp_fixture::OTHER_MAC]];
    for senders in cases {
        let result = Assessment {
            before: step(&[arp_fixture::REMOTE_MAC])?,
            test: step(senders)?,
            after: step(&[arp_fixture::REMOTE_MAC])?,
        };
        assert_eq!(decision::test_claim(&result), Claim::Inconclusive);
        assert!(decision::controls_observed(&result));
    }
    Ok(())
}

#[test]
fn missing_control_does_not_erase_an_observed_test_claim() -> Result<(), Box<dyn Error>> {
    let result = Assessment {
        before: step(&[])?,
        test: step(&[arp_fixture::REMOTE_MAC])?,
        after: Step::Skipped(SkipReason::Budget),
    };
    assert_eq!(decision::test_claim(&result), Claim::ExpectedObserved);
    assert!(!decision::controls_observed(&result));
    Ok(())
}
