//! Interpret retained ARP claims without treating silence as isolation

use super::engine::{Assessment, Attempt, Step};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    ExpectedObserved,
    Inconclusive,
}

pub fn test_claim(result: &Assessment) -> Claim {
    if expected_claim(&result.test) {
        Claim::ExpectedObserved
    } else {
        Claim::Inconclusive
    }
}

pub fn controls_observed(result: &Assessment) -> bool {
    expected_claim(&result.before) && expected_claim(&result.after)
}

pub fn expected_claim(step: &Step) -> bool {
    let Step::Attempted {
        outcome: Attempt::Report { report, .. },
        ..
    } = step
    else {
        return false;
    };
    // Conflicting claims do not erase a separately retained expected claim
    report
        .observations()
        .iter()
        .any(|item| report.expected_match(item.mac()) == Some(true))
}
