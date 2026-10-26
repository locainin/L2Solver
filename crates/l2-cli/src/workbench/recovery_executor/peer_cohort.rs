//! Group related sessions while retaining observed peer and service evidence

use super::RecoveryExecutionError;
use l2_workbench::{evidence::Node, protocol::Direction};
use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PeerCohort {
    pub(super) endpoints_json: String,
    pub(super) direction: Direction,
}

pub(super) fn for_episode(
    episode: &Node,
    direction: Direction,
) -> Result<PeerCohort, RecoveryExecutionError> {
    let endpoints = episode
        .details
        .get("endpoints")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_context("missing peer endpoints"))?;
    let [first, second] = endpoints.as_slice() else {
        return Err(invalid_context("expected two peer endpoints"));
    };
    let Some(initiator) = episode
        .details
        .get("initiator")
        .filter(|value| !value.is_null())
    else {
        // Without an observed initiator, temporary and service ports remain indistinguishable
        return Ok(PeerCohort {
            endpoints_json: json!({"rule":"exact_transport_endpoints","endpoints":endpoints})
                .to_string(),
            direction,
        });
    };
    let (responder, direction) = if initiator == first {
        (second, direction)
    } else if initiator == second {
        (first, reverse(direction))
    } else {
        return Err(invalid_context("initiator is outside the peer endpoints"));
    };
    let address = initiator
        .get("address")
        .filter(|value| !value.is_null())
        .ok_or_else(|| invalid_context("initiator address is missing"))?;

    // The observed client role permits its port to vary while retaining the service endpoint
    Ok(PeerCohort {
        endpoints_json: json!({
            "rule":"observed_initiator_address_and_responder_endpoint",
            "initiator_address":address,
            "responder":responder,
        })
        .to_string(),
        direction,
    })
}

const fn reverse(direction: Direction) -> Direction {
    match direction {
        Direction::FirstToSecond => Direction::SecondToFirst,
        Direction::SecondToFirst => Direction::FirstToSecond,
    }
}

fn invalid_context(reason: &str) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(format!("invalid relational peer context: {reason}"))
}

#[cfg(test)]
#[path = "../../../tests/workbench/peer_cohort.rs"]
mod tests;
