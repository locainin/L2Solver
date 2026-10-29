//! Evaluate visible receiver messages and independently observed endpoint state

use l2_scenario::StopReason;

use crate::ObservationMode;

use super::{Config, Lease, Message, MessageKind, Outcome, Run, StateSnapshot};

pub(super) fn assess(run: &Run) -> Outcome {
    let config = run.config;
    let options = run.options;
    // A visible violation remains a failure even if later collection is incomplete
    if let Some(failure) = observed_failure(config, run) {
        return failure;
    }
    if run.execution.stop_reason() != StopReason::Exhausted {
        return Outcome::IncompleteRun;
    }
    if options.receiver != ObservationMode::Healthy {
        return Outcome::ReceiverIncomplete;
    }
    if options.state != ObservationMode::Healthy {
        return Outcome::StateIncomplete;
    }
    if missing_message(config, run) {
        return Outcome::MissingMessage;
    }
    let Some(state) = run.during.as_ref() else {
        return Outcome::StateIncomplete;
    };
    // Both accepted acknowledgements and both independent bindings are required
    if state.client_leases().iter().any(Option::is_none)
        || state.server_leases().iter().any(Option::is_none)
    {
        return Outcome::InconsistentLease;
    }
    Outcome::Consistent
}

fn observed_failure(config: Config, run: &Run) -> Option<Outcome> {
    if run.received.iter().any(|message| {
        message.source != config.authorized_server.agent()
            && matches!(message.kind, MessageKind::Offer | MessageKind::Ack)
    }) {
        return Some(Outcome::UnauthorizedResponse);
    }
    if inconsistent_acknowledgement(run) {
        return Some(Outcome::InconsistentAcknowledgement);
    }
    if let Some(state) = run.during.as_ref() {
        if inconsistent_lease(config, run, state) {
            return Some(Outcome::InconsistentLease);
        }
        let count = state
            .server_leases()
            .into_iter()
            .flatten()
            .filter(|lease| lease.server == config.authorized_server.agent())
            .count();
        if count > usize::from(config.authorized_lease_limit) {
            return Some(Outcome::LeaseLimitExceeded);
        }
    }
    if let (Some(before), Some(after)) = (run.before.as_ref(), run.after.as_ref())
        && before != after
    {
        return Some(Outcome::CleanupMismatch);
    }
    None
}

// Compare each observed ACK with the request for the same client
fn inconsistent_acknowledgement(run: &Run) -> bool {
    run.received
        .iter()
        .filter(|message| message.kind == MessageKind::Ack)
        .any(|ack| {
            run.sent
                .iter()
                .find(|message| {
                    message.kind == MessageKind::Request && message.client == ack.client
                })
                .is_some_and(|request| !ack.same_assignment(request))
        })
}

fn inconsistent_lease(config: Config, run: &Run, state: &StateSnapshot) -> bool {
    let expected = [
        Lease {
            client: config.control_client,
            server: config.authorized_server.agent(),
            transaction: config.control_transaction,
            address: config.control_address,
        },
        Lease {
            client: config.client,
            server: config.authorized_server.agent(),
            transaction: config.transaction,
            address: config.authorized_address,
        },
    ];
    state
        .client_leases()
        .into_iter()
        .zip(state.server_leases())
        .zip(expected)
        .any(|((client, server), expected)| {
            // A missing client binding is a violation only after a visible ACK
            let ack_observed = run.received.iter().any(|message| {
                message.kind == MessageKind::Ack && message.client == expected.client
            });
            client.is_some_and(|lease| lease != expected || Some(lease) != server)
                || server.is_some_and(|lease| lease != expected)
                || (ack_observed && client.is_none())
        })
}

fn missing_message(config: Config, run: &Run) -> bool {
    let exchanges = [
        (
            config.control_client,
            config.control_transaction,
            config.control_address,
        ),
        (config.client, config.transaction, config.authorized_address),
    ];
    exchanges.into_iter().any(|(client, transaction, address)| {
        [MessageKind::Offer, MessageKind::Ack]
            .into_iter()
            .any(|kind| {
                !run.received.iter().any(|message| {
                    expected_response(message, config, kind, client, transaction, address)
                })
            })
    }) || [MessageKind::Offer, MessageKind::Ack]
        .into_iter()
        .any(|kind| {
            !run.sent.iter().any(|message| {
                message.kind == kind
                    && message.source == config.rogue_server.agent()
                    && message.client == config.client
                    && message.transaction == config.transaction
            })
        })
}

fn expected_response(
    message: &Message,
    config: Config,
    kind: MessageKind,
    client: l2_canary::AgentId,
    transaction: u32,
    address: std::net::Ipv4Addr,
) -> bool {
    message.kind == kind
        && message.client == client
        && message.source == config.authorized_server.agent()
        && message.transaction == transaction
        && message.server_identifier == Some(config.authorized_server.identifier())
        && message.address == Some(address)
}
