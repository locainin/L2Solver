//! Pure client and server transitions for two bounded synthetic exchanges

use std::net::Ipv4Addr;

use l2_canary::AgentId;

use super::{
    Config, ExchangeSnapshot, Fault, IngressPolicy, Lease, Message, MessageKind, Server,
    StateSnapshot,
};

#[derive(Debug)]
pub(super) struct Machine {
    config: Config,
    state: StateSnapshot,
}

impl Machine {
    pub(super) fn new(config: Config) -> Self {
        Self {
            config,
            state: StateSnapshot::default(),
        }
    }

    pub(super) fn snapshot(&self) -> StateSnapshot {
        self.state.clone()
    }

    pub(super) fn restore(&mut self, fault: Fault) {
        // Restore each independently owned exchange to its pre-run state
        self.state.control = ExchangeSnapshot::default();
        if fault != Fault::CleanupNotRestored {
            self.state.target = ExchangeSnapshot::default();
        }
    }

    // Each sequence is a bounded opportunity, even when no message is emitted
    pub(super) fn dispatch(
        &mut self,
        sequence: u64,
        policy: IngressPolicy,
        fault: Fault,
    ) -> Option<(Message, bool)> {
        match sequence {
            1..=4 => self.control_dispatch(sequence, policy, fault),
            5..=10 => self.target_dispatch(sequence, policy, fault),
            _ => None,
        }
    }

    fn control_dispatch(
        &mut self,
        sequence: u64,
        policy: IngressPolicy,
        fault: Fault,
    ) -> Option<(Message, bool)> {
        let config = self.config;
        let exchange = &mut self.state.control;
        match sequence {
            1 => Some((
                discover(sequence, config.control_client, config.control_transaction),
                false,
            )),
            2 if fault != Fault::MissingControlOffer => Some(offer(
                exchange,
                offer_message(
                    sequence,
                    config.control_client,
                    config.control_transaction,
                    config.authorized_server,
                    config.control_address,
                ),
                policy,
            )),
            3 => request(sequence, exchange),
            4 if fault != Fault::MissingControlAck => acknowledgement(
                sequence,
                exchange,
                config.authorized_server,
                config.control_address,
                config.control_transaction,
                policy,
                Fault::None,
            ),
            _ => None,
        }
    }

    fn target_dispatch(
        &mut self,
        sequence: u64,
        policy: IngressPolicy,
        fault: Fault,
    ) -> Option<(Message, bool)> {
        let config = self.config;
        let exchange = &mut self.state.target;
        match sequence {
            5 => Some((discover(sequence, config.client, config.transaction), false)),
            6 | 9 => rogue_response(sequence, exchange, config, policy, fault),
            7 if fault != Fault::MissingTargetOffer => Some(offer(
                exchange,
                offer_message(
                    sequence,
                    config.client,
                    config.transaction,
                    config.authorized_server,
                    config.authorized_address,
                ),
                policy,
            )),
            8 => request(sequence, exchange),
            // An honest server does not ACK a request selecting another offer
            10 if fault != Fault::MissingTargetAck
                && exchange.selected_offer.is_some_and(|selected| {
                    selected.source == config.authorized_server.agent()
                }) =>
            {
                acknowledgement(
                    sequence,
                    exchange,
                    config.authorized_server,
                    config.authorized_address,
                    config.transaction,
                    policy,
                    fault,
                )
            }
            _ => None,
        }
    }
}

// Both rogue messages share the same attachment and fault-controlled identity
fn rogue_response(
    sequence: u64,
    exchange: &mut ExchangeSnapshot,
    config: Config,
    policy: IngressPolicy,
    fault: Fault,
) -> Option<(Message, bool)> {
    let (identifier, address) = match (sequence, fault) {
        (_, Fault::RogueSpoofsIdentifier) => {
            (config.authorized_server.identifier(), config.rogue_address)
        }
        (9, Fault::RogueSpoofsSelectedReply) => (
            config.authorized_server.identifier(),
            config.authorized_address,
        ),
        _ => (config.rogue_server.identifier(), config.rogue_address),
    };
    let server = Server::new(config.rogue_server.agent(), identifier);
    if sequence == 6 {
        Some(offer(
            exchange,
            offer_message(sequence, config.client, config.transaction, server, address),
            policy,
        ))
    } else {
        // A rogue server also sends an unsolicited ACK when not selected
        acknowledgement(
            sequence,
            exchange,
            server,
            address,
            config.transaction,
            policy,
            Fault::None,
        )
    }
}

const fn discover(sequence: u64, client: AgentId, transaction: u32) -> Message {
    Message {
        sequence,
        kind: MessageKind::Discover,
        source: client,
        client,
        transaction,
        server_identifier: None,
        address: None,
    }
}

const fn offer_message(
    sequence: u64,
    client: AgentId,
    transaction: u32,
    server: Server,
    address: Ipv4Addr,
) -> Message {
    Message {
        sequence,
        kind: MessageKind::Offer,
        source: server.agent(),
        client,
        transaction,
        server_identifier: Some(server.identifier()),
        address: Some(address),
    }
}

fn offer(
    exchange: &mut ExchangeSnapshot,
    message: Message,
    policy: IngressPolicy,
) -> (Message, bool) {
    let delivered = policy.permits(message.source, message.kind);
    if delivered && exchange.selected_offer.is_none() {
        // The client selects the first delivered offer in this deterministic model
        exchange.selected_offer = Some(message);
    }
    (message, delivered)
}

fn request(sequence: u64, exchange: &mut ExchangeSnapshot) -> Option<(Message, bool)> {
    let selected = exchange.selected_offer?;
    exchange.requested = true;
    Some((
        Message {
            sequence,
            kind: MessageKind::Request,
            source: selected.client,
            client: selected.client,
            transaction: selected.transaction,
            server_identifier: selected.server_identifier,
            address: selected.address,
        },
        false,
    ))
}

fn acknowledgement(
    sequence: u64,
    exchange: &mut ExchangeSnapshot,
    server: Server,
    address: Ipv4Addr,
    transaction: u32,
    policy: IngressPolicy,
    fault: Fault,
) -> Option<(Message, bool)> {
    let selected = exchange.selected_offer.filter(|_| exchange.requested)?;
    let (reply_transaction, reply_address) = reply_fields(transaction, address, fault);
    let message = Message {
        sequence,
        kind: MessageKind::Ack,
        source: server.agent(),
        client: selected.client,
        transaction: reply_transaction,
        server_identifier: Some(server.identifier()),
        address: Some(reply_address),
    };
    let selected_server = selected.source == server.agent();
    if selected_server && fault != Fault::TargetServerDoesNotBind {
        // The server records the requested binding independently of the client
        exchange.server_lease = Some(Lease {
            client: selected.client,
            server: server.agent(),
            transaction,
            address,
        });
    }
    let delivered = policy.permits(message.source, message.kind);
    if delivered
        && exchange.client_lease.is_none()
        && message.same_assignment(&selected)
        && fault != Fault::TargetClientDoesNotBind
    {
        // The client matches response fields without authenticating the attachment
        exchange.client_lease = Some(Lease {
            client: message.client,
            server: message.source,
            transaction: message.transaction,
            address: reply_address,
        });
    }
    Some((message, delivered))
}

// Faults mutate only the response, not the server's requested binding
fn reply_fields(transaction: u32, address: Ipv4Addr, fault: Fault) -> (u32, Ipv4Addr) {
    let transaction = if fault == Fault::WrongTargetTransaction {
        transaction.wrapping_add(1)
    } else {
        transaction
    };
    let address = if fault == Fault::WrongTargetAddress {
        let [a, b, c, d] = address.octets();
        Ipv4Addr::new(a, b, c, d ^ 1)
    } else {
        address
    };
    (transaction, address)
}
