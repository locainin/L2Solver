use crate::{InterfaceBindingRequest, Message, MessageKind, ProtocolError, SessionId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerPhase {
    AwaitingHandshake,
    Running,
    Stopping,
    Closed,
}

// Actions are deliberately receive-only and contain no raw frame transmission
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAction {
    HandshakeAccepted,
    OpenReceive(InterfaceBindingRequest),
    ReceiveNext,
    Cancel,
    Close,
}

// State validation happens again inside the helper authority boundary
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerState {
    session: SessionId,
    phase: PeerPhase,
    last_data_sequence: Option<u64>,
    last_control_sequence: Option<u64>,
}

impl PeerState {
    #[must_use]
    pub const fn new(session: SessionId) -> Self {
        Self {
            session,
            phase: PeerPhase::AwaitingHandshake,
            last_data_sequence: None,
            last_control_sequence: None,
        }
    }

    /// Validates and applies one frontend request
    ///
    /// Cancellation and workload each have an independent sequence order
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong session, replayed sequencing, invalid
    /// state transitions, or invalid interface binding payloads
    pub fn accept(&mut self, message: &Message<'_>) -> Result<ControlAction, ProtocolError> {
        if message.session() != self.session {
            return Err(ProtocolError::SessionMismatch);
        }
        // Separate socket queues preserve order only within their own channel
        let last_sequence = if message.kind() == MessageKind::Cancel {
            self.last_control_sequence
        } else {
            self.last_data_sequence
        };
        if last_sequence.is_some_and(|sequence| message.sequence() <= sequence) {
            return Err(ProtocolError::SequenceNotIncreasing);
        }

        let (next_phase, action) = self.transition(message)?;
        self.phase = next_phase;
        if message.kind() == MessageKind::Cancel {
            self.last_control_sequence = Some(message.sequence());
        } else {
            self.last_data_sequence = Some(message.sequence());
        }
        Ok(action)
    }

    fn transition(
        self,
        message: &Message<'_>,
    ) -> Result<(PeerPhase, ControlAction), ProtocolError> {
        match self.phase {
            PeerPhase::AwaitingHandshake => {
                match message.kind() {
                    MessageKind::Hello => {
                        Ok((PeerPhase::Running, ControlAction::HandshakeAccepted))
                    }
                    // Cancellation is an out-of-band safety operation and must remain available
                    // while a helper is still authenticating or opening its receive descriptor
                    MessageKind::Cancel => Ok((PeerPhase::Stopping, ControlAction::Cancel)),
                    _ => Err(ProtocolError::HandshakeRequired),
                }
            }
            PeerPhase::Running => running_transition(message),
            PeerPhase::Stopping => match message.kind() {
                MessageKind::Cancel => Ok((PeerPhase::Stopping, ControlAction::Cancel)),
                MessageKind::Close => Ok((PeerPhase::Closed, ControlAction::Close)),
                MessageKind::Hello | MessageKind::OpenReceive | MessageKind::ReceiveNext => {
                    Err(ProtocolError::SessionStopping)
                }
            },
            PeerPhase::Closed => {
                if message.kind() == MessageKind::Close {
                    Ok((PeerPhase::Closed, ControlAction::Close))
                } else {
                    Err(ProtocolError::SessionClosed)
                }
            }
        }
    }
}

fn running_transition(message: &Message<'_>) -> Result<(PeerPhase, ControlAction), ProtocolError> {
    match message.kind() {
        MessageKind::OpenReceive => {
            let binding = InterfaceBindingRequest::decode(message.payload())?;
            Ok((PeerPhase::Running, ControlAction::OpenReceive(binding)))
        }
        MessageKind::ReceiveNext => Ok((PeerPhase::Running, ControlAction::ReceiveNext)),
        MessageKind::Cancel => Ok((PeerPhase::Stopping, ControlAction::Cancel)),
        MessageKind::Close => Ok((PeerPhase::Closed, ControlAction::Close)),
        MessageKind::Hello => Err(ProtocolError::UnexpectedMessageKind(MessageKind::Hello)),
    }
}
