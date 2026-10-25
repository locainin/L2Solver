//! Bounded wire protocol for the receive-only packet helper
//!
//! The helper protocol exposes capture setup, receive polling, cancellation, and
//! closure. It deliberately has no transmit operation

#![forbid(unsafe_code)]

mod binding;
mod bytes;
mod codec;
mod error;
mod message;
mod state;

pub use binding::InterfaceBindingRequest;
pub use codec::{HEADER_LENGTH, MAX_MESSAGE_LENGTH, decode, encode};
pub use error::ProtocolError;
pub use message::{Message, MessageKind, SessionId};
pub use state::{ControlAction, PeerState};
