//! Receive-only local helper boundary
//!
//! This crate owns the small amount of process-boundary code needed to place a
//! capture descriptor behind a credential-checked local helper. Requests reuse
//! the fixed, bounded [`l2_helper_protocol`] codec. Ordinary requests and
//! cancellation use distinct local `SOCK_SEQPACKET` channels, so a full record
//! queue cannot delay a stop request. Linux peer credentials describe the
//! socket-pair creation event; a future launcher must prove later helper-child
//! ownership through descriptor custody and process-lifetime supervision.
//!
//! A production packet backend is supplied through [`ReceiveSocket`]. The
//! backend must already own a capture descriptor and must revalidate its
//! namespace and ifindex binding before every receive. This crate deliberately
//! does not resolve an interface name or create a raw packet socket: the
//! workspace does not yet contain a safe, reviewed Linux packet-socket binding
//! backend. The explicit backend boundary keeps that missing capability from
//! being mistaken for a stable physical identity.

#![forbid(unsafe_code)]

mod budget;
mod client;
mod error;
mod receiver;
mod reply;
mod server;
mod transport;

pub use budget::{
    BudgetError, MAX_SESSION_BYTES, MAX_SESSION_DURATION, MAX_SESSION_FRAMES, SessionBudget,
    SessionLimits,
};
pub use client::{ClientReply, FrontendClient, MAX_FRONTEND_REPLY_WAIT};
pub use error::{BindingError, HelperError, ReplyError, TransportError};
pub use l2_helper_protocol::{InterfaceBindingRequest, ProtocolError, SessionId};
pub use receiver::{CancellationToken, QueueReceiveSocket, ReceiveSocket};
pub use reply::{
    HelperReply, HelperReplyKind, HelperReplyOwned, MAX_FRAME_BYTES, MAX_IPC_BYTES, ReplyErrorCode,
    decode_reply, encode_reply,
};
pub use server::{HelperConfig, HelperServer, SessionReport, SessionStop};
pub use transport::{
    FrontendTransport, HelperTransport, PeerIdentity, SocketType, local_transport_pair,
};
