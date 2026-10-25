//! Authenticated, bounded Layer-2 canary payloads
//!
//! The crate only builds and verifies a fixed payload. It does not open an
//! interface, send an Ethernet frame, manage a socket, or retain network
//! authority. The surrounding Ethernet header carries [`ETHER_TYPE`]; that
//! value is included in every HMAC transcript to prevent cross-protocol reuse.

#![forbid(unsafe_code)]

mod error;
mod key;
mod model;
mod replay;
mod run_id;
mod wire;

pub use error::{
    AgentIdError, CanaryError, CanaryIdentityError, DecodeError, KeyError, ReplayError,
};
pub use key::{AgentKey, SessionKey};
pub use model::{AgentId, Canary, CanaryIdentity, UnverifiedCanary, VerifiedCanary};
pub use replay::ReplayGuard;
pub use run_id::{RunId, RunIdError};
pub use wire::{encode, verify, verify_for};

/// Experimental `EtherType` assigned to canary payloads
pub const ETHER_TYPE: u16 = 0x88b5;

/// Current fixed wire version
pub const VERSION: u8 = 1;

/// Number of bytes in each agent/run identity
pub const ID_LEN: usize = 16;

/// Number of bytes in the nonce field
pub const NONCE_LEN: usize = 16;

/// Number of bytes in the HMAC-SHA-256 tag
pub const TAG_LEN: usize = 32;

/// Minimum accepted secret-key length
pub const MIN_KEY_LEN: usize = 32;

/// Maximum accepted secret-key length
pub const MAX_KEY_LEN: usize = 64;

/// Maximum distinct replay identities retained by one guard
pub const MAX_REPLAY_IDENTITIES: usize = 1_024;

/// Domain separator included before the `EtherType`, version, and fields
pub const DOMAIN_SEPARATOR: &[u8] = b"l2solver:l2-canary";

/// Offset of the version byte in the authenticated payload
pub const VERSION_OFFSET: usize = 0;

/// Offset of the run identity in the authenticated payload
pub const RUN_ID_OFFSET: usize = 1;

/// Offset of the source-agent identity in the authenticated payload
pub const SOURCE_AGENT_ID_OFFSET: usize = RUN_ID_OFFSET + ID_LEN;

/// Offset of the destination-agent identity in the authenticated payload
pub const DESTINATION_AGENT_ID_OFFSET: usize = SOURCE_AGENT_ID_OFFSET + ID_LEN;

/// Offset of the sequence number in the authenticated payload
pub const SEQUENCE_OFFSET: usize = DESTINATION_AGENT_ID_OFFSET + ID_LEN;

/// Offset of the nonce in the authenticated payload
pub const NONCE_OFFSET: usize = SEQUENCE_OFFSET + core::mem::size_of::<u64>();

/// Number of authenticated bytes before the tag
pub const HEADER_LEN: usize = NONCE_OFFSET + NONCE_LEN;

/// Total payload length, including the HMAC tag
pub const WIRE_LEN: usize = HEADER_LEN + TAG_LEN;
