//! Fixed collection and resource limits for on-path plans

/// Maximum controlled endpoints in one on-path session
pub const MAX_ENDPOINTS: usize = 64;

/// Number of bounded checks available in this release
pub const MAX_CHECKS: usize = 22;

/// Maximum bounded protocol stimuli in one on-path session
pub const MAX_STIMULI: usize = 256;

/// Maximum authenticated canary expectations in one on-path session
pub const MAX_CANARIES: usize = 256;

/// Maximum exact transmit commitments implied by all planned transmit slots
pub const MAX_COMMITMENTS: usize = MAX_STIMULI + MAX_CANARIES + MAX_ENDPOINTS;

/// Maximum packets allowed by one descriptor budget
pub const MAX_PACKET_BUDGET: u64 = 4_096;

/// Maximum bytes allowed by one descriptor budget
pub const MAX_BYTE_BUDGET: u64 = 1_048_576;

/// Maximum duration allowed by one descriptor budget, in milliseconds
pub const MAX_DURATION_BUDGET_MILLIS: u64 = 300_000;
