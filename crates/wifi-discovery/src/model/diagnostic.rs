//! Bounded diagnostic records emitted while decoding captures

use serde::{Deserialize, Serialize};

/// Parser layer that produced a diagnostic
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticKind {
    Capture,
    Radiotap,
    WifiMac,
    Management,
    Security,
    Inventory,
}

/// Bounded quality diagnostic tied to one capture sequence
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    sequence: u64,
    kind: DiagnosticKind,
    message: String,
}

impl Diagnostic {
    pub(crate) const fn new(sequence: u64, kind: DiagnosticKind, message: String) -> Self {
        Self {
            sequence,
            kind,
            message,
        }
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn kind(&self) -> DiagnosticKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
