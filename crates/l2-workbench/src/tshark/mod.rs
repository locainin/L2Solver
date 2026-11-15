//! Shared report model for `TShark` production and journal imports

mod model;

pub use model::{
    BudgetReceipt, Diagnostic, EnrichedPacket, InvocationReceipt, PacketCountReceipt, PluginRecord,
    ProfileReceipt, Provenance, ScopeReceipt, ScopeUsage, SourceIdentity, ToolReceipt,
    TsharkFrameObservation, TsharkReport,
};
