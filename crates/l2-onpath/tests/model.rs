// Keep model coverage in one integration crate while grouping related value types
#[path = "model/bindings.rs"]
mod bindings;
#[path = "model/commitments.rs"]
mod commitments;
#[path = "model/identity.rs"]
mod identity;
#[path = "model/plan.rs"]
mod plan;
#[path = "model/types.rs"]
mod types;
