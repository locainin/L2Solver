// Keep state coverage in one integration crate while grouping each behavior
#[path = "state/budget.rs"]
mod budget;
#[path = "state/evaluation.rs"]
mod evaluation;
#[path = "state/gates.rs"]
mod gates;
#[path = "state/lifecycle_evidence.rs"]
mod lifecycle_evidence;
#[path = "state/receipts.rs"]
mod receipts;
#[path = "state/support.rs"]
mod support;
#[path = "state/transitions.rs"]
mod transitions;
#[path = "state/wire.rs"]
mod wire;
