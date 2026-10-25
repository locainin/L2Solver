// The integration test is split by planner behavior so each module has one
// reason to change and failure output stays easy to scan
#[path = "planner/catalog.rs"]
mod catalog;
#[path = "planner/policy.rs"]
mod policy;
#[path = "planner/profiles.rs"]
mod profiles;
#[path = "planner/requirements.rs"]
mod requirements;
#[path = "planner/stp.rs"]
mod stp;
#[path = "planner/support.rs"]
mod support;
