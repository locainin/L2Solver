#![cfg(target_os = "linux")]

#[path = "../../../l2-active/tests/arp/fixture.rs"]
mod arp_fixture;
#[path = "../../src/vlan_assessment/budget.rs"]
mod budget;
#[path = "budget.rs"]
mod budget_tests;
#[path = "../../src/vlan_assessment/decision.rs"]
mod decision;
#[path = "decision.rs"]
mod decision_tests;
#[path = "../../src/vlan_assessment/engine.rs"]
mod engine;
#[path = "engine.rs"]
mod engine_tests;
#[path = "../cli/namespace.rs"]
pub mod namespace;
#[path = "namespace.rs"]
mod namespace_tests;
#[path = "report_fixture.rs"]
mod report_fixture;
#[path = "../../src/vlan_assessment/scope.rs"]
mod scope;
#[path = "scope.rs"]
mod scope_tests;
#[path = "../../../l2-active/tests/support/mod.rs"]
mod support;
