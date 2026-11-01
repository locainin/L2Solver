use std::error::Error;

use super::super::scope_tests as shared;

fn program() -> std::io::Result<Vec<rscap::filter::BpfInstruction>> {
    shared::program(|program| super::mpls(program, [2, 0, 0, 0, 0, 1]))
}

#[test]
fn mpls_filter_produces_a_bounded_forward_only_program() -> Result<(), Box<dyn Error>> {
    let instructions = program()?;
    assert!(!instructions.is_empty());
    assert!(instructions.len() <= super::super::MAX_INSTRUCTIONS);
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn mpls_filter_accepts_the_local_endpoint_and_rejects_other_scopes() -> Result<(), Box<dyn Error>> {
    shared::run_fixture("mpls", "filter::mpls::tests::mpls_child")
}

#[test]
#[ignore = "invoked only inside the proved private filter fixture"]
fn mpls_child() -> Result<(), Box<dyn Error>> {
    shared::check_child(program()?)
}
