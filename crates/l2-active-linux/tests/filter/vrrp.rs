use std::{error::Error, num::NonZeroU8};

use super::super::scope_tests as shared;

fn program(vrid: Option<NonZeroU8>) -> std::io::Result<Vec<rscap::filter::BpfInstruction>> {
    shared::program(|program| super::vrrp(program, vrid))
}

#[test]
fn vrrp_filters_produce_bounded_forward_only_programs() -> Result<(), Box<dyn Error>> {
    for selected in [None, NonZeroU8::new(42)] {
        let instructions = program(selected)?;
        assert!(!instructions.is_empty());
        assert!(instructions.len() <= super::super::MAX_INSTRUCTIONS);
    }
    Ok(())
}

#[test]
#[ignore = "uses a proved private namespace and owned veth pair"]
fn vrrp_filter_accepts_scoped_v3_and_rejects_v2_or_unrelated_frames() -> Result<(), Box<dyn Error>>
{
    shared::run_fixture("vrrp-any", "filter::vrrp::tests::vrrp_any_child")?;
    shared::run_fixture("vrrp-42", "filter::vrrp::tests::vrrp_42_child")
}

#[test]
#[ignore = "invoked only inside the proved private filter fixture"]
fn vrrp_any_child() -> Result<(), Box<dyn Error>> {
    shared::check_child(program(None)?)
}

#[test]
#[ignore = "invoked only inside the proved private filter fixture"]
fn vrrp_42_child() -> Result<(), Box<dyn Error>> {
    shared::check_child(program(NonZeroU8::new(42))?)
}
