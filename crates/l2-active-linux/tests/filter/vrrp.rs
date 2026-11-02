use std::{error::Error, num::NonZeroU8};

use super::super::scope_tests as shared;

fn program(vrid: Option<NonZeroU8>) -> std::io::Result<Vec<rscap::filter::BpfInstruction>> {
    shared::program(|program| super::vrrp(program, vrid))
}

const PARENT_TEST: &str =
    "filter::vrrp::tests::vrrp_filter_accepts_scoped_v3_and_rejects_v2_or_unrelated_frames";

#[test]
fn vrrp_filters_produce_bounded_forward_only_programs() -> Result<(), Box<dyn Error>> {
    for selected in [None, NonZeroU8::new(42)] {
        let instructions = program(selected)?;
        assert_ne!(instructions, [] as [rscap::filter::BpfInstruction; 0]);
        assert!(instructions.len() <= super::super::MAX_INSTRUCTIONS);
    }
    Ok(())
}

#[test]
fn vrrp_filter_accepts_scoped_v3_and_rejects_v2_or_unrelated_frames() -> Result<(), Box<dyn Error>>
{
    if let Some(mode) = std::env::var_os(crate::child_mode::ENV) {
        if mode == "vrrp-any" {
            return vrrp_any_child();
        }
        if mode == "vrrp-42" {
            return vrrp_42_child();
        }
        return Err("unexpected VRRP filter child mode".into());
    }
    shared::run_fixture("vrrp-any", PARENT_TEST)?;
    shared::run_fixture("vrrp-42", PARENT_TEST)
}

fn vrrp_any_child() -> Result<(), Box<dyn Error>> {
    shared::check_child(program(None)?)
}

fn vrrp_42_child() -> Result<(), Box<dyn Error>> {
    shared::check_child(program(NonZeroU8::new(42))?)
}
