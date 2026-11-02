use std::error::Error;

use super::super::{MAX_INSTRUCTIONS, Program};

#[test]
fn isl_program_is_bounded_and_finishes_successfully() -> Result<(), Box<dyn Error>> {
    let mut program = Program::new()?;
    super::isl(&mut program);
    let code = program.finish()?;
    assert_ne!(code, [] as [rscap::filter::BpfInstruction; 0]);
    assert!(code.len() <= MAX_INSTRUCTIONS);
    Ok(())
}
