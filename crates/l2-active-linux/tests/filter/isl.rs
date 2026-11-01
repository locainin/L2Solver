use std::error::Error;

use super::super::{MAX_INSTRUCTIONS, Program};

#[test]
fn isl_program_is_bounded_and_finishes_successfully() -> Result<(), Box<dyn Error>> {
    let mut program = Program::new()?;
    super::isl(&mut program);
    let code = program.finish()?;
    assert!(!code.is_empty());
    assert!(code.len() <= MAX_INSTRUCTIONS);
    Ok(())
}
