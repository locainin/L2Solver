use super::{load, selected};
use std::{error::Error, io::Write, path::Path};

pub(super) fn run(
    case_path: &Path,
    node_id: u64,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = load(case_path)?;
    let (_, bytes) = selected::bytes(&case, node_id)?;
    output.write_all(bytes)?;
    Ok(case.collection_complete())
}
