use flate2::{Compression, write::GzEncoder, write::ZlibEncoder};
use l2_workbench::derivation::{DerivationReport, Operation, Recipe, run};
use std::{error::Error, io::Write};

pub const fn recipe(steps: Vec<Operation>) -> Recipe {
    Recipe {
        steps,
        constraints: Vec::new(),
    }
}

pub fn run_steps(input: &[u8], steps: Vec<Operation>) -> Result<DerivationReport, Box<dyn Error>> {
    Ok(run(input, &recipe(steps))?)
}

pub fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

pub fn zlib(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}
