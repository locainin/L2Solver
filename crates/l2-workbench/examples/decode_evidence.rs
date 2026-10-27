//! Stream a published gzip sidecar into canonical version-two JSON Lines

use flate2::read::MultiGzDecoder;
use l2_workbench::evidence::{PublishedEvidenceLimits, decode_published_evidence};
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let version = args
        .next()
        .ok_or("expected evidence encoding version")?
        .to_str()
        .ok_or("encoding version is not UTF-8")?
        .parse::<u32>()?;
    let path = args.next().ok_or("expected gzip evidence path")?;
    if args.next().is_some() {
        return Err("expected only an encoding version and gzip evidence path".into());
    }
    let input = BufReader::new(MultiGzDecoder::new(File::open(path)?));
    let mut output = BufWriter::new(io::stdout().lock());
    decode_published_evidence(
        version,
        input,
        &mut output,
        PublishedEvidenceLimits::new(u64::MAX, 64 * 1024 * 1024),
    )?;
    output.flush()?;
    Ok(())
}
