use super::{input, label};
use l2_pcap::{CaptureLimits, CaptureSource};
use l2_workbench::{
    investigation::{self, BuildInput, Record},
    reconstruction::Limits,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Read, Write},
    path::Path,
};

#[cfg(test)]
#[path = "../../tests/workbench/hashing.rs"]
mod tests;

pub(super) fn run(
    path: &Path,
    limits: Limits,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let result = build(path, limits)?;
    result.case.write_json(output)?;
    if !result.complete {
        incomplete_diagnostics(&result)?;
    }
    Ok(result.complete)
}

pub fn build(path: &Path, limits: Limits) -> Result<investigation::BuildResult, Box<dyn Error>> {
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut records = Vec::new();
    let mut frames_seen = 0_u32;
    let mut retained_bytes = 0;
    let mut frozen = false;
    let quality = {
        let reader = HashingReader {
            inner: input::capture(path)?,
            hash: &mut hash,
            length: &mut length,
        };
        let mut capture = CaptureSource::with_limits(reader, CaptureLimits::STREAMING)
            .map_err(|error| input::capture_error(path, error))?;
        while let Some(frame) = capture
            .next_packet()
            .map_err(|error| input::capture_error(path, error))?
        {
            frames_seen = frames_seen
                .checked_add(1)
                .ok_or("capture record count exceeds 32-bit numbering")?;
            // Freeze the prefix after a skipped frame while still validating the source to EOF
            if frozen
                || u64::from(frames_seen) > limits.frames
                || frame.bytes().len() > limits.bytes - retained_bytes
            {
                frozen = true;
                continue;
            }
            retained_bytes += frame.bytes().len();
            records.push(Record {
                number: frames_seen,
                frame,
            });
        }
        capture.collection_summary()
    };
    // Hash finalization follows clean EOF, including records omitted from analysis
    let digest = format!("{:x}", hash.finalize());
    let mut result = investigation::build_with_limits(
        BuildInput {
            label: label(path, "capture"),
            length,
            sha256_hex: &digest,
            records: &records,
            frames_seen: u64::from(frames_seen),
        },
        limits,
    )?;
    let source = format!("sha256:{digest}");
    l2_workbench::capture_collection::apply_to_case(&mut result, &source, quality)?;
    Ok(result)
}

fn incomplete_diagnostics(result: &investigation::BuildResult) -> Result<(), Box<dyn Error>> {
    // Count published packet nodes because evidence quotas can bind after reconstruction
    let retained = u64::try_from(
        result
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "packet")
            .count(),
    )?;
    let frames_seen = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .and_then(|node| node.details.get("frames_seen"))
        .and_then(serde_json::Value::as_u64)
        .ok_or("capture summary is missing the source record count")?;
    let omitted = frames_seen
        .checked_sub(retained)
        .ok_or("retained packet count exceeds source record count")?;
    let mut diagnostics = io::stderr().lock();
    // Diagnostic delivery cannot discard a valid case or change its incomplete outcome
    let _ = writeln!(
        diagnostics,
        "workbench build is incomplete: retained {retained} of {frames_seen} capture records as packet evidence ({omitted} omitted)"
    );
    let _ = writeln!(
        diagnostics,
        "Case limitations describe incomplete collection or analysis; larger --max-* budgets can still reach other evidence or application limits"
    );
    let _ = writeln!(
        diagnostics,
        "Use workbench index CAPTURE --directory NEW_DIRECTORY to preserve all original packets, or workbench stream CAPTURE --directory NEW_DIRECTORY to analyze every record in bounded windows"
    );
    Ok(())
}

pub(super) struct HashingReader<'a, R> {
    pub inner: R,
    pub hash: &'a mut Sha256,
    pub length: &'a mut u64,
}
impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // CaptureSource owns the input budget; this wrapper only records bytes read
        let count = self.inner.read(buffer)?;
        let bytes = buffer
            .get(..count)
            .ok_or_else(|| io::Error::other("reader returned an invalid byte count"))?;
        self.hash.update(bytes);
        *self.length = self
            .length
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("capture source length overflow"))?;
        Ok(count)
    }
}
