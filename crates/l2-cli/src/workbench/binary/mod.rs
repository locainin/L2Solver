use super::{input, read_bounded};
use l2_workbench::{artifact, sha256};
use serde_json::json;
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

mod process;

// Signature inputs are independent from the PE and ELF structural-parser budget
const DEFAULT_SIGNATURE_INPUT_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn run(
    path: &Path,
    engine: &str,
    max_input_bytes: Option<usize>,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let maximum = match engine {
        "signatures" => max_input_bytes.unwrap_or(DEFAULT_SIGNATURE_INPUT_BYTES),
        "headers" | "r2" => {
            if max_input_bytes.is_some() {
                return Err("--max-input-bytes applies only to the signatures engine".into());
            }
            artifact::MAX_ARTIFACT_BYTES
        }
        _ => return Err("binary engine must be signatures, headers, or r2".into()),
    };
    let bytes = read_bounded(input::regular(path)?, maximum)?;
    if engine == "signatures" {
        serde_json::to_writer(output, &artifact::scan_file_signatures(&bytes))?;
        return Ok(true);
    }
    let headers = artifact::inspect(&bytes)?;
    let (analysis, diagnostics) = if engine == "r2" {
        let (receipt, diagnostics) = analyze_r2(&bytes)?;
        (Some(receipt), Some(diagnostics))
    } else {
        (None, None)
    };
    let complete = analysis.as_ref().is_none_or(|receipt| receipt.complete);
    serde_json::to_writer(
        output,
        &json!({"headers":headers,"analysis":analysis,"tool_diagnostics":diagnostics,
        "execution":"static_read_only","runtime_packet_or_key_use":"not_established"}),
    )?;
    Ok(complete)
}

fn analyze_r2(bytes: &[u8]) -> Result<(artifact::AnalysisReceipt, String), Box<dyn Error>> {
    let version = process::run(&["-NN".as_ref(), "-v".as_ref()], 4096)?;
    let version = std::str::from_utf8(&version.stdout)?
        .lines()
        .next()
        .ok_or("radare2 did not report a version")?;
    // Parse a private snapshot, so path changes cannot swap the analyzed bytes
    let directory = tempfile::tempdir()?;
    let snapshot = directory.path().join("image.bin");
    let mut file = std::fs::File::create_new(&snapshot)?;
    file.write_all(bytes)?;
    file.flush()?;
    drop(file);
    let result = process::run(
        &[
            "-NN".as_ref(),
            "-S".as_ref(),
            "-x".as_ref(),
            "-q".as_ref(),
            "-e".as_ref(),
            "scr.color=false".as_ref(),
            "-e".as_ref(),
            "scr.utf8=false".as_ref(),
            "-e".as_ref(),
            "scr.interactive=false".as_ref(),
            "-c".as_ref(),
            "aaa;iej;aflj;iij;axlj".as_ref(),
            snapshot.as_os_str(),
        ],
        artifact::MAX_R2_JSON_BYTES,
    )?;
    let arrays = json_arrays(&result.stdout)?;
    let [entrypoints, functions, imports, xrefs] = arrays;
    let receipt = artifact::import_r2_json(
        bytes,
        &sha256(bytes),
        version,
        entrypoints,
        functions,
        imports,
        xrefs,
    )?;
    Ok((
        receipt,
        String::from_utf8_lossy(&result.stderr).into_owned(),
    ))
}

fn json_arrays(bytes: &[u8]) -> Result<[&[u8]; 4], io::Error> {
    let arrays: Vec<_> = bytes
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| line.starts_with(b"["))
        .collect();
    arrays.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "radare2 must return exactly four line-separated JSON arrays",
        )
    })
}
