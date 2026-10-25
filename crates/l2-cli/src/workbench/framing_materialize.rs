//! Materialize byte ranges under one explicitly selected framing rule

#[cfg(test)]
#[path = "../../tests/workbench/framing_service.rs"]
mod service_tests;

mod service;

#[cfg(test)]
pub(super) use service::FramingOutcome;
pub(super) use service::PreparedFraming;
pub(super) use service::commit_recovery;
pub(super) use service::{FramingSelectionBasis, apply, apply_with_basis};
pub(super) use service::{prepare_recovery_with_basis, validate_cli_discovered_rule};

use super::load;
use crate::arguments::MaterializeFramesArgs;
use l2_workbench::protocol::{self, BoundaryStatus, FramingKind};
use std::{error::Error, io::Write};

pub(super) fn run(
    args: &MaterializeFramesArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    let rule = parse_rule(args)?;
    let outcome = match args.discovery_report {
        Some(report_node) => {
            validate_cli_discovered_rule(&case, report_node, &rule)?;
            apply_with_basis(
                &mut case,
                args.node,
                &rule,
                FramingSelectionBasis::CallerAndDiscovered { report_node },
            )?
        }
        None => apply(&mut case, args.node, &rule)?,
    };
    let complete = outcome.status == BoundaryStatus::Complete && case.collection_complete();
    case.write_json(output)?;
    Ok(complete)
}

fn parse_rule(args: &MaterializeFramesArgs) -> Result<FramingKind, Box<dyn Error>> {
    if let Some(byte) = args.delimiter_byte {
        return Ok(FramingKind::Delimiter { byte });
    }
    if let Some(bytes) = args.fixed_size {
        return Ok(FramingKind::FixedSize { bytes: bytes.get() });
    }
    if let Some(prefix) = args.length_prefix.as_deref() {
        return parse_length_prefix(prefix);
    }
    if let Some(rule) = args.rule_json.as_deref() {
        return Ok(serde_json::from_str(rule)?);
    }
    Err("select one framing rule".into())
}

fn parse_length_prefix(value: &str) -> Result<FramingKind, Box<dyn Error>> {
    let mut fields = value.split(':');
    let offset = fields
        .next()
        .ok_or("length prefix requires OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING")?
        .parse::<usize>()?;
    let width = fields
        .next()
        .ok_or("length prefix requires OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING")?
        .parse::<usize>()?;
    let byte_order = match fields
        .next()
        .ok_or("length prefix requires OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING")?
    {
        "big_endian" => protocol::ByteOrder::BigEndian,
        "little_endian" => protocol::ByteOrder::LittleEndian,
        _ => return Err("byte order must be big_endian or little_endian".into()),
    };
    let meaning = match fields
        .next()
        .ok_or("length prefix requires OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING")?
    {
        "whole_message" => protocol::LengthMeaning::WholeMessage,
        "bytes_after_field" => protocol::LengthMeaning::BytesAfterField,
        _ => return Err("length meaning must be whole_message or bytes_after_field".into()),
    };
    if fields.next().is_some() {
        return Err("length prefix has extra fields".into());
    }
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err("length prefix width must be 1, 2, 4, or 8".into());
    }
    Ok(FramingKind::LengthPrefix {
        offset,
        width,
        byte_order,
        meaning,
    })
}
