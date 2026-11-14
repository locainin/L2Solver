//! Bounded collection of PCAPNG interface loss snapshots

use crate::{
    CollectionSummary, Error,
    header::ByteOrder,
    pcapng_blocks::{BLOCK_TRAILER_LENGTH, INTERFACE_STATISTICS_BLOCK, read_u32, read_u64},
    pcapng_options::{OptionScope, parse_options},
};

const MIN_LENGTH: usize = 24;

#[derive(Clone, Copy, Default)]
pub struct Statistics {
    interface_dropped: Option<u64>,
    os_dropped: Option<u64>,
}

pub fn decode(bytes: &[u8], order: ByteOrder) -> Result<(u32, Statistics), Error> {
    if bytes.len() < MIN_LENGTH {
        return Err(Error::InvalidBlockLength {
            block_type: INTERFACE_STATISTICS_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }
    let interface = read_u32(bytes, 8, order)?;
    let body_end = bytes.len() - BLOCK_TRAILER_LENGTH;
    let options = parse_options(
        INTERFACE_STATISTICS_BLOCK,
        bytes.get(20..body_end).ok_or(Error::InvalidHeaderLayout)?,
        OptionScope::InterfaceStatistics,
        order,
    )?;
    let mut statistics = Statistics::default();
    for option in options {
        match option.code {
            5 => statistics.interface_dropped = Some(read_u64(&option.value, 0, order)?),
            7 => statistics.os_dropped = Some(read_u64(&option.value, 0, order)?),
            _ => {}
        }
    }
    Ok((interface, statistics))
}

pub fn observe(
    summary: &mut CollectionSummary,
    previous: &mut Statistics,
    current: Statistics,
) -> Result<(), Error> {
    // Snapshots are cumulative, so retain only each interface's highest value
    let (interface_total, interface_max) = update(
        summary.interface_statistics_interface_dropped,
        previous.interface_dropped,
        current.interface_dropped,
    )?;
    let (os_total, os_max) = update(
        summary.interface_statistics_os_dropped,
        previous.os_dropped,
        current.os_dropped,
    )?;
    summary.interface_statistics_interface_dropped = interface_total;
    summary.interface_statistics_os_dropped = os_total;
    previous.interface_dropped = interface_max;
    previous.os_dropped = os_max;
    Ok(())
}

fn update(
    total: Option<u64>,
    previous: Option<u64>,
    current: Option<u64>,
) -> Result<(Option<u64>, Option<u64>), Error> {
    let Some(current) = current else {
        return Ok((total, previous));
    };
    let maximum = previous.map_or(current, |old| old.max(current));
    let difference = maximum - previous.unwrap_or(0);
    let total = total
        .unwrap_or(0)
        .checked_add(difference)
        .ok_or(Error::LossCounterOverflow)?;
    Ok((Some(total), Some(maximum)))
}
