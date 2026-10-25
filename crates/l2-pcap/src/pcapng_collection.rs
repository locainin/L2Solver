//! Fixed-length collection declarations in the standard section comment option

use crate::{CollectionGoal, CollectionReport, CollectionStopReason, Error};

const PREFIX: &str = "l2solver:collection:v1:";

pub fn encode(report: CollectionReport) -> String {
    let stop = match report.stop_reason() {
        CollectionStopReason::Unavailable => 0,
        CollectionStopReason::PacketLimit => 1,
        CollectionStopReason::Deadline => 2,
    };
    let goal = match report.goal() {
        CollectionGoal::Packets => 1,
        CollectionGoal::Duration => 2,
    };
    // Fixed-width fields allow an unpublished file header to be replaced in place
    format!(
        "{PREFIX}{stop}:{goal}:{:010}:{:010}:{:010}:{}",
        report.received(),
        report.capture_dropped(),
        report.interface_dropped(),
        u8::from(report.loss_counters_authoritative())
    )
}

pub fn decode(bytes: &[u8]) -> Result<Option<CollectionReport>, Error> {
    let Some(suffix) = bytes.strip_prefix(PREFIX.as_bytes()) else {
        return Ok(None);
    };
    let value = std::str::from_utf8(suffix).map_err(|_| Error::InvalidCollectionReport)?;
    let mut fields = value.split(':');
    let stop = match fields.next() {
        Some("0") => CollectionStopReason::Unavailable,
        Some("1") => CollectionStopReason::PacketLimit,
        Some("2") => CollectionStopReason::Deadline,
        _ => return Err(Error::InvalidCollectionReport),
    };
    let goal = match fields.next() {
        Some("1") => CollectionGoal::Packets,
        Some("2") => CollectionGoal::Duration,
        _ => return Err(Error::InvalidCollectionReport),
    };
    let received = counter(fields.next())?;
    let capture_dropped = counter(fields.next())?;
    let interface_dropped = counter(fields.next())?;
    let authoritative = match fields.next() {
        Some("0") => false,
        Some("1") => true,
        _ => return Err(Error::InvalidCollectionReport),
    };
    if fields.next().is_some() {
        return Err(Error::InvalidCollectionReport);
    }
    Ok(Some(CollectionReport::new(
        stop,
        goal,
        received,
        capture_dropped,
        interface_dropped,
        authoritative,
    )))
}

fn counter(value: Option<&str>) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidCollectionReport)?;
    let number = value
        .parse::<u32>()
        .map_err(|_| Error::InvalidCollectionReport)?;
    if format!("{number:010}") != value {
        return Err(Error::InvalidCollectionReport);
    }
    Ok(number)
}
