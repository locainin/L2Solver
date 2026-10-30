//! Parse the offer options needed for source and transaction correlation

use std::net::Ipv4Addr;

const MAGIC_END: usize = 240;
const SERVER_NAME: std::ops::Range<usize> = 44..108;
const BOOT_FILE: std::ops::Range<usize> = 108..236;
const MAX_OPTIONS: usize = 128;

#[derive(Default)]
struct Fields {
    kind: Option<u8>,
    server: Option<Ipv4Addr>,
    lease_seconds: Option<u32>,
    overload: Option<u8>,
    count: usize,
}

/// Extract required offer fields while rejecting ambiguous or truncated options
pub(super) fn offer(payload: &[u8]) -> Option<(Ipv4Addr, u32)> {
    let mut fields = Fields::default();
    scan(payload.get(MAGIC_END..)?, &mut fields, true)?;
    scan_overloaded(payload, &mut fields)?;
    if fields.kind != Some(2) {
        return None;
    }
    Some((fields.server?, fields.lease_seconds?))
}

// The option value selects which fixed BOOTP fields contain extra options
fn scan_overloaded(payload: &[u8], fields: &mut Fields) -> Option<()> {
    if fields.overload.is_some_and(|value| value & 1 != 0) {
        scan(payload.get(BOOT_FILE)?, fields, false)?;
    }
    if fields.overload.is_some_and(|value| value & 2 != 0) {
        scan(payload.get(SERVER_NAME)?, fields, false)?;
    }
    Some(())
}

fn scan(mut bytes: &[u8], fields: &mut Fields, primary: bool) -> Option<()> {
    while let Some((&kind, rest)) = bytes.split_first() {
        bytes = rest;
        if kind == 0 {
            continue;
        }
        if kind == 255 {
            return Some(());
        }
        fields.count += 1;
        if fields.count > MAX_OPTIONS {
            return None;
        }
        let (&len, rest) = bytes.split_first()?;
        let (value, rest) = rest.split_at_checked(usize::from(len))?;
        bytes = rest;
        record(fields, kind, value, primary)?;
    }
    None
}

fn record(fields: &mut Fields, kind: u8, value: &[u8], primary: bool) -> Option<()> {
    match kind {
        53 => {
            let [message] = value else { return None };
            store(&mut fields.kind, *message)
        }
        54 => store(
            &mut fields.server,
            Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?),
        ),
        51 => store(
            &mut fields.lease_seconds,
            u32::from_be_bytes(value.try_into().ok()?),
        ),
        52 if primary => {
            let [overload @ 1..=3] = value else {
                return None;
            };
            store(&mut fields.overload, *overload)
        }
        52 => None,
        _ => Some(()),
    }
}

// A repeated required option is ambiguous, even when its value agrees
fn store<T>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(value);
    Some(())
}
