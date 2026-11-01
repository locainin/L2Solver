use super::{BudgetedMessage, format_message};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
use std::{error::Error, fmt, fmt::Write};

struct Fragments;

impl fmt::Display for Fragments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..4 {
            formatter
                .write_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        }
        formatter.write_str("b")
    }
}

#[test]
fn formatted_message_growth_requires_both_live_buffers_to_fit() -> Result<(), Box<dyn Error>> {
    const LIMIT: u64 = 1024 * 1024;
    let memory = MemoryBudget::new(LIMIT);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut message = BudgetedMessage {
        value: String::new(),
        memory: &mut lease,
        error: None,
    };
    let input = [b'a'; 64];
    let prefix = std::str::from_utf8(&input)?;
    message
        .write_str(prefix)
        .map_err(|_| "initial formatting failed")?;
    let old = message.value.capacity();
    let fill = "x".repeat(old - message.value.len());
    message
        .write_str(&fill)
        .map_err(|_| "filling the initial buffer failed")?;
    let previous = message.value.clone();
    let required = u64::try_from(old.checked_mul(3).ok_or("capacity overflow")?)?;
    let blocker = memory.try_reserve(MemoryClass::Executor, LIMIT - required + 1)?;
    assert!(message.write_str("b").is_err());
    assert!(matches!(
        message
            .error
            .as_ref()
            .and_then(|error| crate::memory_error::find(error.as_ref())),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(message.value, previous);
    drop(message);
    assert_eq!(lease.bytes(), u64::try_from(old)?);
    drop(blocker);
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_formatting_releases_only_its_message_charge() -> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(198);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 7)?;
    let error = format_message(format_args!("{Fragments}"), &mut lease)
        .expect_err("overlapping message buffers must exceed the limit");
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(lease.bytes(), 7);
    assert_eq!(memory.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn successful_formatting_charges_the_overlap_then_keeps_only_the_result()
-> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(2048);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 7)?;
    let value = format_message(format_args!("{Fragments}"), &mut lease)?;
    assert_eq!(value.len(), 257);
    assert!(value.ends_with('b'));
    assert_eq!(lease.bytes(), 7 + u64::try_from(value.capacity())?);
    drop(value);
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn successful_growth_records_both_live_buffers_at_peak() -> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(1024 * 1024);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 7)?;
    let mut message = BudgetedMessage {
        value: String::new(),
        memory: &mut lease,
        error: None,
    };
    message.write_str("a").map_err(|_| "initial write failed")?;
    let old = message.value.capacity();
    let fill = "x".repeat(old - message.value.len());
    message.write_str(&fill).map_err(|_| "fill failed")?;
    message.write_str("b").map_err(|_| "growth failed")?;
    let new = message.value.capacity();
    assert!(memory.snapshot()?.peak_bytes >= 7 + u64::try_from(old + new)?);
    drop(message);
    assert_eq!(lease.bytes(), 7 + u64::try_from(new)?);
    Ok(())
}
