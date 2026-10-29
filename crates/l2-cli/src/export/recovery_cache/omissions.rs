//! Keep exported omission text charged for its complete lifetime

use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use std::{error::Error, fmt, fmt::Write as _, mem::size_of};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(super) fn collect<T: fmt::Display>(
    entries: impl ExactSizeIterator<Item = Result<T>>,
    budget: Option<&MemoryBudget>,
) -> Result<(Vec<String>, Option<MemoryLease>)> {
    let requested = entries
        .len()
        .checked_mul(size_of::<String>())
        .ok_or("omission vector size overflow")?;
    let requested = u64::try_from(requested)?;
    let mut memory = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, requested))
        .transpose()?;
    let mut values = Vec::new();
    values.try_reserve_exact(entries.len())?;
    let mut retained = values
        .capacity()
        .checked_mul(size_of::<String>())
        .ok_or("omission vector size overflow")?;
    resize(&mut memory, retained)?;

    for entry in entries {
        let entry = entry?;
        // Count before allocating so even a long cached omission needs admission first
        let mut length = TextLength::default();
        write!(&mut length, "{entry}")?;
        let requested = retained
            .checked_add(length.bytes)
            .ok_or("omission text size overflow")?;
        resize(&mut memory, requested)?;
        let mut text = String::new();
        text.try_reserve_exact(length.bytes)?;
        retained = retained
            .checked_add(text.capacity())
            .ok_or("omission text size overflow")?;
        resize(&mut memory, retained)?;
        write!(&mut text, "{entry}")?;
        values.push(text);
    }
    Ok((values, memory))
}

fn resize(memory: &mut Option<MemoryLease>, bytes: usize) -> Result<()> {
    if let Some(memory) = memory {
        memory.try_resize(u64::try_from(bytes)?)?;
    }
    Ok(())
}

#[derive(Default)]
struct TextLength {
    bytes: usize,
}

impl fmt::Write for TextLength {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}
