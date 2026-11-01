//! Admit retained vectors and strings before allocating their storage

use l2_workbench::job::MemoryLease;
use std::error::Error;

pub(crate) fn grow_vec_optional<T>(
    values: &mut Vec<T>,
    memory: &mut Option<MemoryLease>,
    additional: usize,
) -> Result<(), Box<dyn Error>> {
    if let Some(memory) = memory {
        grow_vec(values, memory, additional)
    } else {
        values.try_reserve(additional)?;
        Ok(())
    }
}

pub(crate) fn copy_optional(
    value: &str,
    memory: &mut Option<MemoryLease>,
) -> Result<String, Box<dyn Error>> {
    if let Some(memory) = memory {
        copy_message(value, memory)
    } else {
        let mut copy = String::new();
        copy.try_reserve_exact(value.len())?;
        copy.push_str(value);
        Ok(copy)
    }
}

pub(crate) fn grow_vec_exact_optional<T>(
    values: &mut Vec<T>,
    memory: &mut Option<MemoryLease>,
    additional: usize,
) -> Result<(), Box<dyn Error>> {
    if let Some(memory) = memory {
        grow_vec_exact(values, memory, additional)
    } else {
        values.try_reserve_exact(additional)?;
        Ok(())
    }
}

pub(crate) fn charge(memory: &mut MemoryLease, bytes: usize) -> Result<(), Box<dyn Error>> {
    let total = memory
        .bytes()
        .checked_add(u64::try_from(bytes)?)
        .ok_or("retained memory size overflows")?;
    memory.try_resize(total)?;
    Ok(())
}

pub(crate) fn grow_vec<T>(
    values: &mut Vec<T>,
    memory: &mut MemoryLease,
    additional: usize,
) -> Result<(), Box<dyn Error>> {
    let needed = values
        .len()
        .checked_add(additional)
        .ok_or("retained vector size overflows")?;
    if needed <= values.capacity() {
        return Ok(());
    }
    let wanted = values.capacity().saturating_mul(2).max(4).max(needed);
    grow_vec_to(values, memory, wanted)
}

pub(crate) fn grow_vec_exact<T>(
    values: &mut Vec<T>,
    memory: &mut MemoryLease,
    additional: usize,
) -> Result<(), Box<dyn Error>> {
    let needed = values
        .len()
        .checked_add(additional)
        .ok_or("retained vector size overflows")?;
    if needed <= values.capacity() {
        return Ok(());
    }
    grow_vec_to(values, memory, needed)
}

fn grow_vec_to<T>(
    values: &mut Vec<T>,
    memory: &mut MemoryLease,
    wanted: usize,
) -> Result<(), Box<dyn Error>> {
    let old = values
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .ok_or("retained vector capacity overflows")?;
    let requested = wanted
        .checked_mul(std::mem::size_of::<T>())
        .ok_or("retained vector capacity overflows")?;
    let before = memory.bytes();
    // The new allocation is admitted while the old vector is still live
    charge(memory, requested)?;
    let mut next = Vec::new();
    if let Err(error) = next.try_reserve_exact(wanted) {
        drop(next);
        memory.try_resize(before)?;
        return Err(Box::new(error));
    }
    let admitted = next
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| before.checked_add(bytes));
    let Some(admitted) = admitted else {
        drop(next);
        memory.try_resize(before)?;
        return Err("retained vector memory overflows".into());
    };
    if let Err(error) = memory.try_resize(admitted) {
        drop(next);
        memory.try_resize(before)?;
        return Err(Box::new(error));
    }
    next.append(values);
    *values = next;
    let remaining = admitted
        .checked_sub(u64::try_from(old)?)
        .ok_or("retained vector charge is inconsistent")?;
    memory.try_resize(remaining)?;
    Ok(())
}

pub(crate) fn copy_message(
    value: &str,
    memory: &mut MemoryLease,
) -> Result<String, Box<dyn Error>> {
    let before = memory.bytes();
    charge(memory, value.len())?;
    let mut copy = String::new();
    if let Err(error) = copy.try_reserve_exact(value.len()) {
        drop(copy);
        memory.try_resize(before)?;
        return Err(Box::new(error));
    }
    let admitted = u64::try_from(copy.capacity())
        .ok()
        .and_then(|bytes| before.checked_add(bytes));
    let Some(admitted) = admitted else {
        drop(copy);
        memory.try_resize(before)?;
        return Err("retained string memory overflows".into());
    };
    if let Err(error) = memory.try_resize(admitted) {
        drop(copy);
        memory.try_resize(before)?;
        return Err(Box::new(error));
    }
    copy.push_str(value);
    Ok(copy)
}
