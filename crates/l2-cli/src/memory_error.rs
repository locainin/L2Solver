//! Preserve typed memory failures across error-wrapping boundaries

use l2_workbench::job::MemoryError;
use std::{error::Error, io};

/// Find a shared-budget failure without relying on display text
pub fn find(error: &(dyn Error + 'static)) -> Option<MemoryError> {
    find_map(error, |cause| cause.downcast_ref::<MemoryError>().copied())
}

pub fn any_cause(
    error: &(dyn Error + 'static),
    mut predicate: impl FnMut(&(dyn Error + 'static)) -> bool,
) -> bool {
    find_map(error, |cause| predicate(cause).then_some(())).is_some()
}

pub fn find_map<T>(
    error: &(dyn Error + 'static),
    mut inspect: impl FnMut(&(dyn Error + 'static)) -> Option<T>,
) -> Option<T> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(value) = inspect(cause) {
            return Some(value);
        }
        // io::Error can hold the typed error without exposing it as its source
        current = cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .map(|inner| inner as &(dyn Error + 'static))
            .or_else(|| cause.source());
    }
    None
}
