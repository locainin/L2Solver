//! Preserve typed memory failures across error-wrapping boundaries

use l2_workbench::job::MemoryError;
use std::{error::Error, io};

/// Find a shared-budget failure without relying on display text
pub fn find(error: &(dyn Error + 'static)) -> Option<MemoryError> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(memory) = cause.downcast_ref::<MemoryError>() {
            return Some(*memory);
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
