//! Preserve typed memory failures across error-wrapping boundaries

use l2_workbench::job::MemoryError;
use std::error::Error;

/// Find a shared-budget failure without relying on display text
pub fn find(error: &(dyn Error + 'static)) -> Option<MemoryError> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(memory) = cause.downcast_ref::<MemoryError>() {
            return Some(*memory);
        }
        current = cause.source();
    }
    None
}
