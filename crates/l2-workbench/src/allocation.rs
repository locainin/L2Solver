//! Shared logical models for owned container storage

mod vector;

pub(crate) use vector::{
    Metered, Unrestricted, VectorAdmission, VectorAllocationError, reserve_one_with_memory,
};

/// One Rust 1.96 `BTreeMap` node, including unused slots and internal child pointers
pub fn btree_node_bytes<K, V>() -> Option<usize> {
    let slots = 11_usize.checked_mul(size_of::<(K, V)>())?;
    let header = 14_usize.checked_mul(size_of::<usize>())?;
    slots.checked_add(header)
}
