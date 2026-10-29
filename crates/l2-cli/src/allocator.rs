//! Release unused allocator pages between recovery Cases

// Retaining freed arena pages would consume headroom after their Case leases have ended
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(test)]
#[path = "../tests/allocator/configuration.rs"]
mod tests;
