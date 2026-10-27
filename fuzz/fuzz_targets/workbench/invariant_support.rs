// Keep failed fuzz invariants visible as process crashes
pub fn require(condition: bool) {
    if !condition {
        fail();
    }
}

// A missing expected value means the harness assumptions no longer hold
pub fn fail() -> ! {
    std::process::abort()
}
