use std::error::Error;

pub const ENV: &str = "L2_ACTIVE_LINUX_TEST_CHILD";

pub fn selected(expected: &str) -> Result<bool, Box<dyn Error>> {
    match std::env::var_os(ENV) {
        None => Ok(false),
        Some(mode) if mode == expected => Ok(true),
        Some(_) => Err("unexpected namespace fixture child mode".into()),
    }
}
