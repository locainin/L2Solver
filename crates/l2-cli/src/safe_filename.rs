//! Shared checks for artifact names written as flat files

pub fn is_safe_flat_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && !matches!(file_name, "." | "..")
        && !file_name.contains(['/', '\\'])
        && !file_name.chars().any(char::is_control)
}
