use std::io;

/// A named interface explicitly selected by the operator
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceSelector(String);

impl InterfaceSelector {
    /// Check the Linux kernel's interface-name rules without opening an interface
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty, reserved, overlong, or invalid name
    pub fn new(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() >= 16
            || name == "."
            || name == ".."
            || name
                .bytes()
                .any(|byte| byte == 0 || byte == b'/' || byte == b':' || byte.is_ascii_whitespace())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Linux interface name",
            ));
        }
        Ok(Self(name.to_owned()))
    }

    /// Borrow the exact name that was selected
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}
