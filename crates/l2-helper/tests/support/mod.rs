use std::error::Error;
use std::io::ErrorKind;

use l2_helper::{FrontendTransport, HelperTransport, TransportError, local_transport_pair};

/// Return a socketpair when the test runner permits `AF_UNIX` syscalls
///
/// The managed development sandbox denies socket creation with `EPERM`. The
/// elevated focused run exercises the same tests with real Linux sockets; a
/// default sandbox run skips only that environmental limitation.
pub fn pair() -> Result<Option<(FrontendTransport, HelperTransport)>, Box<dyn Error>> {
    match local_transport_pair() {
        Ok(pair) => Ok(Some(pair)),
        Err(TransportError::Io(error)) if error.kind() == ErrorKind::PermissionDenied => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}
