//! Source-declared Linux identity carried by the standard interface description

use crate::Error;
use l2_capture::LinuxInterfaceIdentity;

const PREFIX: &str = "l2solver:linux-interface:v1:";

pub fn encode(identity: LinuxInterfaceIdentity) -> String {
    format!(
        "{PREFIX}{}:{}:{}:{}:{}",
        identity.namespace_device(),
        identity.namespace_inode(),
        identity.interface_device(),
        identity.interface_inode(),
        identity.ifindex(),
    )
}

pub fn decode(bytes: &[u8]) -> Result<Option<LinuxInterfaceIdentity>, Error> {
    // Ordinary descriptions and unknown versions do not assert a recognized identity
    let Some(suffix) = bytes.strip_prefix(PREFIX.as_bytes()) else {
        return Ok(None);
    };
    let value = std::str::from_utf8(suffix).map_err(|_| Error::InvalidLinuxInterfaceIdentity)?;
    let mut fields = value.split(':');
    let namespace_device = component(fields.next())?;
    let namespace_inode = component(fields.next())?;
    let interface_device = component(fields.next())?;
    let interface_inode = component(fields.next())?;
    let ifindex = u32::try_from(component(fields.next())?)
        .map_err(|_| Error::InvalidLinuxInterfaceIdentity)?;
    if fields.next().is_some() {
        return Err(Error::InvalidLinuxInterfaceIdentity);
    }
    // A saved declaration remains provenance asserted by the source file
    LinuxInterfaceIdentity::new(
        namespace_device,
        namespace_inode,
        interface_device,
        interface_inode,
        ifindex,
    )
    .map(Some)
    .map_err(|_| Error::InvalidLinuxInterfaceIdentity)
}

fn component(value: Option<&str>) -> Result<u64, Error> {
    let value = value.ok_or(Error::InvalidLinuxInterfaceIdentity)?;
    let number = value
        .parse::<u64>()
        .map_err(|_| Error::InvalidLinuxInterfaceIdentity)?;
    // One spelling prevents signs, whitespace, and leading-zero aliases
    if number.to_string() != value {
        return Err(Error::InvalidLinuxInterfaceIdentity);
    }
    Ok(number)
}
