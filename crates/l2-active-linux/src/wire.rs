use std::io;

#[cfg(test)]
#[path = "../tests/wire/codec.rs"]
mod tests;

pub const OPEN: u8 = 1;
// Version 9 binds each operation to its sampled VLAN and parent identity
pub const VERSION: u8 = 9;
pub const SEND: u8 = 2;
pub const RECEIVE: u8 = 3;
pub const LOSS: u8 = 4;
pub const CLOSE: u8 = 5;
pub const PRE_SEND: u8 = 6;
pub const BACKLOG: u8 = 7;
pub const OK: u8 = 10;
pub const FRAME: u8 = 11;
pub const TIMEOUT: u8 = 12;
pub const CANCELLED: u8 = 13;
pub const DOWN: u8 = 14;
pub const STATS: u8 = 15;
pub const FINAL_TIMEOUT: u8 = 16;
pub const USAGE: u8 = 17;
pub const BACKLOG_RESULT: u8 = 18;
pub const ERROR: u8 = 255;
pub const MAX_RECORD: usize = l2_capture::MAX_FRAME_LENGTH + 128;

pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new(opcode: u8) -> Self {
        Self(vec![opcode])
    }
    pub fn with_capacity(opcode: u8, capacity: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        bytes.push(opcode);
        Ok(Self(bytes))
    }
    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }
    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    pub fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(invalid_record)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(invalid_record)?;
        self.offset = end;
        Ok(bytes)
    }
    pub fn u8(&mut self) -> io::Result<u8> {
        self.take(1)?.first().copied().ok_or_else(invalid_record)
    }
    pub fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| invalid_record())?,
        ))
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid_record())?,
        ))
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid_record())?,
        ))
    }
    pub fn rest(&mut self) -> io::Result<&'a [u8]> {
        self.take(self.bytes.len() - self.offset)
    }
    pub fn finish(self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid_record())
        }
    }
}

pub fn write_identity(writer: &mut Writer, identity: l2_capture::LinuxInterfaceIdentity) {
    writer.u64(identity.namespace_device());
    writer.u64(identity.namespace_inode());
    writer.u64(identity.interface_device());
    writer.u64(identity.interface_inode());
    writer.u32(identity.ifindex());
}

pub fn read_identity(reader: &mut Reader<'_>) -> io::Result<l2_capture::LinuxInterfaceIdentity> {
    l2_capture::LinuxInterfaceIdentity::new(
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u32()?,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn write_vlan(writer: &mut Writer, vlan: Option<crate::VlanInfo>) {
    if let Some(vlan) = vlan {
        writer.u8(1);
        writer.u16(vlan.id());
        writer.u8(match vlan.protocol() {
            crate::VlanProtocol::Ieee8021Q => 1,
            crate::VlanProtocol::Ieee8021Ad => 2,
        });
        write_identity(writer, vlan.parent_identity());
        writer.u8(u8::from(vlan.reorders_headers()));
    } else {
        writer.u8(0);
    }
}

pub fn read_vlan(
    reader: &mut Reader<'_>,
    selected: l2_capture::LinuxInterfaceIdentity,
) -> io::Result<Option<crate::VlanInfo>> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let id = reader.u16()?;
            if id >= 4095 {
                return Err(invalid_record());
            }
            let protocol = match reader.u8()? {
                1 => crate::VlanProtocol::Ieee8021Q,
                2 => crate::VlanProtocol::Ieee8021Ad,
                _ => return Err(invalid_record()),
            };
            let parent = read_identity(reader)?;
            if parent.namespace_device() != selected.namespace_device()
                || parent.namespace_inode() != selected.namespace_inode()
                || parent.ifindex() == selected.ifindex()
            {
                return Err(invalid_record());
            }
            let reorders_headers = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(invalid_record()),
            };
            Ok(Some(crate::VlanInfo {
                id,
                protocol,
                parent,
                reorders_headers,
            }))
        }
        _ => Err(invalid_record()),
    }
}

pub fn error_record(error: &io::Error) -> Vec<u8> {
    let kind = if matches!(error.get_ref(), Some(source) if source.is::<crate::VlanScopeChanged>())
    {
        10
    } else {
        match error.kind() {
            io::ErrorKind::InvalidInput => 1,
            io::ErrorKind::PermissionDenied => 2,
            io::ErrorKind::NotFound => 3,
            io::ErrorKind::Unsupported => 4,
            io::ErrorKind::Interrupted => 5,
            io::ErrorKind::TimedOut => 6,
            io::ErrorKind::NotConnected => 7,
            io::ErrorKind::NetworkUnreachable => 8,
            io::ErrorKind::HostUnreachable => 9,
            _ => 0,
        }
    };
    let message: String = error.to_string().chars().take(128).collect();
    let mut writer = Writer::new(ERROR);
    writer.u8(kind);
    writer.bytes(message.as_bytes());
    writer.finish()
}

pub fn read_error(reader: &mut Reader<'_>) -> io::Result<io::Error> {
    let code = reader.u8()?;
    let kind = match code {
        1 => io::ErrorKind::InvalidInput,
        2 => io::ErrorKind::PermissionDenied,
        3 => io::ErrorKind::NotFound,
        4 => io::ErrorKind::Unsupported,
        5 => io::ErrorKind::Interrupted,
        6 => io::ErrorKind::TimedOut,
        7 => io::ErrorKind::NotConnected,
        8 => io::ErrorKind::NetworkUnreachable,
        9 => io::ErrorKind::HostUnreachable,
        10 => io::ErrorKind::InvalidData,
        0 => io::ErrorKind::Other,
        _ => return Err(invalid_record()),
    };
    let message = std::str::from_utf8(reader.rest()?).map_err(|_| invalid_record())?;
    if message.len() > 512 {
        return Err(invalid_record());
    }
    if code == 10 {
        return Ok(io::Error::new(kind, crate::VlanScopeChanged));
    }
    Ok(io::Error::new(kind, message.to_owned()))
}

pub fn invalid_record() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid active-helper record")
}
