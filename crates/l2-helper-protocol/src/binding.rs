use crate::ProtocolError;
use crate::bytes::{read_array, write_at};

// Namespace device and inode prevent an interface name from becoming authority
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceBindingRequest {
    namespace_device: u64,
    namespace_inode: u64,
    ifindex: u32,
    datalink: u32,
}

impl InterfaceBindingRequest {
    pub const ENCODED_LENGTH: usize = 24;

    /// Creates a stable Linux namespace and interface binding request
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidInterfaceBinding`] when any identity
    /// component is zero and therefore cannot identify a kernel object
    pub const fn new(
        namespace_device: u64,
        namespace_inode: u64,
        ifindex: u32,
        datalink: u32,
    ) -> Result<Self, ProtocolError> {
        if namespace_device == 0 || namespace_inode == 0 || ifindex == 0 || datalink == 0 {
            return Err(ProtocolError::InvalidInterfaceBinding);
        }
        Ok(Self {
            namespace_device,
            namespace_inode,
            ifindex,
            datalink,
        })
    }

    /// Decodes one fixed-width interface binding payload
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong payload size or an incomplete identity
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() < Self::ENCODED_LENGTH {
            return Err(ProtocolError::InputTooShort {
                needed: Self::ENCODED_LENGTH,
                available: input.len(),
            });
        }
        if input.len() > Self::ENCODED_LENGTH {
            return Err(ProtocolError::TrailingBytes);
        }
        Self::new(
            u64::from_be_bytes(read_array::<8>(input, 0)?),
            u64::from_be_bytes(read_array::<8>(input, 8)?),
            u32::from_be_bytes(read_array::<4>(input, 16)?),
            u32::from_be_bytes(read_array::<4>(input, 20)?),
        )
    }

    /// Encodes one fixed-width interface binding without partial output
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::OutputTooShort`] when the output is too small
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        if output.len() < Self::ENCODED_LENGTH {
            return Err(ProtocolError::OutputTooShort {
                needed: Self::ENCODED_LENGTH,
                available: output.len(),
            });
        }

        let mut encoded = [0_u8; Self::ENCODED_LENGTH];
        write_at(&mut encoded, 0, &self.namespace_device.to_be_bytes())?;
        write_at(&mut encoded, 8, &self.namespace_inode.to_be_bytes())?;
        write_at(&mut encoded, 16, &self.ifindex.to_be_bytes())?;
        write_at(&mut encoded, 20, &self.datalink.to_be_bytes())?;
        let destination = output
            .get_mut(..Self::ENCODED_LENGTH)
            .ok_or(ProtocolError::InternalEncodingInvariant)?;
        destination.copy_from_slice(&encoded);
        Ok(Self::ENCODED_LENGTH)
    }

    #[must_use]
    pub const fn namespace_device(self) -> u64 {
        self.namespace_device
    }

    #[must_use]
    pub const fn namespace_inode(self) -> u64 {
        self.namespace_inode
    }

    #[must_use]
    pub const fn ifindex(self) -> u32 {
        self.ifindex
    }

    #[must_use]
    pub const fn datalink(self) -> u32 {
        self.datalink
    }
}
