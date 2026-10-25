use crate::{EncodeError, encode::encoded_len};
use serde::{Deserialize, Serialize};

/// Raw radiotap flags with common capture-quality helpers
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RadiotapFlags(u8);

impl RadiotapFlags {
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn has_fcs(self) -> bool {
        self.0 & 0x10 != 0
    }

    #[must_use]
    pub const fn bad_fcs(self) -> bool {
        self.0 & 0x40 != 0
    }
}

/// Frequency and flags from radiotap field three
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Channel {
    frequency_mhz: u16,
    flags: u16,
}

impl Channel {
    #[must_use]
    pub const fn new(frequency_mhz: u16, flags: u16) -> Self {
        Self {
            frequency_mhz,
            flags,
        }
    }

    #[must_use]
    pub const fn frequency_mhz(self) -> u16 {
        self.frequency_mhz
    }

    #[must_use]
    pub const fn flags(self) -> u16 {
        self.flags
    }
}

/// Supported radiotap metadata retained by the portable parser
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RadiotapFields {
    tsft: Option<u64>,
    flags: Option<RadiotapFlags>,
    rate_500kbps: Option<u8>,
    channel: Option<Channel>,
    signal_dbm: Option<i8>,
    noise_dbm: Option<i8>,
    antenna: Option<u8>,
    rx_flags: Option<u16>,
    tx_flags: Option<u16>,
    zero_length_psdu: Option<u8>,
}

impl RadiotapFields {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tsft: None,
            flags: None,
            rate_500kbps: None,
            channel: None,
            signal_dbm: None,
            noise_dbm: None,
            antenna: None,
            rx_flags: None,
            tx_flags: None,
            zero_length_psdu: None,
        }
    }

    #[must_use]
    pub const fn with_tsft(mut self, value: u64) -> Self {
        self.tsft = Some(value);
        self
    }

    #[must_use]
    pub const fn with_flags(mut self, value: RadiotapFlags) -> Self {
        self.flags = Some(value);
        self
    }

    #[must_use]
    pub const fn with_rate_500kbps(mut self, value: u8) -> Self {
        self.rate_500kbps = Some(value);
        self
    }

    #[must_use]
    pub const fn with_channel(mut self, value: Channel) -> Self {
        self.channel = Some(value);
        self
    }

    #[must_use]
    pub const fn with_signal_dbm(mut self, value: i8) -> Self {
        self.signal_dbm = Some(value);
        self
    }

    #[must_use]
    pub const fn with_noise_dbm(mut self, value: i8) -> Self {
        self.noise_dbm = Some(value);
        self
    }

    #[must_use]
    pub const fn with_antenna(mut self, value: u8) -> Self {
        self.antenna = Some(value);
        self
    }

    #[must_use]
    pub const fn with_rx_flags(mut self, value: u16) -> Self {
        self.rx_flags = Some(value);
        self
    }

    #[must_use]
    pub const fn with_tx_flags(mut self, value: u16) -> Self {
        self.tx_flags = Some(value);
        self
    }

    /// Mark a PHY-only record that carries no 802.11 PSDU
    #[must_use]
    pub const fn with_zero_length_psdu(mut self, value: u8) -> Self {
        self.zero_length_psdu = Some(value);
        self
    }

    #[must_use]
    pub const fn tsft(&self) -> Option<u64> {
        self.tsft
    }

    #[must_use]
    pub const fn flags(&self) -> Option<RadiotapFlags> {
        self.flags
    }

    #[must_use]
    pub const fn rate_500kbps(&self) -> Option<u8> {
        self.rate_500kbps
    }

    #[must_use]
    pub const fn channel(&self) -> Option<Channel> {
        self.channel
    }

    #[must_use]
    pub const fn signal_dbm(&self) -> Option<i8> {
        self.signal_dbm
    }

    #[must_use]
    pub const fn noise_dbm(&self) -> Option<i8> {
        self.noise_dbm
    }

    #[must_use]
    pub const fn antenna(&self) -> Option<u8> {
        self.antenna
    }

    #[must_use]
    pub const fn rx_flags(&self) -> Option<u16> {
        self.rx_flags
    }

    #[must_use]
    pub const fn tx_flags(&self) -> Option<u16> {
        self.tx_flags
    }

    /// Return the reported zero-length PSDU type
    #[must_use]
    pub const fn zero_length_psdu(&self) -> Option<u8> {
        self.zero_length_psdu
    }

    /// Exact size of a canonical header containing these fields
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the encoded header length overflows
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        encoded_len(self)
    }
}

/// Radiotap metadata plus the following raw IEEE 802.11 bytes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadiotapFrame<'a> {
    header_bytes: &'a [u8],
    wifi_bytes: &'a [u8],
    fields: RadiotapFields,
    metadata_complete: bool,
    first_unsupported_field: Option<u16>,
}

impl<'a> RadiotapFrame<'a> {
    pub(crate) const fn new(
        header_bytes: &'a [u8],
        wifi_bytes: &'a [u8],
        fields: RadiotapFields,
        metadata_complete: bool,
        first_unsupported_field: Option<u16>,
    ) -> Self {
        Self {
            header_bytes,
            wifi_bytes,
            fields,
            metadata_complete,
            first_unsupported_field,
        }
    }

    #[must_use]
    pub const fn header_bytes(&self) -> &'a [u8] {
        self.header_bytes
    }

    #[must_use]
    pub const fn wifi_bytes(&self) -> &'a [u8] {
        self.wifi_bytes
    }

    #[must_use]
    pub const fn fields(&self) -> &RadiotapFields {
        &self.fields
    }

    #[must_use]
    pub const fn metadata_complete(&self) -> bool {
        self.metadata_complete
    }

    #[must_use]
    pub const fn first_unsupported_field(&self) -> Option<u16> {
        self.first_unsupported_field
    }
}
