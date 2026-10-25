//! A live capture handle has no transmit API in this crate

use super::budget::{Budget, DEFAULT_CAPTURE_DURATION, StopReason};
use l2_capture::{CapturedFrame, LinkType};
use l2_io::LinkIo;
use std::{
    io, thread,
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../tests/statistics/internal.rs"]
mod statistics_tests;

/// Libpcap counters with their evidence-strength limitation made explicit
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveStatistics {
    received: u32,
    capture_dropped: u32,
    interface_dropped: u32,
}

impl LiveStatistics {
    const fn from_pcap(statistics: pcap::Stat) -> Self {
        Self {
            received: statistics.received,
            capture_dropped: statistics.dropped,
            interface_dropped: statistics.if_dropped,
        }
    }

    /// Return packets reported to the backend by libpcap
    #[must_use]
    pub const fn received(self) -> u32 {
        self.received
    }

    /// Return capture-buffer drops reported by libpcap
    #[must_use]
    pub const fn capture_dropped(self) -> u32 {
        self.capture_dropped
    }

    /// Return interface drops reported by libpcap
    #[must_use]
    pub const fn interface_dropped(self) -> u32 {
        self.interface_dropped
    }

    /// Return whether zero values prove the absence of loss
    ///
    /// Libpcap exposes no availability bit for these fields, so its current
    /// counters are diagnostic rather than authoritative completeness evidence
    #[must_use]
    pub const fn loss_counters_authoritative(self) -> bool {
        false
    }
}

pub struct LiveLink {
    capture: pcap::Capture<pcap::Active>,
    budget: Budget,
    interface_name: String,
    pinned_interface: super::interface::PinnedInterface,
    /// Data-link identity checked after libpcap opens
    link_type: LinkType,
    interface_identity: super::interface::LiveInterfaceIdentity,
}

impl LiveLink {
    /// Open a supported data-link interface for inbound capture, at most 30 seconds and 10,000 packets
    ///
    /// # Errors
    /// Returns an error for unknown interfaces, unsupported datalinks, invalid limits or missing permissions
    pub fn open(interface: &str, packets: u32) -> Result<Self, io::Error> {
        Self::open_with_limits(interface, packets, DEFAULT_CAPTURE_DURATION)
    }

    /// Open a supported data-link interface with explicit packet and duration limits
    ///
    /// # Errors
    /// Returns an error for unknown interfaces, unsupported datalinks, invalid limits or missing permissions
    pub fn open_with_limits(
        interface: &str,
        packets: u32,
        duration: Duration,
    ) -> Result<Self, io::Error> {
        Budget::validate_packet_count(packets).map_err(io::Error::other)?;
        Budget::validate_duration(duration).map_err(io::Error::other)?;
        let device = pcap::Device::list()
            .map_err(io::Error::other)?
            .into_iter()
            .find(|device| device.name == interface)
            .ok_or_else(|| io::Error::other("unknown capture interface"))?;
        let pinned_interface = super::interface::pin(interface)?;
        let capture = pcap::Capture::from_device(device)
            .map_err(io::Error::other)?
            .promisc(false)
            .snaplen(65_535)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(io::Error::other)?;
        let link_type = checked_link_type(capture.get_datalink())?;
        if !link_type.is_supported() {
            return Err(io::Error::other(format!(
                "unsupported live capture link type {link_type} ({})",
                link_type.raw()
            )));
        }
        capture
            .direction(pcap::Direction::In)
            .map_err(io::Error::other)?;
        let interface_identity = super::interface::validate_capture(
            &capture,
            interface,
            &pinned_interface,
            u32::from(link_type.raw()),
        )?;
        let capture = capture.setnonblock().map_err(io::Error::other)?;
        Ok(Self {
            capture,
            budget: Budget::new(packets, duration, Instant::now()),
            interface_name: interface.to_owned(),
            pinned_interface,
            link_type,
            interface_identity,
        })
    }

    /// Return the normal stop reason after the receive loop reaches EOF
    #[must_use]
    pub const fn stop_reason(&self) -> Option<StopReason> {
        self.budget.stop_reason()
    }

    /// Return backend counters without claiming that they measure physical wire loss
    ///
    /// # Errors
    /// Returns an error when source identity changed or capture statistics are unavailable
    pub fn statistics(&mut self) -> Result<LiveStatistics, io::Error> {
        self.revalidate_interface()?;
        self.capture
            .stats()
            .map(LiveStatistics::from_pcap)
            .map_err(io::Error::other)
    }

    /// Return the exact data-link layout reported by libpcap
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Return the namespace and kernel interface bound to the capture socket
    ///
    /// # Errors
    /// Returns an error when the retained descriptors, name binding, socket
    /// binding, or data-link layout no longer matches the identity opened
    pub fn interface_identity(
        &mut self,
    ) -> Result<super::interface::LiveInterfaceIdentity, io::Error> {
        self.revalidate_interface()?;
        Ok(self.interface_identity)
    }

    fn revalidate_interface(&self) -> io::Result<()> {
        super::interface::revalidate_capture(
            &self.capture,
            &self.interface_name,
            self.interface_identity,
            &self.pinned_interface,
        )
    }
}

impl LinkIo for LiveLink {
    type Error = io::Error;

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        loop {
            // The budget decides whether EOF is a normal packet-limit or deadline stop
            if self.budget.poll(Instant::now()).is_some() {
                return Ok(None);
            }
            // Never expose bytes after the requested kernel object has changed
            self.revalidate_interface()?;
            match self.capture.next_packet() {
                Ok(packet) => {
                    let frame = super::packet::capture_with_link_type(
                        self.interface_identity.source(),
                        self.link_type,
                        packet.data,
                        packet.header.caplen,
                        packet.header.len,
                        packet.header.ts.tv_sec,
                        packet.header.ts.tv_usec,
                    )?;
                    // A change during acquisition invalidates the copied frame
                    self.revalidate_interface()?;
                    self.budget.consume_packet();
                    return Ok(Some(frame));
                }
                // Only orchestration waits; the parsers and observation engine never sleep
                Err(pcap::Error::TimeoutExpired) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error @ pcap::Error::NoMorePackets) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, error));
                }
                Err(error) => return Err(io::Error::other(error)),
            }
        }
    }
}

fn checked_link_type(link_type: pcap::Linktype) -> io::Result<LinkType> {
    let raw = u16::try_from(link_type.0).map_err(|_| {
        io::Error::other(format!(
            "unsupported live capture link type {}",
            link_type.0
        ))
    })?;
    Ok(LinkType::from_raw(raw))
}
