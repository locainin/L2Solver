//! Correlate actual, source-scoped replies with one prepared ARP query

use std::{sync::atomic::AtomicBool, time::Instant};

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::{ActiveLink, RunError, session::run_single_until};

use super::{ArpObservation, ArpProbe, ArpReport};

const MAX_OBSERVATIONS: usize = 64;

impl ArpProbe {
    /// Send the prepared request and collect bounded actual responses
    ///
    /// A successful send records socket acceptance only. ARP replies have no
    /// nonce or authentication, so matching fields cannot prove freshness
    ///
    /// # Errors
    /// Returns an error only if preparation fails before the send is attempted
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<ArpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Run under an absolute deadline shared with interface and helper setup
    ///
    /// A later deadline cannot extend the prepared operation's time limit
    ///
    /// # Errors
    /// Returns an error only if preparation fails before a send is attempted
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<ArpReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let summary = run_single_until(
            link,
            self.frame(),
            self.limits,
            cancelled,
            deadline,
            |frame| {
                let Some(mac) = self.match_reply(&frame) else {
                    return false;
                };
                if observations
                    .iter()
                    .any(|item: &ArpObservation| item.mac == mac)
                {
                    return false;
                }
                observations.push(ArpObservation { mac, frame });
                observations.len() == MAX_OBSERVATIONS
            },
        )?;
        Ok(ArpReport {
            summary,
            expected: self.expected,
            observations,
        })
    }

    fn match_reply(&self, frame: &CapturedFrame) -> Option<MacAddress> {
        let ethernet = l2_core::decode(frame.bytes()).ok()?;
        if !ethernet.vlan_tags.is_empty() {
            return None;
        }
        let arp = l2_discovery::arp_packet(&ethernet)?;
        if arp.operation != 2
            || arp.sender_ip != self.target.octets()
            || arp.target_ip != self.source_ip.octets()
            || arp.target_mac != self.source_mac.bytes()
            || arp.sender_mac != ethernet.source
            || (ethernet.destination != self.source_mac.bytes()
                && ethernet.destination != [0xff; 6])
        {
            return None;
        }
        MacAddress::new(arp.sender_mac).ok()
    }
}
