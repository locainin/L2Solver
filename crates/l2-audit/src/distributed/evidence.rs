//! Serializable provenance for distributed canary results

use l2_segmentation::{AbsenceEvidence, ArrivalEvidence, ClockStamp, InterfaceBindingRequest};
use serde::Serialize;

/// Stable Linux network-namespace and interface identity
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DistributedInterfaceBinding {
    pub namespace_device: u64,
    pub namespace_inode: u64,
    pub ifindex: u32,
    pub datalink: u32,
}

impl DistributedInterfaceBinding {
    const fn from_binding(binding: InterfaceBindingRequest) -> Self {
        Self {
            namespace_device: binding.namespace_device(),
            namespace_inode: binding.namespace_inode(),
            ifindex: binding.ifindex(),
            datalink: binding.datalink(),
        }
    }

    #[must_use]
    pub fn report_label(self) -> String {
        format!(
            "netns={}:{},ifindex={},datalink={}",
            self.namespace_device, self.namespace_inode, self.ifindex, self.datalink
        )
    }
}

/// Diagnostic timestamp whose ticks are meaningful only within its domain
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DistributedClockStamp {
    pub domain: [u8; 16],
    pub ticks: u64,
}

impl DistributedClockStamp {
    const fn from_stamp(stamp: ClockStamp) -> Self {
        Self {
            domain: stamp.domain().get(),
            ticks: stamp.ticks(),
        }
    }
}

/// Complete structural provenance for one accepted authenticated arrival
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DistributedCanaryEvidence {
    pub packet_source: String,
    pub packet_sequence: u64,
    pub run_id: [u8; 16],
    pub probe_sequence: u64,
    pub source_agent: [u8; 16],
    pub receiver_agent: [u8; 16],
    pub transmit_interface: DistributedInterfaceBinding,
    pub observation_interface: DistributedInterfaceBinding,
    pub frame_sha256: [u8; 32],
    pub canary_wire_sha256: [u8; 32],
    pub transmit_clock: DistributedClockStamp,
    pub observation_clock: DistributedClockStamp,
    pub window_clock_domain: [u8; 16],
    pub window_armed_ticks: u64,
    pub window_closed_ticks: u64,
    pub window_capture_loss: u64,
    pub window_complete: bool,
    pub window_arm_event: u64,
    pub transmit_event: u64,
    pub window_close_event: u64,
    pub window_complete_event: u64,
}

impl From<ArrivalEvidence> for DistributedCanaryEvidence {
    fn from(evidence: ArrivalEvidence) -> Self {
        let canary = evidence.canary();
        let transmit = evidence.transmit();
        let window = evidence.window();
        let window_timing = window.timing();
        let packet = evidence.packet_reference();
        Self {
            packet_source: packet.source().to_string(),
            packet_sequence: packet.packet_number(),
            run_id: canary.run_id().into_bytes(),
            probe_sequence: canary.sequence(),
            source_agent: canary.source_agent_id().bytes(),
            receiver_agent: evidence.arrival().receiver().bytes(),
            transmit_interface: DistributedInterfaceBinding::from_binding(
                evidence.source_interface(),
            ),
            observation_interface: DistributedInterfaceBinding::from_binding(
                evidence.observation_interface(),
            ),
            frame_sha256: evidence.frame_sha256(),
            canary_wire_sha256: evidence.canary_wire_sha256(),
            transmit_clock: DistributedClockStamp::from_stamp(transmit.local_commit()),
            observation_clock: DistributedClockStamp::from_stamp(evidence.observed_at()),
            window_clock_domain: window.armed_at().domain().get(),
            window_armed_ticks: window.armed_at().ticks(),
            window_closed_ticks: window.closed_at().ticks(),
            window_capture_loss: window.capture_loss(),
            window_complete: window.complete(),
            window_arm_event: window_timing.arm_ack().ordinal(),
            transmit_event: evidence.transmit_event().ordinal(),
            window_close_event: window_timing.close_issued().ordinal(),
            window_complete_event: window_timing.complete().ordinal(),
        }
    }
}

/// Complete structural provenance for one loss-free destination absence
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DistributedCanaryAbsenceEvidence {
    pub run_id: [u8; 16],
    pub probe_sequence: u64,
    pub source_agent: [u8; 16],
    pub receiver_agent: [u8; 16],
    pub transmit_interface: DistributedInterfaceBinding,
    pub observation_interface: DistributedInterfaceBinding,
    pub frame_sha256: [u8; 32],
    pub transmit_clock: DistributedClockStamp,
    pub window_clock_domain: [u8; 16],
    pub window_armed_ticks: u64,
    pub window_closed_ticks: u64,
    pub window_capture_loss: u64,
    pub window_complete: bool,
    pub window_arm_event: u64,
    pub transmit_event: u64,
    pub window_close_event: u64,
    pub window_complete_event: u64,
}

impl From<AbsenceEvidence> for DistributedCanaryAbsenceEvidence {
    fn from(evidence: AbsenceEvidence) -> Self {
        let canary = evidence.canary();
        let transmit = evidence.transmit();
        let window = evidence.window();
        let timing = window.timing();
        Self {
            run_id: canary.run_id().into_bytes(),
            probe_sequence: canary.sequence(),
            source_agent: canary.source_agent_id().bytes(),
            receiver_agent: canary.destination_agent_id().bytes(),
            transmit_interface: DistributedInterfaceBinding::from_binding(
                evidence.source_interface(),
            ),
            observation_interface: DistributedInterfaceBinding::from_binding(
                evidence.observation_interface(),
            ),
            frame_sha256: evidence.frame_sha256(),
            transmit_clock: DistributedClockStamp::from_stamp(transmit.local_commit()),
            window_clock_domain: window.armed_at().domain().get(),
            window_armed_ticks: window.armed_at().ticks(),
            window_closed_ticks: window.closed_at().ticks(),
            window_capture_loss: window.capture_loss(),
            window_complete: window.complete(),
            window_arm_event: timing.arm_ack().ordinal(),
            transmit_event: evidence.transmit_event().ordinal(),
            window_close_event: timing.close_issued().ordinal(),
            window_complete_event: timing.complete().ordinal(),
        }
    }
}
