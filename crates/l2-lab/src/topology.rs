//! Checked virtual access ports and their static unicast bridge

use l2_canary::AgentId;
use l2_onpath::MacAddress;
use l2_segmentation::{InterfaceBindingRequest, Plan};

use crate::LabError;

/// An IEEE access VLAN identifier excluding reserved values
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VlanId(u16);

impl VlanId {
    /// Validate an access VLAN identifier
    ///
    /// # Errors
    /// Rejects reserved IDs zero and 4095 and values above the twelve-bit range
    pub const fn new(value: u16) -> Result<Self, LabError> {
        if value == 0 || value > 4094 {
            return Err(LabError::InvalidVlan);
        }
        Ok(Self(value))
    }

    /// Return the checked access VLAN number
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A controlled synthetic agent attached to one modeled access port
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualEndpoint {
    agent: AgentId,
    interface: InterfaceBindingRequest,
    mac: MacAddress,
    vlan: VlanId,
}

impl VirtualEndpoint {
    /// Bind a synthetic agent to a modeled interface, address, and access VLAN
    ///
    /// The interface identity is an opaque virtual label, not kernel authority
    ///
    /// # Errors
    /// Rejects zero, broadcast, and multicast Ethernet addresses
    pub fn new(
        agent: AgentId,
        interface: InterfaceBindingRequest,
        mac: [u8; 6],
        vlan: VlanId,
    ) -> Result<Self, LabError> {
        // Reuse the checked identity instead of maintaining another MAC validator
        let mac = MacAddress::new(mac).map_err(|_| LabError::InvalidMac)?;
        Ok(Self {
            agent,
            interface,
            mac,
            vlan,
        })
    }

    /// Return the canary identity attached to this port
    #[must_use]
    pub const fn agent_id(self) -> AgentId {
        self.agent
    }

    /// Return the modeled interface label
    #[must_use]
    pub const fn interface(self) -> InterfaceBindingRequest {
        self.interface
    }

    /// Return the virtual unicast Ethernet address
    #[must_use]
    pub const fn mac(self) -> [u8; 6] {
        self.mac.bytes()
    }

    /// Return the port's assigned access VLAN
    #[must_use]
    pub const fn vlan(self) -> VlanId {
        self.vlan
    }
}

/// Forwarding implementation configured separately from expected policy
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeMode {
    /// Forward known unicast frames only to ports in the ingress VLAN
    VlanAware,
    /// Fault injection: ignore VLAN boundaries for known unicast frames
    LeaksAcrossVlans,
}

#[derive(Debug)]
pub struct Topology {
    endpoints: Vec<VirtualEndpoint>,
    mode: BridgeMode,
}

pub struct Delivery<'a> {
    pub receiver: VirtualEndpoint,
    pub frame: &'a [u8],
}

impl Topology {
    pub(crate) fn new(
        plan: &Plan,
        endpoints: &[VirtualEndpoint],
        mode: BridgeMode,
    ) -> Result<Self, LabError> {
        if endpoints.len() != plan.agents().len() {
            return Err(LabError::UnboundTopology);
        }
        for (index, endpoint) in endpoints.iter().enumerate() {
            // Require unique synthetic attachments before any virtual dispatch
            if endpoints.iter().take(index).any(|other| {
                other.agent == endpoint.agent
                    || other.interface == endpoint.interface
                    || other.mac == endpoint.mac
            }) {
                return Err(LabError::DuplicateEndpoint);
            }
            if !plan.agents().iter().any(|agent| {
                agent.id() == endpoint.agent && agent.interface() == endpoint.interface
            }) {
                return Err(LabError::UnboundTopology);
            }
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(endpoints.len())
            .map_err(|_| LabError::Allocation)?;
        owned.extend_from_slice(endpoints);
        Ok(Self {
            endpoints: owned,
            mode,
        })
    }

    pub(crate) fn endpoint(&self, agent: AgentId) -> Result<VirtualEndpoint, LabError> {
        self.endpoints
            .iter()
            .copied()
            .find(|endpoint| endpoint.agent == agent)
            .ok_or(LabError::UnboundTopology)
    }

    pub(crate) fn forward<'a>(
        &self,
        source: VirtualEndpoint,
        frame: &'a [u8],
    ) -> Result<Option<Delivery<'a>>, LabError> {
        let decoded = l2_core::decode(frame)?;
        // Static unicast forwarding uses wire addresses and port VLANs only
        if decoded.source != source.mac() || !decoded.vlan_tags.is_empty() {
            return Err(LabError::Invariant);
        }
        let receiver = self
            .endpoints
            .iter()
            .copied()
            .find(|endpoint| endpoint.mac() == decoded.destination);
        Ok(receiver
            .filter(|endpoint| {
                endpoint.agent != source.agent
                    && (self.mode == BridgeMode::LeaksAcrossVlans || endpoint.vlan == source.vlan)
            })
            .map(|receiver| Delivery { receiver, frame }))
    }
}
