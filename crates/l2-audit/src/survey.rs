//! A terminal survey cannot export partially updated inventory after a limit error

use crate::{
    AssessmentProfile, AuditError, EvidenceLocator, EvidenceRef, InterfaceObservation,
    LinuxInterfaceEvidence, PacketEvidence, PlannerInput, Policy, Quality, Report, ResourceLimit,
    ResourceLimitStatus, SourceLabelMap, assess_with_input, assess_with_input_and_source_labels,
    forensics::ForensicTracker, inventory,
};
use l2_capture::{CaptureLocator, CaptureTimestamp, CapturedFrame};
use l2_codecs::{StpError, Validity};
use l2_core::FrameField;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// References scale independently while embedded packet bytes stay small and predictable
const ABSOLUTE_MAX_EVIDENCE_REFS: usize = 262_144;
const ABSOLUTE_MAX_EMBEDDED_PACKETS: usize = 4_096;
const ABSOLUTE_MAX_EMBEDDED_BYTES: usize = 64 * 1024 * 1024;
const ABSOLUTE_MAX_MAC_FACTS: usize = 65_536;
const ABSOLUTE_MAX_VLAN_CONTEXTS: usize = 4_096;
const ABSOLUTE_MAX_NEIGHBORS: usize = 4_096;
const ABSOLUTE_MAX_PROTOCOL_IDENTITIES: usize = 65_536;
const ABSOLUTE_MAX_STP_TRANSITIONS: usize = 10_000;
const ABSOLUTE_MAX_FORENSIC_RECORDS: usize = 65_536;
const ABSOLUTE_MAX_DNS_MESSAGES: usize = 4_096;
const MAX_INTERFACES: usize = 64;

/// Runtime retention limits constrained by absolute process ceilings
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurveyLimits {
    evidence_references: usize,
    embedded_packets: usize,
    embedded_bytes: usize,
    mac_facts: usize,
    vlan_contexts: usize,
    neighbors: usize,
    protocol_identities: usize,
    stp_transitions: usize,
    forensic_records: usize,
    dns_messages: usize,
}
impl Default for SurveyLimits {
    fn default() -> Self {
        Self {
            evidence_references: 131_072,
            embedded_packets: 256,
            embedded_bytes: 4 * 1024 * 1024,
            mac_facts: ABSOLUTE_MAX_MAC_FACTS,
            vlan_contexts: ABSOLUTE_MAX_VLAN_CONTEXTS,
            neighbors: ABSOLUTE_MAX_NEIGHBORS,
            protocol_identities: 16_384,
            stp_transitions: ABSOLUTE_MAX_STP_TRANSITIONS,
            forensic_records: 16_384,
            dns_messages: 1_024,
        }
    }
}
impl SurveyLimits {
    /// Bound retained DNS message layouts independently of lightweight relationships
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_dns_messages(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_DNS_MESSAGES {
            return Err(AuditError::InvalidLimit("DNS messages must be in 1..=4096"));
        }
        self.dns_messages = limit;
        Ok(self)
    }

    /// Set the shared ceiling for communication, ARP, change, and trailing-data records
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_forensic_records(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_FORENSIC_RECORDS {
            return Err(AuditError::InvalidLimit(
                "forensic records must be in 1..=65536",
            ));
        }
        self.forensic_records = limit;
        Ok(self)
    }

    /// Set the maximum number of distinct source-MAC facts
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_mac_facts(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_MAC_FACTS {
            return Err(AuditError::InvalidLimit("MAC facts must be in 1..=65536"));
        }
        self.mac_facts = limit;
        Ok(self)
    }

    /// Set the maximum number of distinct VLAN-stack contexts
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_vlan_contexts(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_VLAN_CONTEXTS {
            return Err(AuditError::InvalidLimit(
                "VLAN contexts must be in 1..=4096",
            ));
        }
        self.vlan_contexts = limit;
        Ok(self)
    }

    /// Set the maximum number of distinct LLDP neighbors
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_neighbors(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_NEIGHBORS {
            return Err(AuditError::InvalidLimit("neighbors must be in 1..=4096"));
        }
        self.neighbors = limit;
        Ok(self)
    }

    /// Set the maximum number of distinct protocol identity claims
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_protocol_identities(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_PROTOCOL_IDENTITIES {
            return Err(AuditError::InvalidLimit(
                "protocol identities must be in 1..=65536",
            ));
        }
        self.protocol_identities = limit;
        Ok(self)
    }

    /// Set the maximum number of retained STP root transitions
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_stp_transitions(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_STP_TRANSITIONS {
            return Err(AuditError::InvalidLimit(
                "STP transitions must be in 1..=10000",
            ));
        }
        self.stp_transitions = limit;
        Ok(self)
    }

    /// Set the maximum number of hashed evidence references
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_evidence_references(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_EVIDENCE_REFS {
            return Err(AuditError::InvalidLimit(
                "evidence references must be in 1..=262144",
            ));
        }
        self.evidence_references = limit;
        Ok(self)
    }

    /// Set the maximum number of embedded raw packets
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_embedded_packets(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_EMBEDDED_PACKETS {
            return Err(AuditError::InvalidLimit(
                "embedded packets must be in 1..=4096",
            ));
        }
        self.embedded_packets = limit;
        Ok(self)
    }

    /// Set the maximum total bytes retained in embedded raw packets
    /// # Errors
    /// Rejects zero or a value above the absolute process ceiling
    pub const fn with_embedded_bytes(mut self, limit: usize) -> Result<Self, AuditError> {
        if limit == 0 || limit > ABSOLUTE_MAX_EMBEDDED_BYTES {
            return Err(AuditError::InvalidLimit(
                "embedded bytes must be in 1..=67108864",
            ));
        }
        self.embedded_bytes = limit;
        Ok(self)
    }
}

pub struct Survey {
    interfaces: BTreeMap<(u32, u32), InterfaceObservation>,
    evidence_refs: Vec<EvidenceRef>,
    evidence: Vec<PacketEvidence>,
    limits: SurveyLimits,
    resource_limits: ResourceLimitStatus,
    embedded_bytes: usize,
    quality: Quality,
    inventory: inventory::InventoryTracker,
    forensics: ForensicTracker,
    terminated: bool,
}

impl Default for Survey {
    fn default() -> Self {
        Self::new()
    }
}
impl Survey {
    /// Construct an empty passive collection
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(SurveyLimits::default())
    }

    /// Construct a passive collection with runtime retention limits
    #[must_use]
    pub fn with_limits(limits: SurveyLimits) -> Self {
        Self {
            interfaces: BTreeMap::new(),
            evidence_refs: Vec::new(),
            evidence: Vec::new(),
            limits,
            resource_limits: ResourceLimitStatus::default(),
            embedded_bytes: 0,
            quality: Quality::default(),
            inventory: inventory::InventoryTracker::new(
                limits.mac_facts,
                limits.vlan_contexts,
                limits.neighbors,
                limits.protocol_identities,
                limits.stp_transitions,
            ),
            terminated: false,
            forensics: ForensicTracker::new(limits.forensic_records, limits.dns_messages),
        }
    }

    /// Observe one captured frame without granting any transmit authority
    /// # Errors
    /// Returns a resource limit or prior terminal error
    pub fn observe(&mut self, packet: &CapturedFrame) -> Result<(), AuditError> {
        if self.terminated {
            return Err(AuditError::Terminated);
        }
        let result = self.collect(packet);
        if result.is_err() {
            self.terminated = true;
        }
        result
    }

    /// Record source loss or an incomplete live sampling deadline
    /// # Errors
    /// Returns an error if loss accounting overflows or collection already failed
    pub const fn record_quality(
        &mut self,
        dropped: u64,
        incomplete: bool,
    ) -> Result<(), AuditError> {
        if self.terminated {
            return Err(AuditError::Terminated);
        }
        let Some(total) = self.quality.dropped.checked_add(dropped) else {
            self.terminated = true;
            return Err(AuditError::Limit("drop counter"));
        };
        self.quality.dropped = total;
        self.quality.incomplete |= incomplete;
        Ok(())
    }

    /// Evaluate explicit policy over the collected observations
    /// # Errors
    /// Rejects invalid policy or a collection that failed earlier
    pub fn finish(self, policy: &Policy) -> Result<Report, AuditError> {
        self.finish_with_profile(policy, AssessmentProfile::Opportunistic)
    }

    /// Evaluate explicit policy using the selected active-check planning profile
    /// # Errors
    /// Rejects invalid policy or a collection that failed earlier
    pub fn finish_with_profile(
        self,
        policy: &Policy,
        profile: AssessmentProfile,
    ) -> Result<Report, AuditError> {
        self.finish_with_profile_and_optional_source_labels(policy, profile, None)
    }

    /// Evaluate policy using checked runtime labels for capture interfaces
    ///
    /// # Errors
    /// Rejects an invalid policy, an incomplete source mapping, or a collection
    /// that failed earlier
    pub fn finish_with_profile_and_source_labels(
        self,
        policy: &Policy,
        profile: AssessmentProfile,
        labels: &SourceLabelMap,
    ) -> Result<Report, AuditError> {
        self.finish_with_profile_and_optional_source_labels(policy, profile, Some(labels))
    }

    fn finish_with_profile_and_optional_source_labels(
        self,
        policy: &Policy,
        profile: AssessmentProfile,
        labels: Option<&SourceLabelMap>,
    ) -> Result<Report, AuditError> {
        if self.terminated {
            return Err(AuditError::Terminated);
        }
        let mut interfaces: Vec<_> = self.interfaces.into_values().collect();
        inventory::sort_interfaces(&mut interfaces);
        let planner_input = PlannerInput::from_interfaces(&interfaces).with_profile(profile);
        let source_ids: Vec<_> = interfaces
            .iter()
            .map(|interface| l2_capture::InterfaceId {
                section: interface.section,
                index: interface.index,
            })
            .collect();
        let assessment = if policy.uses_stable_fields() {
            let labels = labels.ok_or(AuditError::SourceMapping(
                crate::SourceLabelMapError::MissingMapping,
            ))?;
            policy.validate_source_mapping(labels, &source_ids)?;
            assess_with_input_and_source_labels(
                &interfaces,
                policy,
                &self.quality,
                &planner_input,
                labels,
            )?
        } else if let Some(labels) = labels {
            policy.validate_source_mapping(labels, &source_ids)?;
            assess_with_input_and_source_labels(
                &interfaces,
                policy,
                &self.quality,
                &planner_input,
                labels,
            )?
        } else {
            assess_with_input(&interfaces, policy, &self.quality, &planner_input)?
        };
        Ok(Report {
            schema_version: 8,
            tool_version: env!("CARGO_PKG_VERSION").into(),
            assessment_profile: profile,
            policy: policy.clone(),
            interfaces,
            network_model: assessment.network_model,
            forensics: self.forensics.finish(),
            port_roles: assessment.port_roles,
            exposures: assessment.exposures,
            findings: assessment.findings,
            coverage: assessment.coverage,
            coverage_summary: assessment.coverage_summary,
            plan: assessment.plan,
            quality: self.quality,
            resource_limits: self.resource_limits,
            evidence_refs: self.evidence_refs,
            evidence: self.evidence,
        })
    }

    fn collect(&mut self, packet: &CapturedFrame) -> Result<(), AuditError> {
        let sequence = self
            .quality
            .frames
            .checked_add(1)
            .ok_or(AuditError::Limit("frame count"))?;
        self.quality.frames = sequence;
        let id = packet.metadata().interface();
        let key = (id.section, id.index);
        if !self.interfaces.contains_key(&key) && self.interfaces.len() == MAX_INTERFACES {
            return Err(AuditError::Limit("interface count"));
        }
        let interface = self
            .interfaces
            .entry(key)
            .or_insert_with(|| empty_interface(id.section, id.index));
        interface.frames += 1;
        let truncated = packet.is_truncated();
        if truncated {
            self.quality.truncated += 1;
        }
        if !packet.metadata().link_type().is_ethernet() {
            self.quality.unsupported_link_types += 1;
            return Ok(());
        }
        if truncated {
            return Ok(());
        }
        let Ok(frame) = l2_core::decode(packet.bytes()) else {
            self.quality.malformed += 1;
            return Ok(());
        };

        let mut changed = collect_decoded(
            interface,
            &frame,
            sequence,
            &mut self.quality,
            &mut self.inventory,
            &mut self.resource_limits,
            packet.metadata(),
        );
        changed |= self.forensics.observe(
            packet,
            &frame,
            sequence,
            self.evidence_refs.len() < self.limits.evidence_references,
            &mut self.resource_limits,
        );
        if changed {
            self.record_evidence(sequence, packet);
        }
        Ok(())
    }

    fn record_evidence(&mut self, sequence: u64, packet: &CapturedFrame) {
        if self.evidence_refs.len() < self.limits.evidence_references {
            self.evidence_refs.push(evidence_ref(sequence, packet));
        } else {
            self.resource_limits.mark(ResourceLimit::EvidenceReferences);
        }
        let attempted_bytes = self.embedded_bytes.saturating_add(packet.captured_len());
        if self.evidence.len() >= self.limits.embedded_packets {
            self.resource_limits.mark(ResourceLimit::EmbeddedPackets);
        } else if attempted_bytes > self.limits.embedded_bytes {
            self.resource_limits.mark(ResourceLimit::EmbeddedBytes);
        } else {
            self.evidence.push(PacketEvidence {
                sequence,
                raw_bytes: packet.bytes().to_vec(),
            });
            self.embedded_bytes = attempted_bytes;
        }
    }
}

const fn empty_interface(section: u32, index: u32) -> InterfaceObservation {
    InterfaceObservation {
        section,
        index,
        frames: 0,
        macs: Vec::new(),
        vlans: Vec::new(),
        untagged_packet: None,
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

fn collect_decoded(
    interface: &mut InterfaceObservation,
    frame: &l2_core::EthernetFrame<'_>,
    sequence: u64,
    quality: &mut Quality,
    tracker: &mut inventory::InventoryTracker,
    limits: &mut ResourceLimitStatus,
    metadata: &l2_capture::CaptureMetadata,
) -> bool {
    // Lower-layer facts remain valid when a protocol payload is malformed
    let mut changed = inventory::ethernet(interface, frame, sequence, tracker, limits);
    if let Some(discovery) = l2_discovery::discover(frame) {
        changed |= inventory::protocol(interface, discovery.fingerprint, sequence);
        if let Some(identity) = discovery.identity {
            changed |= inventory::protocol_identity(
                interface,
                discovery.fingerprint.protocol,
                identity,
                (&frame.vlan_tags, metadata.vlan()),
                sequence,
                tracker,
                limits,
            );
        }
        match discovery.fingerprint.status {
            l2_discovery::FingerprintStatus::Observed => {}
            l2_discovery::FingerprintStatus::Malformed => quality.invalid += 1,
            l2_discovery::FingerprintStatus::Truncated => quality.malformed += 1,
            l2_discovery::FingerprintStatus::Unsupported => {
                quality.unsupported_fingerprints += 1;
            }
        }
    }
    changed |= collect_lldp(interface, frame, sequence, quality, tracker, limits);
    changed | collect_stp(interface, frame, sequence, quality, tracker, limits)
}

fn collect_lldp(
    interface: &mut InterfaceObservation,
    frame: &l2_core::EthernetFrame<'_>,
    sequence: u64,
    quality: &mut Quality,
    tracker: &mut inventory::InventoryTracker,
    limits: &mut ResourceLimitStatus,
) -> bool {
    if frame.field != FrameField::EtherType(0x88cc) {
        return false;
    }
    match l2_codecs::decode_lldp(frame.payload) {
        Ok(lldp) if lldp.validity == Validity::Valid => {
            inventory::lldp(interface, &lldp, sequence, tracker, limits)
        }
        Ok(_) => {
            quality.invalid += 1;
            false
        }
        Err(_) => {
            quality.malformed += 1;
            false
        }
    }
}

fn collect_stp(
    interface: &mut InterfaceObservation,
    frame: &l2_core::EthernetFrame<'_>,
    sequence: u64,
    quality: &mut Quality,
    tracker: &mut inventory::InventoryTracker,
    limits: &mut ResourceLimitStatus,
) -> bool {
    if !matches!(frame.field, FrameField::Length(_))
        || !frame.payload.starts_with(&[0x42, 0x42, 0x03])
    {
        return false;
    }
    match l2_codecs::decode_stp(frame.payload) {
        Ok(stp) => inventory::stp(
            interface,
            stp,
            sequence,
            frame.vlan_tags.is_empty(),
            tracker,
            limits,
        ),
        Err(
            StpError::UnsupportedVersion { .. }
            | StpError::UnsupportedType { .. }
            | StpError::UnsupportedExtension { .. },
        ) => {
            quality.unsupported_stp += 1;
            quality.unsupported_stp == 1
        }
        Err(_) => {
            quality.malformed += 1;
            false
        }
    }
}

fn evidence_ref(sequence: u64, packet: &CapturedFrame) -> EvidenceRef {
    let metadata = packet.metadata();
    let timestamp = metadata.timestamp();
    let units = timestamp.map(|time| {
        let resolution = time.resolution();
        (resolution.radix(), resolution.exponent())
    });
    EvidenceRef {
        sequence,
        section: metadata.interface().section,
        interface: metadata.interface().index,
        captured_len: packet.captured_len(),
        original_len: metadata.original_len(),
        sha256: sha256(packet.bytes()),
        locator: match metadata.locator() {
            Some(CaptureLocator::ClassicPcap {
                record_offset,
                data_offset,
            }) => EvidenceLocator::ClassicPcap {
                record_offset,
                data_offset,
            },
            Some(CaptureLocator::PcapNg {
                block_offset,
                data_offset,
                block_type,
            }) => EvidenceLocator::PcapNg {
                block_offset,
                data_offset,
                block_type,
            },
            None => EvidenceLocator::Unavailable,
        },
        timestamp_ticks: timestamp.map(CaptureTimestamp::ticks),
        timestamp_radix: units.map(|(radix, _)| radix),
        timestamp_exponent: units.map(|(_, exponent)| exponent),
        timestamp_offset_seconds: timestamp.map(CaptureTimestamp::offset_seconds),
        timestamp_source: timestamp.map(|time| format!("{:?}", time.source())),
        direction: format!("{:?}", metadata.direction()),
        fcs: format!("{:?}", metadata.fcs()),
        vlan_aux: metadata.vlan().map(|vlan| (vlan.tpid, vlan.tci)),
        linux_interface: metadata
            .linux_interface()
            .map(|identity| LinuxInterfaceEvidence {
                namespace_device: identity.namespace_device(),
                namespace_inode: identity.namespace_inode(),
                interface_device: identity.interface_device(),
                interface_inode: identity.interface_inode(),
                ifindex: identity.ifindex(),
            }),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '?',
    }
}
