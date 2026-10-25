//! Versioned policy expectations for flat and multi-interface assessments

use crate::policy_schema::{RawPolicy, RawPorts};
use crate::{
    AuditError, BridgeIdentity, DEFAULT_SOURCE, Protocol, SourceLabelMap, SourceLabelMapError,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use std::collections::{BTreeMap, BTreeSet};

use self::policy_validation::{
    disposition, validate_label, validate_segment, validate_stp_pair, validate_vlan_depth,
    validate_vlan_list,
};

#[path = "policy_validation.rs"]
mod policy_validation;

pub use crate::policy_schema::StablePortBinding;

const POLICY_SCHEMA_V2: u32 = 2;
const POLICY_SCHEMA_V3: u32 = 3;
const MAX_POLICY_PORTS: usize = 4_096;
const MAX_POLICY_SEGMENTS: usize = 4_096;

/// Whether one observable behavior is allowed by a segment policy
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Allowed,
    Forbidden,
    #[default]
    Unspecified,
}

/// Expectations shared by all capture interfaces bound to one segment
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SegmentExpectations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_vlans: Option<BTreeSet<u16>>,
    pub priority_tagged: Disposition,
    pub untagged: Disposition,
    pub max_vlan_depth: Option<u8>,
    pub expected_stp_bridge: Option<BridgeIdentity>,
    pub lldp: Disposition,
    pub stp_endpoint: Disposition,
    pub require_8021x: Option<bool>,
    pub protocols: BTreeMap<Protocol, Disposition>,
    pub isolation_from: BTreeSet<String>,
    pub allow_to: BTreeSet<String>,
}

/// One PCAPNG source interface or live source bound to a segment role
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortBinding {
    pub section: u32,
    pub index: u32,
    pub segment: String,
    pub role: String,
}

/// Effective expectations selected for one source interface
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedExpectations {
    pub segment: String,
    pub role: String,
    pub allowed_vlans: BTreeSet<u16>,
    pub priority_tagged: Disposition,
    pub untagged: Disposition,
    pub max_vlan_depth: Option<u8>,
    pub expected_stp_bridge: Option<BridgeIdentity>,
    pub expected_stp_root: Option<String>,
    pub lldp: Disposition,
    pub stp_endpoint: Disposition,
    pub require_8021x: Option<bool>,
    pub protocols: BTreeMap<Protocol, Disposition>,
    pub isolation_from: BTreeSet<String>,
    pub allow_to: BTreeSet<String>,
    allowed_vlans_specified: bool,
}

impl ResolvedExpectations {
    /// Whether the selected policy explicitly constrains tagged VLANs
    #[must_use]
    pub const fn has_allowed_vlan_policy(&self) -> bool {
        self.allowed_vlans_specified
    }
}

/// Explicit expectations applied to one capture or multiple bound interfaces
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub allowed_vlans: Option<Vec<u16>>,
    pub allow_priority_tagged: Option<bool>,
    pub allow_untagged: Option<bool>,
    pub max_vlan_depth: Option<u8>,
    pub expected_stp_bridge: Option<BridgeIdentity>,
    pub expected_stp_root: Option<String>,
    pub schema_version: Option<u32>,
    pub segments: Option<BTreeMap<String, SegmentExpectations>>,
    pub ports: Option<Vec<PortBinding>>,
    /// Schema-three bindings keyed by stable operator source labels
    pub stable_ports: Option<Vec<StablePortBinding>>,
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPolicy::deserialize(deserializer)?;
        let (ports, stable_ports) = match (raw.schema_version, raw.ports) {
            // An empty untagged array has no fields to distinguish its schema
            (Some(POLICY_SCHEMA_V3), Some(RawPorts::Ordinal(bindings))) if bindings.is_empty() => {
                (None, Some(Vec::new()))
            }
            (_, Some(RawPorts::Ordinal(bindings))) => (Some(bindings), None),
            (_, Some(RawPorts::Stable(bindings))) => (None, Some(bindings)),
            (_, None) => (None, None),
        };

        Ok(Self {
            allowed_vlans: raw.allowed_vlans,
            allow_priority_tagged: raw.allow_priority_tagged,
            allow_untagged: raw.allow_untagged,
            max_vlan_depth: raw.max_vlan_depth,
            expected_stp_bridge: raw.expected_stp_bridge,
            expected_stp_root: raw.expected_stp_root,
            schema_version: raw.schema_version,
            segments: raw.segments,
            ports,
            stable_ports,
        })
    }
}

impl Policy {
    /// Validate either the legacy flat policy or a complete versioned model
    ///
    /// # Errors
    ///
    /// Rejects mixed schemas, invalid identifiers, duplicate source bindings,
    /// broken segment references, and values outside absolute policy bounds
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.uses_versioned_fields() {
            return self.validate_versioned();
        }
        self.validate_legacy()
    }

    /// Resolve the expectations that apply to one capture interface
    #[must_use]
    pub fn expectations_for(&self, section: u32, index: u32) -> Option<ResolvedExpectations> {
        if self.uses_stable_fields() {
            return None;
        }
        if self.uses_versioned_fields() {
            return self.versioned_expectations(section, index);
        }
        if section == DEFAULT_SOURCE.section && index == DEFAULT_SOURCE.index {
            self.legacy_expectations()
        } else {
            None
        }
    }

    /// Resolve one capture interface through its checked stable source label
    ///
    /// Schema two keeps resolving capture section and IDB index directly. The
    /// schema-three path requires a runtime label for every source so an IDB
    /// reorder cannot silently change the selected segment
    ///
    /// # Errors
    /// Returns an error when a schema-three source has no runtime label or its
    /// label is not bound by the policy
    pub fn expectations_for_source(
        &self,
        source: l2_capture::InterfaceId,
        labels: &SourceLabelMap,
    ) -> Result<Option<ResolvedExpectations>, AuditError> {
        if self.uses_stable_fields() {
            let label = labels.label_for(source).ok_or_else(|| {
                source_mapping_error(SourceLabelMapError::MissingSource { source })
            })?;
            let Some((binding, expectations)) = self.stable_binding_for(label) else {
                return Err(source_mapping_error(SourceLabelMapError::UnboundLabel {
                    label: label.to_owned(),
                }));
            };
            return Ok(Some(resolved_expectations(
                &binding.segment,
                &binding.role,
                expectations,
            )));
        }
        Ok(self.expectations_for(source.section, source.index))
    }

    /// Validate the complete runtime mapping needed by a policy and source set
    ///
    /// # Errors
    /// Returns an error when schema three is missing a source mapping, contains
    /// an extra mapping, or maps a source to an unbound policy label
    pub fn validate_source_mapping(
        &self,
        labels: &SourceLabelMap,
        sources: &[l2_capture::InterfaceId],
    ) -> Result<(), AuditError> {
        self.validate()?;
        if !self.uses_stable_fields() {
            return Ok(());
        }
        labels.validate_for(sources).map_err(source_mapping_error)?;
        for source in sources {
            self.expectations_for_source(*source, labels)?;
        }
        Ok(())
    }

    /// Borrow the segment expectations bound to one versioned source
    pub(crate) fn versioned_segment_for(
        &self,
        section: u32,
        index: u32,
    ) -> Option<&SegmentExpectations> {
        if self.schema_version != Some(POLICY_SCHEMA_V2) {
            return None;
        }
        self.versioned_binding_for(section, index)
            .map(|(_, expectations)| expectations)
    }

    pub(crate) fn versioned_segment_for_source(
        &self,
        source: l2_capture::InterfaceId,
        labels: &SourceLabelMap,
    ) -> Result<Option<&SegmentExpectations>, AuditError> {
        if self.schema_version == Some(POLICY_SCHEMA_V2) {
            return Ok(self.versioned_segment_for(source.section, source.index));
        }
        if !self.uses_stable_fields() {
            return Ok(None);
        }
        let label = labels
            .label_for(source)
            .ok_or_else(|| source_mapping_error(SourceLabelMapError::MissingSource { source }))?;
        Ok(self
            .stable_binding_for(label)
            .map(|(_, expectations)| expectations))
    }

    pub(crate) const fn uses_versioned_fields(&self) -> bool {
        self.schema_version.is_some()
            || self.segments.is_some()
            || self.ports.is_some()
            || self.stable_ports.is_some()
    }

    pub(crate) fn uses_stable_fields(&self) -> bool {
        self.schema_version == Some(POLICY_SCHEMA_V3) || self.stable_ports.is_some()
    }

    fn validate_legacy(&self) -> Result<(), AuditError> {
        validate_vlan_list(self.allowed_vlans.as_deref())?;
        validate_vlan_depth(self.max_vlan_depth)?;
        validate_stp_pair(
            self.expected_stp_bridge.as_ref(),
            self.expected_stp_root.as_deref(),
        )
    }

    fn validate_versioned(&self) -> Result<(), AuditError> {
        match self.schema_version {
            Some(POLICY_SCHEMA_V2) => self.validate_version_two(),
            Some(POLICY_SCHEMA_V3) => self.validate_version_three(),
            _ => Err(AuditError::Policy("versioned policy schema must be 2 or 3")),
        }
    }

    fn validate_version_two(&self) -> Result<(), AuditError> {
        let (Some(segments), Some(ports)) = (&self.segments, &self.ports) else {
            return Err(AuditError::Policy(
                "version-two policy requires segments and ports",
            ));
        };
        if self.stable_ports.is_some() {
            return Err(AuditError::Policy(
                "version-two policy cannot contain stable source bindings",
            ));
        }
        Self::validate_segments(segments)?;
        if self.has_legacy_fields() {
            return Err(AuditError::Policy(
                "versioned and legacy policy fields cannot be mixed",
            ));
        }
        if segments.len() > MAX_POLICY_SEGMENTS || ports.len() > MAX_POLICY_PORTS {
            return Err(AuditError::Policy(
                "versioned policy collection limit exceeded",
            ));
        }

        let mut sources = BTreeSet::new();
        for port in ports {
            validate_label(&port.segment)?;
            validate_label(&port.role)?;
            if !segments.contains_key(&port.segment) {
                return Err(AuditError::Policy("port references an unknown segment"));
            }
            if !sources.insert((port.section, port.index)) {
                return Err(AuditError::Policy("duplicate source interface binding"));
            }
        }
        Ok(())
    }

    fn validate_version_three(&self) -> Result<(), AuditError> {
        let (Some(segments), Some(ports)) = (&self.segments, &self.stable_ports) else {
            return Err(AuditError::Policy(
                "version-three policy requires segments and stable source ports",
            ));
        };
        if self.ports.is_some() {
            return Err(AuditError::Policy(
                "version-three policy cannot contain ordinal source bindings",
            ));
        }
        Self::validate_segments(segments)?;
        if self.has_legacy_fields() {
            return Err(AuditError::Policy(
                "versioned and legacy policy fields cannot be mixed",
            ));
        }
        if ports.len() > MAX_POLICY_PORTS {
            return Err(AuditError::Policy(
                "versioned policy collection limit exceeded",
            ));
        }

        let mut sources = BTreeSet::new();
        for port in ports {
            validate_label(&port.segment)?;
            validate_label(&port.role)?;
            if !segments.contains_key(&port.segment) {
                return Err(AuditError::Policy("port references an unknown segment"));
            }
            if !sources.insert(&port.source) {
                return Err(AuditError::Policy("duplicate stable source binding"));
            }
        }
        Ok(())
    }

    fn validate_segments(
        segments: &BTreeMap<String, SegmentExpectations>,
    ) -> Result<(), AuditError> {
        if segments.len() > MAX_POLICY_SEGMENTS {
            return Err(AuditError::Policy(
                "versioned policy collection limit exceeded",
            ));
        }
        for (name, expectations) in segments {
            validate_label(name)?;
            validate_segment(expectations, segments)?;
        }
        Ok(())
    }

    const fn has_legacy_fields(&self) -> bool {
        self.allowed_vlans.is_some()
            || self.allow_priority_tagged.is_some()
            || self.allow_untagged.is_some()
            || self.max_vlan_depth.is_some()
            || self.expected_stp_bridge.is_some()
            || self.expected_stp_root.is_some()
    }

    fn versioned_expectations(&self, section: u32, index: u32) -> Option<ResolvedExpectations> {
        if self.schema_version != Some(POLICY_SCHEMA_V2) {
            return None;
        }
        let (binding, expectations) = self.versioned_binding_for(section, index)?;
        Some(resolved_expectations(
            &binding.segment,
            &binding.role,
            expectations,
        ))
    }

    fn versioned_binding_for(
        &self,
        section: u32,
        index: u32,
    ) -> Option<(&PortBinding, &SegmentExpectations)> {
        let ports = self.ports.as_ref()?;
        let segments = self.segments.as_ref()?;
        let binding = ports
            .iter()
            .find(|binding| binding.section == section && binding.index == index)?;
        let expectations = segments.get(&binding.segment)?;
        Some((binding, expectations))
    }

    fn stable_binding_for(
        &self,
        source: &str,
    ) -> Option<(&StablePortBinding, &SegmentExpectations)> {
        let ports = self.stable_ports.as_ref()?;
        let segments = self.segments.as_ref()?;
        let binding = ports
            .iter()
            .find(|binding| binding.source.as_str() == source)?;
        let expectations = segments.get(&binding.segment)?;
        Some((binding, expectations))
    }

    fn legacy_expectations(&self) -> Option<ResolvedExpectations> {
        if !self.has_legacy_fields() {
            return None;
        }
        Some(ResolvedExpectations {
            segment: "legacy capture scope".into(),
            role: "unspecified".into(),
            allowed_vlans: self
                .allowed_vlans
                .as_ref()
                .map_or_else(BTreeSet::new, |values| values.iter().copied().collect()),
            priority_tagged: disposition(self.allow_priority_tagged),
            untagged: disposition(self.allow_untagged),
            max_vlan_depth: self.max_vlan_depth,
            expected_stp_bridge: self.expected_stp_bridge.clone(),
            expected_stp_root: self.expected_stp_root.clone(),
            lldp: Disposition::Unspecified,
            stp_endpoint: Disposition::Unspecified,
            require_8021x: None,
            protocols: BTreeMap::new(),
            isolation_from: BTreeSet::new(),
            allow_to: BTreeSet::new(),
            allowed_vlans_specified: self.allowed_vlans.is_some(),
        })
    }
}

const fn source_mapping_error(error: SourceLabelMapError) -> AuditError {
    AuditError::SourceMapping(error)
}

fn resolved_expectations(
    segment: &str,
    role: &str,
    expectations: &SegmentExpectations,
) -> ResolvedExpectations {
    ResolvedExpectations {
        segment: segment.to_owned(),
        role: role.to_owned(),
        allowed_vlans: expectations.allowed_vlans.clone().unwrap_or_default(),
        priority_tagged: expectations.priority_tagged,
        untagged: expectations.untagged,
        max_vlan_depth: expectations.max_vlan_depth,
        expected_stp_bridge: expectations.expected_stp_bridge.clone(),
        expected_stp_root: None,
        lldp: expectations.lldp,
        stp_endpoint: expectations.stp_endpoint,
        require_8021x: expectations.require_8021x,
        protocols: expectations.protocols.clone(),
        isolation_from: expectations.isolation_from.clone(),
        allow_to: expectations.allow_to.clone(),
        allowed_vlans_specified: expectations.allowed_vlans.is_some(),
    }
}

impl Serialize for Policy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Policy", 9)?;
        state.serialize_field("allowed_vlans", &self.allowed_vlans)?;
        state.serialize_field("allow_priority_tagged", &self.allow_priority_tagged)?;
        state.serialize_field("allow_untagged", &self.allow_untagged)?;
        state.serialize_field("max_vlan_depth", &self.max_vlan_depth)?;
        state.serialize_field("expected_stp_bridge", &self.expected_stp_bridge)?;
        state.serialize_field("expected_stp_root", &self.expected_stp_root)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("segments", &self.segments)?;
        if self.uses_stable_fields() {
            let ordered_ports = self.stable_ports.as_ref().map(|ports| {
                let mut ordered: Vec<_> = ports.iter().collect();
                ordered.sort_by_key(|port| (&port.source, &port.segment, &port.role));
                ordered
            });
            state.serialize_field("ports", &ordered_ports)?;
        } else {
            let ordered_ports = self.ports.as_ref().map(|ports| {
                let mut ordered: Vec<_> = ports.iter().collect();
                ordered.sort_by_key(|port| (port.section, port.index, &port.segment, &port.role));
                ordered
            });
            state.serialize_field("ports", &ordered_ports)?;
        }
        state.end()
    }
}
