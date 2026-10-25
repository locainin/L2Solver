//! Policy coverage calculation for the observed capture scope

use super::input::PlannerInput;
use super::types::PolicyRequirement;
use crate::{AuditError, DEFAULT_SOURCE, Disposition, Policy, SegmentExpectations, SourceLabelMap};

/// Policy fields explicitly covered by the observed source scope
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PolicyCoverage {
    any: u16,
    all: u16,
    matched_source: bool,
    multiple_matched_sources: bool,
    all_have_stp_root_advertisements: bool,
}

impl PolicyCoverage {
    /// Gather policy coverage once before evaluating the check catalog
    pub(super) fn for_input(input: &PlannerInput, policy: &Policy) -> Self {
        let mut coverage = Self::default();
        if !input.capture_available() {
            return coverage;
        }
        if policy.uses_versioned_fields() {
            for source in input.sources() {
                if let Some(segment) = policy.versioned_segment_for(source.section, source.index) {
                    coverage.include_segment(segment, input.has_stp_root_advertisement(*source));
                }
            }
        } else if input.sources().contains(&DEFAULT_SOURCE) {
            coverage.include_legacy(policy, input.has_stp_root_advertisement(DEFAULT_SOURCE));
        }
        coverage
    }

    /// Gather policy coverage after resolving sources through stable labels
    pub(super) fn for_input_with_source_labels(
        input: &PlannerInput,
        policy: &Policy,
        labels: &SourceLabelMap,
    ) -> Result<Self, AuditError> {
        if !policy.uses_stable_fields() {
            return Ok(Self::for_input(input, policy));
        }
        let mut coverage = Self::default();
        if !input.capture_available() {
            return Ok(coverage);
        }
        for source in input.sources() {
            if let Some(segment) = policy.versioned_segment_for_source(*source, labels)? {
                coverage.include_segment(segment, input.has_stp_root_advertisement(*source));
            }
        }
        Ok(coverage)
    }

    /// Add every explicit field represented by one borrowed segment
    fn include_segment(&mut self, segment: &SegmentExpectations, has_stp_root: bool) {
        let mut fields = 0_u16;
        if segment.allowed_vlans.is_some() {
            fields |= PolicyRequirement::AllowedVlans.mask();
        }
        if segment.require_8021x == Some(true) {
            fields |= PolicyRequirement::Dot1xRequired.mask();
        }
        if segment.lldp != Disposition::Unspecified {
            fields |= PolicyRequirement::LldpVisibility.mask();
        }
        if segment.priority_tagged != Disposition::Unspecified {
            fields |= PolicyRequirement::PriorityTaggedFrames.mask();
        }
        if segment.stp_endpoint != Disposition::Unspecified {
            fields |= PolicyRequirement::StpEndpointVisibility.mask();
        }
        if segment.untagged != Disposition::Unspecified {
            fields |= PolicyRequirement::UntaggedFrames.mask();
        }
        if segment.max_vlan_depth.is_some() {
            fields |= PolicyRequirement::MaximumVlanDepth.mask();
        }
        if segment.expected_stp_bridge.is_some() {
            fields |= PolicyRequirement::ExpectedStpRoot.mask();
        }
        if !segment.protocols.is_empty() {
            fields |= PolicyRequirement::ProtocolPolicy.mask();
        }
        if !segment.isolation_from.is_empty() || !segment.allow_to.is_empty() {
            fields |= PolicyRequirement::SegmentationPaths.mask();
        }
        self.include_fields(fields, has_stp_root);
    }

    /// Add every explicit field represented by the legacy capture scope
    const fn include_legacy(&mut self, policy: &Policy, has_stp_root: bool) {
        let mut fields = 0_u16;
        if policy.allowed_vlans.is_some() {
            fields |= PolicyRequirement::AllowedVlans.mask();
        }
        if policy.allow_untagged.is_some() {
            fields |= PolicyRequirement::UntaggedFrames.mask();
        }
        if policy.allow_priority_tagged.is_some() {
            fields |= PolicyRequirement::PriorityTaggedFrames.mask();
        }
        if policy.max_vlan_depth.is_some() {
            fields |= PolicyRequirement::MaximumVlanDepth.mask();
        }
        if policy.expected_stp_bridge.is_some() || policy.expected_stp_root.is_some() {
            fields |= PolicyRequirement::ExpectedStpRoot.mask();
        }
        self.include_fields(fields, has_stp_root);
    }

    /// Merge one matched source while retaining partial and complete coverage
    const fn include_fields(&mut self, fields: u16, has_stp_root: bool) {
        self.any |= fields;
        if self.matched_source {
            self.all &= fields;
            self.all_have_stp_root_advertisements &= has_stp_root;
            self.multiple_matched_sources = true;
        } else {
            self.all = fields;
            self.all_have_stp_root_advertisements = has_stp_root;
            self.matched_source = true;
        }
    }

    /// Return whether any matched source supplies one policy requirement
    #[must_use]
    pub(super) const fn contains_any(self, requirement: PolicyRequirement) -> bool {
        self.any & requirement.mask() != 0
    }

    /// Return whether every matched source supplies one policy requirement
    #[must_use]
    pub(super) const fn contains_all(self, requirement: PolicyRequirement) -> bool {
        self.matched_source && self.all & requirement.mask() != 0
    }

    /// Return whether every matched source supplied a root-bearing advertisement
    #[must_use]
    pub(super) const fn all_have_stp_root_advertisements(self) -> bool {
        self.matched_source && self.all_have_stp_root_advertisements
    }

    /// Return whether more than one source contributed to policy coverage
    #[must_use]
    pub(super) const fn has_multiple_sources(self) -> bool {
        self.multiple_matched_sources
    }
}
