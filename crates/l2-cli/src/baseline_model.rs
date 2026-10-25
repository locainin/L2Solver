//! Bounded, typed observation facts for stable baseline comparison

pub use l2_audit::StableSourceLabel as StableSource;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_FACTS: usize = 65_536;
pub const MAX_FACT_BYTES: usize = 2_048;
pub const MAX_BASELINE_FACT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BASELINE_JSON_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaselineError {
    UnsupportedSchema { found: u32, expected: u32 },
    TooManyFacts { count: usize, max: usize },
    FactTooLong { length: usize, max: usize },
    TotalBytesExceeded { total: usize, max: usize },
}

impl fmt::Display for BaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { found, expected } => write!(
                formatter,
                "unsupported baseline schema version {found}; expected {expected}"
            ),
            Self::TooManyFacts { count, max } => {
                write!(
                    formatter,
                    "baseline contains {count} facts; maximum is {max}"
                )
            }
            Self::FactTooLong { length, max } => write!(
                formatter,
                "baseline fact has {length} data bytes; maximum is {max}"
            ),
            Self::TotalBytesExceeded { total, max } => write!(
                formatter,
                "baseline facts contain {total} data bytes; maximum is {max}"
            ),
        }
    }
}

impl std::error::Error for BaselineError {}

/// Return the conventional identity for a capture with one source
///
/// # Errors
/// Returns an error only if the built-in label stops satisfying the shared
/// source-label contract
pub fn single_capture_source() -> Result<StableSource, l2_audit::SourceLabelMapError> {
    StableSource::new("capture")
}

/// One typed, source-scoped observation retained without presentation formatting
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BaselineFact {
    SourceMac {
        source: StableSource,
        mac: String,
    },
    VlanStack {
        source: StableSource,
        tags: Vec<(u16, u16)>,
    },
    UntaggedTraffic {
        source: StableSource,
    },
    LldpNeighbor {
        source: StableSource,
        chassis_id: Vec<u8>,
        port_id: Vec<u8>,
        system_name: Vec<u8>,
    },
    Protocol {
        source: StableSource,
        protocol: String,
        status: String,
    },
    ProtocolIdentity {
        source: StableSource,
        protocol: String,
        role: String,
        outer_source_mac: String,
        claimed_mac: Option<String>,
        address: Option<String>,
        vlan_tags: Vec<(u16, u16)>,
    },
    StpRoot {
        source: StableSource,
        priority: u16,
        system_id_extension: u16,
        mac: String,
        version: String,
    },
}

impl BaselineFact {
    fn data_bytes(&self) -> usize {
        match self {
            Self::SourceMac { source, mac } => source.as_str().len() + mac.len(),
            Self::VlanStack { source, tags } => source.as_str().len() + tags.len() * 4,
            Self::UntaggedTraffic { source } => source.as_str().len(),
            Self::LldpNeighbor {
                source,
                chassis_id,
                port_id,
                system_name,
            } => source.as_str().len() + chassis_id.len() + port_id.len() + system_name.len(),
            Self::Protocol {
                source,
                protocol,
                status,
            } => source.as_str().len() + protocol.len() + status.len(),
            Self::ProtocolIdentity {
                source,
                protocol,
                role,
                outer_source_mac,
                claimed_mac,
                address,
                vlan_tags,
            } => {
                source.as_str().len()
                    + protocol.len()
                    + role.len()
                    + outer_source_mac.len()
                    + claimed_mac.as_ref().map_or(0, String::len)
                    + address.as_ref().map_or(0, String::len)
                    + vlan_tags.len() * 4
            }
            Self::StpRoot {
                source,
                mac,
                version,
                ..
            } => source.as_str().len() + mac.len() + version.len() + 4,
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::SourceMac { source, mac } => {
                format!("source {} MAC {mac}", source.as_str())
            }
            Self::VlanStack { source, tags } => {
                format!("source {} VLAN stack {tags:?} (TPID, TCI)", source.as_str())
            }
            Self::UntaggedTraffic { source } => {
                format!("source {} untagged traffic", source.as_str())
            }
            Self::LldpNeighbor {
                source,
                chassis_id,
                port_id,
                system_name,
            } => format!(
                "source {} LLDP chassis={chassis_id:?} port={port_id:?} name={system_name:?}",
                source.as_str()
            ),
            Self::Protocol {
                source,
                protocol,
                status,
            } => format!(
                "source {} protocol={protocol} status={status}",
                source.as_str()
            ),
            Self::ProtocolIdentity {
                source,
                protocol,
                role,
                outer_source_mac,
                claimed_mac,
                address,
                vlan_tags,
            } => format!(
                "source {} protocol={protocol} role={role} source={outer_source_mac} claimed={claimed_mac:?} address={address:?} vlan_tags={vlan_tags:?}",
                source.as_str()
            ),
            Self::StpRoot {
                source,
                priority,
                system_id_extension,
                mac,
                version,
            } => format!(
                "source {} STP root={mac} priority={priority} system_id_extension={system_id_extension} version={version}",
                source.as_str()
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema_version: u32,
    pub facts: BTreeSet<BaselineFact>,
}

impl Baseline {
    /// Construct a checked current-schema baseline
    ///
    /// # Errors
    /// Returns an error when a hard count, source, or byte limit is exceeded
    pub fn new(facts: BTreeSet<BaselineFact>) -> Result<Self, BaselineError> {
        let baseline = Self {
            schema_version: SCHEMA_VERSION,
            facts,
        };
        baseline.validate()?;
        Ok(baseline)
    }

    /// Validate imported baseline facts before comparison
    ///
    /// # Errors
    /// Returns an error for an unknown schema or exceeded model limit
    pub fn validate(&self) -> Result<(), BaselineError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedSchema {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if self.facts.len() > MAX_FACTS {
            return Err(BaselineError::TooManyFacts {
                count: self.facts.len(),
                max: MAX_FACTS,
            });
        }
        let mut total = 0_usize;
        for fact in &self.facts {
            let length = fact.data_bytes();
            if length > MAX_FACT_BYTES {
                return Err(BaselineError::FactTooLong {
                    length,
                    max: MAX_FACT_BYTES,
                });
            }
            total += length;
        }
        if total > MAX_BASELINE_FACT_BYTES {
            return Err(BaselineError::TotalBytesExceeded {
                total,
                max: MAX_BASELINE_FACT_BYTES,
            });
        }
        Ok(())
    }

    /// Compare two checked typed observation sets
    ///
    /// # Errors
    /// Returns the first validation error from either baseline
    pub fn compare(&self, current: &Self) -> Result<Vec<Change>, BaselineError> {
        self.validate()?;
        current.validate()?;

        let mut changes = Vec::new();
        changes.extend(
            current
                .facts
                .difference(&self.facts)
                .cloned()
                .map(|observation| Change {
                    kind: ChangeKind::Added,
                    observation,
                }),
        );
        changes.extend(
            self.facts
                .difference(&current.facts)
                .cloned()
                .map(|observation| Change {
                    kind: ChangeKind::NotObserved,
                    observation,
                }),
        );
        changes.sort_unstable_by(|left, right| left.observation.cmp(&right.observation));
        Ok(changes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    NotObserved,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub observation: BaselineFact,
}
