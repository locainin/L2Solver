//! Checked runtime identity for capture interfaces

use l2_capture::InterfaceId;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Maximum number of capture interfaces that can be mapped in one assessment
pub const MAX_SOURCE_LABELS: usize = 4_096;
/// Maximum UTF-8 byte length for one stable source identity
pub const MAX_SOURCE_LABEL_BYTES: usize = 64;

/// A bounded, path-neutral operator identity for one capture source
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StableSourceLabel(String);

impl StableSourceLabel {
    /// Construct a checked source identity
    ///
    /// # Errors
    /// Returns [`SourceLabelMapError::InvalidLabel`] for an empty, excessive,
    /// non-ASCII, or path-like label
    pub fn new<S>(label: S) -> Result<Self, SourceLabelMapError>
    where
        S: Into<String>,
    {
        let label = label.into();
        if valid_source_label(&label) {
            Ok(Self(label))
        } else {
            Err(SourceLabelMapError::InvalidLabel { label })
        }
    }

    /// Return the canonical operator identity text
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the identity and return its canonical text
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for StableSourceLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl AsRef<str> for StableSourceLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<StableSourceLabel> for String {
    fn from(label: StableSourceLabel) -> Self {
        label.into_string()
    }
}

impl fmt::Display for StableSourceLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A checked mapping from capture-local interface IDs to operator labels
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceLabelMap {
    labels: BTreeMap<InterfaceId, StableSourceLabel>,
}

impl SourceLabelMap {
    /// Construct a bounded mapping and reject duplicate IDs or labels
    ///
    /// # Errors
    /// Returns an error when a label is unsafe, a source or label is repeated,
    /// or the mapping exceeds its hard bound
    pub fn new<I, Label>(entries: I) -> Result<Self, SourceLabelMapError>
    where
        I: IntoIterator<Item = (InterfaceId, Label)>,
        Label: Into<String>,
    {
        let mut labels = BTreeMap::new();
        let mut seen_labels = BTreeSet::new();
        for (source, label) in entries {
            if labels.len() == MAX_SOURCE_LABELS {
                return Err(SourceLabelMapError::TooManyMappings {
                    count: labels.len().saturating_add(1),
                    max: MAX_SOURCE_LABELS,
                });
            }
            let label = StableSourceLabel::new(label.into())?;
            if labels.contains_key(&source) {
                return Err(SourceLabelMapError::DuplicateInterface { source });
            }
            if !seen_labels.insert(label.clone()) {
                return Err(SourceLabelMapError::DuplicateLabel {
                    label: label.into_string(),
                });
            }
            labels.insert(source, label);
        }
        Ok(Self { labels })
    }

    /// Return an empty checked mapping
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            labels: BTreeMap::new(),
        }
    }

    /// Return the stable label assigned to one capture-local interface
    #[must_use]
    pub fn label_for(&self, source: InterfaceId) -> Option<&str> {
        self.labels.get(&source).map(StableSourceLabel::as_str)
    }

    /// Return the number of mapped capture interfaces
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Return whether no capture interfaces are mapped
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Require an exact mapping for a bounded set of observed interfaces
    ///
    /// # Errors
    /// Returns an error when an observed interface has no label, a mapping
    /// refers to an unobserved interface, or the source set is too large
    pub fn validate_for(&self, sources: &[InterfaceId]) -> Result<(), SourceLabelMapError> {
        if sources.len() > MAX_SOURCE_LABELS {
            return Err(SourceLabelMapError::TooManySources {
                count: sources.len(),
                max: MAX_SOURCE_LABELS,
            });
        }
        let mut observed = BTreeSet::new();
        for source in sources {
            if observed.insert(*source) && !self.labels.contains_key(source) {
                return Err(SourceLabelMapError::MissingSource { source: *source });
            }
        }
        if let Some(source) = self.labels.keys().find(|source| !observed.contains(source)) {
            return Err(SourceLabelMapError::UnexpectedSource { source: *source });
        }
        Ok(())
    }
}

/// Mapping validation failure that prevents policy resolution
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceLabelMapError {
    MissingMapping,
    InvalidLabel { label: String },
    DuplicateInterface { source: InterfaceId },
    DuplicateLabel { label: String },
    MissingSource { source: InterfaceId },
    UnexpectedSource { source: InterfaceId },
    TooManyMappings { count: usize, max: usize },
    TooManySources { count: usize, max: usize },
    UnboundLabel { label: String },
}

impl fmt::Display for SourceLabelMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMapping => {
                formatter.write_str("schema-three policy requires a runtime source-label mapping")
            }
            Self::InvalidLabel { label } => write!(
                formatter,
                "source label {label:?} must use 1..=64 safe ASCII bytes"
            ),
            Self::DuplicateInterface { source } => write!(
                formatter,
                "capture interface {}:{} has more than one source label",
                source.section, source.index
            ),
            Self::DuplicateLabel { label } => {
                write!(
                    formatter,
                    "source label {label:?} is assigned more than once"
                )
            }
            Self::MissingSource { source } => write!(
                formatter,
                "capture interface {}:{} has no stable source label",
                source.section, source.index
            ),
            Self::UnexpectedSource { source } => write!(
                formatter,
                "source label mapping includes unobserved interface {}:{}",
                source.section, source.index
            ),
            Self::TooManyMappings { count, max } => write!(
                formatter,
                "source label mapping contains {count} entries; maximum is {max}"
            ),
            Self::TooManySources { count, max } => write!(
                formatter,
                "capture contains {count} source interfaces; maximum is {max}"
            ),
            Self::UnboundLabel { label } => {
                write!(formatter, "source label {label:?} has no policy binding")
            }
        }
    }
}

impl std::error::Error for SourceLabelMapError {}

/// Return whether a source label is bounded and cannot escape its identity scope
#[must_use]
pub fn valid_source_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_SOURCE_LABEL_BYTES
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        && label
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}
