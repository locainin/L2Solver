use super::super::FileRange;
use serde::Serialize;

/// Provenance for the built-in, reviewed signature catalogue
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FileSignatureCatalogue {
    /// Stable catalogue schema and review revision
    pub version: u32,
    /// Human-readable catalogue name
    pub name: &'static str,
    /// Reference used to seed the byte patterns and declared offsets
    pub source: &'static str,
    /// Date on which the checked-in rules were reviewed
    pub reviewed_on: &'static str,
    /// Number of rules evaluated against the supplied byte object
    pub rules_evaluated: usize,
}

/// Whether every byte or only the non-wildcard bytes constrained a match
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileSignatureMatchKind {
    /// Every byte in the signature was compared exactly
    Exact,
    /// Explicit wildcard positions were ignored while every other byte matched
    Masked,
}

/// One exact or deliberately masked byte-pattern observation at its defined offset
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FileSignatureMatch {
    /// Stable rule identity for queries and reproducible reports
    pub rule_id: &'static str,
    /// Short factual description of the signature family
    pub description: &'static str,
    /// Possible formats supported by this signature alone
    pub possible_formats: &'static [&'static str],
    /// Common filename extensions, without claiming the supplied name is correct
    pub extensions: &'static [&'static str],
    /// Common media types when the format has a useful registered or conventional value
    pub media_types: &'static [&'static str],
    /// Published reference supporting this rule's bytes and offset
    pub reference: &'static str,
    /// Exact source-object bytes that supported this observation
    pub range: FileRange,
    /// Lowercase hexadecimal pattern with `??` for deliberate wildcard positions
    pub pattern_hex: String,
    /// Lowercase hexadecimal bytes observed in the supplied object
    pub observed_hex: String,
    /// Exact or masked comparison semantics
    pub match_kind: FileSignatureMatchKind,
    /// Whether the signature has multiple meanings or names only a shared container
    pub ambiguous: bool,
    /// Calibrated boundary on what the byte observation establishes
    pub interpretation: &'static str,
}

/// Complete evaluation of the built-in catalogue against one selected byte object
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct FileSignatureReport {
    /// Schema revision for this report shape
    pub schema_version: u32,
    /// SHA-256 of the exact bytes evaluated
    pub source_sha256: String,
    /// Number of supplied bytes
    pub source_length: usize,
    /// Catalogue identity and coverage
    pub catalogue: FileSignatureCatalogue,
    /// Every supported rule that matched at its declared relative offset
    pub matches: Vec<FileSignatureMatch>,
    /// Scope and interpretation boundaries that apply even when no rule matched
    pub limitations: &'static [&'static str],
}

/// A retained match together with the catalogue revision that produced it
#[derive(Clone, Copy, Debug, Serialize)]
#[non_exhaustive]
pub struct FileSignatureEvidence<'a> {
    // Flattening keeps stable match fields directly queryable in a case node
    #[serde(flatten)]
    signature: &'a FileSignatureMatch,
    catalogue: &'a FileSignatureCatalogue,
}

impl FileSignatureReport {
    /// Pair every match with immutable catalogue provenance for persistence
    pub fn evidence_matches(&self) -> impl Iterator<Item = FileSignatureEvidence<'_>> {
        self.matches.iter().map(|signature| FileSignatureEvidence {
            signature,
            catalogue: &self.catalogue,
        })
    }
}

impl<'a> FileSignatureEvidence<'a> {
    /// Access the match while preserving the catalogue wrapper for serialization
    #[must_use]
    pub const fn signature(&self) -> &'a FileSignatureMatch {
        self.signature
    }
}
