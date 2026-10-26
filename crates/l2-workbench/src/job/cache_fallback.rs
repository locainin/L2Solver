//! Keep cache failures observable without changing recovery completeness or retaining payloads

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};

const MAX_SAMPLE_BYTES: usize = 160;
const TRUNCATION_MARKER: &str = "...";
// Leave room for a visible marker without cutting a character's escape sequence
const MAX_SAMPLE_CONTENT_BYTES: usize = MAX_SAMPLE_BYTES - TRUNCATION_MARKER.len();
// Each stage and failure pair occupies one record even when many workers report it
const MAX_RECORDS: usize = CacheStage::ALL.len() * CacheFallbackKind::ALL.len();

/// Identifies the persistent cache stage that used a fallback
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CacheStage {
    /// Capture index acquisition
    CaptureIndex,
    /// Per-flow or per-cohort recovery
    CaseRecovery,
    /// File artifact analysis during refinement
    ArtifactAnalysis,
}

impl CacheStage {
    const ALL: [Self; 3] = [
        Self::CaptureIndex,
        Self::CaseRecovery,
        Self::ArtifactAnalysis,
    ];

    /// Returns the short name used by text renderers
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CaptureIndex => "capture index",
            Self::CaseRecovery => "Case recovery",
            Self::ArtifactAnalysis => "artifact analysis",
        }
    }
}

/// Identifies why one cache stage continued without using its entry
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CacheFallbackKind {
    /// A cached value could not be validated or restored
    InvalidEntry,
    /// A cache read failed
    LookupFailed,
    /// A cache write lease was unavailable
    LeaseUnavailable,
    /// A cache entry could not be committed
    CommitFailed,
    /// The persistent cache could not be opened
    CacheUnavailable,
    /// Another process held a cache lock beyond the wait bound
    ContentionFallback,
}

impl CacheFallbackKind {
    const ALL: [Self; 6] = [
        Self::InvalidEntry,
        Self::LookupFailed,
        Self::LeaseUnavailable,
        Self::CommitFailed,
        Self::CacheUnavailable,
        Self::ContentionFallback,
    ];

    /// Returns the short name used by text renderers
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InvalidEntry => "invalid entry",
            Self::LookupFailed => "lookup failed",
            Self::LeaseUnavailable => "write lease unavailable",
            Self::CommitFailed => "write failed",
            Self::CacheUnavailable => "cache unavailable",
            Self::ContentionFallback => "lock contention fallback",
        }
    }
}

/// One aggregated cache fallback category and its bounded sample detail
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct CacheFallbackRecord {
    stage: CacheStage,
    kind: CacheFallbackKind,
    count: u64,
    sample_detail: Option<String>,
}

impl CacheFallbackRecord {
    /// Returns the cache stage for this fallback category
    #[must_use]
    pub const fn stage(&self) -> CacheStage {
        self.stage
    }

    /// Returns the failure type for this fallback category
    #[must_use]
    pub const fn kind(&self) -> CacheFallbackKind {
        self.kind
    }

    /// Returns the number of fallbacks in this category
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the escaped sample detail, when one was recorded
    #[must_use]
    pub fn sample_detail(&self) -> Option<&str> {
        self.sample_detail.as_deref()
    }
}

impl<'de> Deserialize<'de> for CacheFallbackRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRecord {
            stage: CacheStage,
            kind: CacheFallbackKind,
            count: u64,
            sample_detail: Option<BoundedSample>,
        }

        let record = WireRecord::deserialize(deserializer)?;
        if record.count == 0 {
            return Err(de::Error::custom("cache fallback count must be nonzero"));
        }

        Ok(Self {
            stage: record.stage,
            kind: record.kind,
            count: record.count,
            sample_detail: record.sample_detail.map(|sample| sample.0),
        })
    }
}

struct BoundedSample(String);

impl<'de> Deserialize<'de> for BoundedSample {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedSampleVisitor;

        impl Visitor<'_> for BoundedSampleVisitor {
            type Value = BoundedSample;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "escaped text with at most {MAX_SAMPLE_BYTES} bytes"
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                validate_sample::<E>(value)?;
                let mut copied = String::new();
                copied.try_reserve_exact(value.len()).map_err(E::custom)?;
                copied.push_str(value);
                Ok(BoundedSample(copied))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                validate_sample::<E>(&value)?;
                Ok(BoundedSample(value))
            }
        }

        deserializer.deserialize_str(BoundedSampleVisitor)
    }
}

fn validate_sample<E: de::Error>(sample: &str) -> Result<(), E> {
    if sample.is_empty()
        || sample.len() > MAX_SAMPLE_BYTES
        || !sample.is_ascii()
        || sample.chars().any(char::is_control)
    {
        return Err(E::custom(
            "cache fallback sample is not bounded escaped text",
        ));
    }
    Ok(())
}

/// Bounded cache fallback counts retained in a job snapshot
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CacheFallbackSummary {
    records: Vec<CacheFallbackRecord>,
}

impl CacheFallbackSummary {
    /// Returns fallback records in stable stage and failure order
    #[must_use]
    pub fn records(&self) -> &[CacheFallbackRecord] {
        &self.records
    }

    pub(super) fn record(
        &mut self,
        stage: CacheStage,
        kind: CacheFallbackKind,
        sample_detail: Option<String>,
    ) {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.stage == stage && record.kind == kind)
        {
            record.count = record.count.saturating_add(1);
            prefer_sample(&mut record.sample_detail, sample_detail);
            return;
        }

        if self.records.len() < MAX_RECORDS {
            self.records.push(CacheFallbackRecord {
                stage,
                kind,
                count: 1,
                sample_detail,
            });
            self.records
                .sort_unstable_by_key(|record| (record.stage, record.kind));
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        for record in other.records {
            if let Some(existing) = self
                .records
                .iter_mut()
                .find(|existing| existing.stage == record.stage && existing.kind == record.kind)
            {
                existing.count = existing.count.saturating_add(record.count);
                prefer_sample(&mut existing.sample_detail, record.sample_detail);
            } else if self.records.len() < MAX_RECORDS {
                self.records.push(record);
                self.records
                    .sort_unstable_by_key(|entry| (entry.stage, entry.kind));
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacheFallbackSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSummary {
            #[serde(default)]
            records: BoundedRecords,
        }

        let mut records = WireSummary::deserialize(deserializer)?.records.0;
        records.sort_unstable_by_key(|record| (record.stage, record.kind));
        Ok(Self { records })
    }
}

#[derive(Default)]
struct BoundedRecords(Vec<CacheFallbackRecord>);

impl<'de> Deserialize<'de> for BoundedRecords {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecordsVisitor;

        impl<'de> Visitor<'de> for RecordsVisitor {
            type Value = BoundedRecords;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_RECORDS} unique cache fallback records"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or_default().min(MAX_RECORDS);
                let mut records = Vec::new();
                records.try_reserve(capacity).map_err(de::Error::custom)?;
                while records.len() < MAX_RECORDS {
                    let Some(record) = sequence.next_element::<CacheFallbackRecord>()? else {
                        return Ok(BoundedRecords(records));
                    };
                    if records.iter().any(|existing: &CacheFallbackRecord| {
                        existing.stage == record.stage && existing.kind == record.kind
                    }) {
                        return Err(de::Error::custom(
                            "cache fallback summary has duplicate records",
                        ));
                    }
                    records.push(record);
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom(
                        "cache fallback summary has too many records",
                    ));
                }
                Ok(BoundedRecords(records))
            }
        }

        deserializer.deserialize_seq(RecordsVisitor)
    }
}

pub(super) fn bounded_escaped_sample(arguments: fmt::Arguments<'_>) -> Option<String> {
    let mut detail = BoundedEscapedDetail::default();
    let _ = fmt::write(&mut detail, arguments);
    detail.finish()
}

fn prefer_sample(current: &mut Option<String>, candidate: Option<String>) {
    let Some(candidate) = candidate else {
        return;
    };
    if current
        .as_ref()
        .is_none_or(|existing| candidate.as_str() < existing.as_str())
    {
        *current = Some(candidate);
    }
}

struct BoundedEscapedDetail {
    text: String,
    truncated: bool,
}

impl BoundedEscapedDetail {
    fn finish(mut self) -> Option<String> {
        if self.truncated {
            self.text.push_str(TRUNCATION_MARKER);
        }
        (!self.text.is_empty()).then_some(self.text)
    }
}

impl Default for BoundedEscapedDetail {
    fn default() -> Self {
        Self {
            text: String::with_capacity(MAX_SAMPLE_BYTES),
            truncated: false,
        }
    }
}

impl fmt::Write for BoundedEscapedDetail {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }

        for character in text.chars() {
            let escaped_length = character.escape_default().count();
            if self.text.len() + escaped_length > MAX_SAMPLE_CONTENT_BYTES {
                self.truncated = true;
                return Err(fmt::Error);
            }
            self.text.extend(character.escape_default());
        }
        Ok(())
    }
}
