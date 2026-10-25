//! Checked-in file-signature catalogue split by format domain

mod archives;
mod documents;
mod foundational;
mod images;
mod media;
mod offsets;

pub(super) const CATALOGUE_SOURCE: &str = "https://en.wikipedia.org/wiki/List_of_file_signatures";
pub(super) const CATALOGUE_REVIEWED_ON: &str = "2026-10-22";
pub(super) const CATALOGUE_VERSION: u32 = 2;

pub const ELF_MAGIC: &[u8] = b"\x7fELF";
pub const MZ_MAGIC: &[u8] = b"MZ";

/// A pattern is exact unless explicit positions are marked as wildcards
pub(super) enum Pattern {
    Exact(&'static [u8]),
    Masked(&'static [Option<u8>]),
}

/// The finite or format-derived locations at which a signature may occur
#[derive(Clone, Copy)]
pub(super) enum SignatureOffsets {
    /// A fixed list published by the format
    Declared(&'static [usize]),
    /// Zero, then every power of two beginning at 512 within the supplied object
    Hdf5Superblocks,
    /// Consecutive ISO-9660 descriptors for 2048-byte logical-sector images
    Iso9660VolumeDescriptors,
}

impl Pattern {
    pub(super) const fn length(&self) -> usize {
        match self {
            Self::Exact(bytes) => bytes.len(),
            Self::Masked(bytes) => bytes.len(),
        }
    }
}

/// One signature and every offset at which its format defines that signature
pub(super) struct SignatureRule {
    pub(super) id: &'static str,
    pub(super) description: &'static str,
    pub(super) formats: &'static [&'static str],
    pub(super) extensions: &'static [&'static str],
    pub(super) media_types: &'static [&'static str],
    pub(super) reference: &'static str,
    pub(super) offsets: SignatureOffsets,
    pub(super) pattern: Pattern,
    pub(super) ambiguous: bool,
}

// Most rules are exact, so the macro keeps each catalogue entry focused on its data
macro_rules! exact_rule {
    ($id:literal, $description:literal, $formats:expr, $extensions:expr, $media:expr, $offsets:expr, $bytes:expr, $ambiguous:expr) => {
        super::SignatureRule {
            id: $id,
            description: $description,
            formats: $formats,
            extensions: $extensions,
            media_types: $media,
            reference: super::CATALOGUE_SOURCE,
            offsets: super::SignatureOffsets::Declared($offsets),
            pattern: super::Pattern::Exact($bytes),
            ambiguous: $ambiguous,
        }
    };
}

macro_rules! exact_rule_from {
    ($id:literal, $description:literal, $formats:expr, $extensions:expr, $media:expr, $offsets:expr, $bytes:expr, $ambiguous:expr, $reference:expr) => {
        super::SignatureRule {
            id: $id,
            description: $description,
            formats: $formats,
            extensions: $extensions,
            media_types: $media,
            reference: $reference,
            offsets: super::SignatureOffsets::Declared($offsets),
            pattern: super::Pattern::Exact($bytes),
            ambiguous: $ambiguous,
        }
    };
}

pub(super) use {exact_rule, exact_rule_from};

// A group boundary is organizational only; the scanner evaluates every rule uniformly
pub(super) const RULE_GROUPS: &[&[SignatureRule]] = &[
    foundational::RULES,
    archives::RULES,
    documents::RULES,
    images::RULES,
    media::RULES,
    offsets::RULES,
];

pub(super) fn rules() -> impl Iterator<Item = &'static SignatureRule> {
    RULE_GROUPS.iter().flat_map(|group| group.iter())
}

pub(super) fn rule_count() -> usize {
    RULE_GROUPS.iter().map(|group| group.len()).sum()
}
