//! Provenance of acquisition conditions supplied with a capture

/// Origin of the available acquisition conditions
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CollectionAuthority {
    /// No acquisition declaration is retained in the summary
    #[default]
    Absent,
    /// The capture source supplied conditions without independent verification
    SourceDeclared,
}

impl CollectionAuthority {
    /// Return the stable name used in output
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::SourceDeclared => "source_declared",
        }
    }
}
