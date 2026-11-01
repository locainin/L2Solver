//! Compact only the retained bytes in a private cursor representation

use crate::protocol::{RelationalAppliedOutput, RelationalCandidateOutputs};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize)]
struct OutputRef<'a>(
    #[serde(serialize_with = "crate::job::checkpoint_relational_output::serialize")]
    &'a RelationalAppliedOutput,
);

struct OutputSequenceRef<'a>(&'a [RelationalAppliedOutput]);

impl Serialize for OutputSequenceRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(OutputRef))
    }
}

#[derive(Serialize)]
pub(super) struct CandidateOutputsRef<'a> {
    discovery: OutputSequenceRef<'a>,
    heldout: OutputSequenceRef<'a>,
}

impl<'a> From<&'a RelationalCandidateOutputs> for CandidateOutputsRef<'a> {
    fn from(outputs: &'a RelationalCandidateOutputs) -> Self {
        Self {
            discovery: OutputSequenceRef(&outputs.discovery),
            heldout: OutputSequenceRef(&outputs.heldout),
        }
    }
}

#[derive(Deserialize)]
struct OutputOwned(
    #[serde(deserialize_with = "crate::job::checkpoint_relational_output::deserialize")]
    RelationalAppliedOutput,
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateOutputsOwned {
    discovery: Vec<OutputOwned>,
    heldout: Vec<OutputOwned>,
}

pub(in super::super) fn deserialize_outputs<'de, D>(
    deserializer: D,
) -> Result<Option<RelationalCandidateOutputs>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<CandidateOutputsOwned>::deserialize(deserializer).map(|outputs| {
        outputs.map(|outputs| RelationalCandidateOutputs {
            discovery: outputs
                .discovery
                .into_iter()
                .map(|output| output.0)
                .collect(),
            heldout: outputs.heldout.into_iter().map(|output| output.0).collect(),
        })
    })
}
