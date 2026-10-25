//! Serde wire forms for versioned policy bindings

use crate::{BridgeIdentity, PortBinding, SegmentExpectations, StableSourceLabel};
use serde::{
    Deserialize, Deserializer,
    de::{Error as DeError, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};

/// One schema-three source binding identified by a stable operator label
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StablePortBinding {
    pub source: StableSourceLabel,
    pub segment: String,
    pub role: String,
}

/// Wire representation shared by schema two and schema three policies
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawPolicy {
    pub allowed_vlans: Option<Vec<u16>>,
    pub allow_priority_tagged: Option<bool>,
    pub allow_untagged: Option<bool>,
    pub max_vlan_depth: Option<u8>,
    pub expected_stp_bridge: Option<BridgeIdentity>,
    pub expected_stp_root: Option<String>,
    pub schema_version: Option<u32>,
    #[serde(deserialize_with = "deserialize_segments")]
    pub segments: Option<BTreeMap<String, SegmentExpectations>>,
    pub ports: Option<RawPorts>,
}

/// The two port binding forms are selected from their field names
#[derive(Deserialize)]
#[serde(untagged)]
pub enum RawPorts {
    Ordinal(Vec<PortBinding>),
    Stable(Vec<StablePortBinding>),
}

fn deserialize_segments<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, SegmentExpectations>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<UniqueSegments>::deserialize(deserializer)
        .map(|segments| segments.map(|segments| segments.0))
}

// Keep duplicate detection inside the map representation
struct UniqueSegments(BTreeMap<String, SegmentExpectations>);

impl<'de> Deserialize<'de> for UniqueSegments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_map(UniqueSegmentsVisitor)
            .map(Self)
    }
}

struct UniqueSegmentsVisitor;

impl<'de> Visitor<'de> for UniqueSegmentsVisitor {
    type Value = BTreeMap<String, SegmentExpectations>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a segment expectation object with unique names")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut segments = BTreeMap::new();
        while let Some(name) = access.next_key::<String>()? {
            if segments.contains_key(&name) {
                return Err(A::Error::custom("duplicate segment name"));
            }
            let expectations = access.next_value::<SegmentExpectations>()?;
            segments.insert(name, expectations);
        }
        Ok(segments)
    }
}
