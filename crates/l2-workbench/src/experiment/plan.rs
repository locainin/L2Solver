use super::{MAX_MUTATIONS, MAX_OUTPUT_BYTES, MAX_PLAN_BYTES};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    FlipBit {
        offset: usize,
        bit: u8,
    },
    XorRange {
        offset: usize,
        length: usize,
        #[serde(deserialize_with = "deserialize_key_hex")]
        key_hex: String,
    },
    Insert {
        offset: usize,
        #[serde(deserialize_with = "deserialize_insert_hex")]
        bytes_hex: String,
    },
    Delete {
        offset: usize,
        length: usize,
    },
    Truncate {
        length: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MutationPlan {
    pub mutations: Vec<Mutation>,
}

impl MutationPlan {
    pub(crate) fn estimated_bytes(&self) -> Option<usize> {
        self.mutations.iter().try_fold(0_usize, |total, mutation| {
            let payload_length = match mutation {
                Mutation::XorRange { key_hex, .. } => key_hex.len(),
                Mutation::Insert { bytes_hex, .. } => bytes_hex.len(),
                Mutation::FlipBit { .. } | Mutation::Delete { .. } | Mutation::Truncate { .. } => 0,
            };
            // Six bytes per source byte covers JSON escaping for control characters
            total
                .checked_add(128)?
                .checked_add(payload_length.checked_mul(6)?)
        })
    }
}

impl<'de> Deserialize<'de> for MutationPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePlan {
            #[serde(deserialize_with = "deserialize_mutations")]
            mutations: Vec<Mutation>,
        }

        let plan = WirePlan::deserialize(deserializer)?.mutations;
        let plan = Self { mutations: plan };
        let Some(length) = plan.estimated_bytes() else {
            return Err(de::Error::custom("mutation plan size overflow"));
        };
        if length > MAX_PLAN_BYTES {
            return Err(de::Error::custom("mutation plan exceeds its byte limit"));
        }
        Ok(plan)
    }
}

fn deserialize_mutations<'de, D>(deserializer: D) -> Result<Vec<Mutation>, D::Error>
where
    D: Deserializer<'de>,
{
    struct MutationsVisitor;

    impl<'de> Visitor<'de> for MutationsVisitor {
        type Value = Vec<Mutation>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_MUTATIONS} mutation operations")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut mutations = Vec::new();
            while let Some(mutation) = sequence.next_element()? {
                if mutations.len() == MAX_MUTATIONS {
                    return Err(de::Error::custom("mutation count exceeds its limit"));
                }
                mutations.push(mutation);
            }
            Ok(mutations)
        }
    }

    deserializer.deserialize_seq(MutationsVisitor)
}

fn deserialize_key_hex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, 2 * 256, "XOR key exceeds 256 bytes")
}

fn deserialize_insert_hex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(
        deserializer,
        2 * MAX_OUTPUT_BYTES,
        "insert data exceeds the output bound",
    )
}

fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    maximum: usize,
    message: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor {
        maximum: usize,
        message: &'static str,
    }

    impl Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a string no longer than {} bytes", self.maximum)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > self.maximum {
                return Err(E::custom(self.message));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() > self.maximum {
                return Err(E::custom(self.message));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor { maximum, message })
}
