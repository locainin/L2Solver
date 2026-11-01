use serde::{
    Deserialize, Deserializer,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use std::{fmt, marker::PhantomData};

pub(super) fn deserialize_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct LimitedVecVisitor<T, const MAXIMUM: usize> {
        marker: PhantomData<T>,
    }

    impl<'de, T, const MAXIMUM: usize> Visitor<'de> for LimitedVecVisitor<T, MAXIMUM>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence with at most {MAXIMUM} entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or_default().min(MAXIMUM);
            let mut values = Vec::new();
            values.try_reserve(capacity).map_err(A::Error::custom)?;
            while values.len() < MAXIMUM {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("sequence exceeds its limit"));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(LimitedVecVisitor::<T, MAXIMUM> {
        marker: PhantomData,
    })
}
