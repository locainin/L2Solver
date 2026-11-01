//! Read only cleanup locations while bounding untrusted field and nesting sizes

use super::super::Component;
use serde::de::{self, Deserialize, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::{
    cell::Cell,
    fmt,
    io::{self, Read},
    marker::PhantomData,
    rc::Rc,
};

// Valid cursor names and digests fit even when every ASCII character is escaped
const FIELD_BYTES: usize = 1024;
// Normal checkpoint decoding has a lower recursion limit
const NESTING_DEPTH: usize = 256;

pub(super) struct Locations {
    pub(super) version: u32,
    pub(super) revision: Option<u64>,
    pub(super) components: [Component; 3],
}

struct BoundedReader<R> {
    input: R,
    remaining: Rc<Cell<Option<usize>>>,
    in_string: bool,
    escaped: bool,
    depth: usize,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let Some(first) = output.first_mut() else {
            return Ok(0);
        };
        // serde_json reads one byte at a time; keep the guard precise for any caller
        let count = self.input.read(std::slice::from_mut(first))?;
        if count == 0 {
            return Ok(0);
        }
        let byte = *first;
        // Bound raw escaped bytes before serde can grow a string buffer
        if let Some(remaining) = self.remaining.get()
            && (self.in_string || byte == b'"')
        {
            let next = remaining.checked_sub(1).ok_or_else(invalid_data)?;
            self.remaining.set(Some(next));
        }
        // Track nesting even in metadata that the decoder otherwise skips
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
        } else {
            match byte {
                b'"' => self.in_string = true,
                b'{' | b'[' => {
                    self.depth += 1;
                    if self.depth > NESTING_DEPTH {
                        return Err(invalid_data());
                    }
                }
                b'}' | b']' => {
                    self.depth = self.depth.checked_sub(1).ok_or_else(invalid_data)?;
                }
                _ => {}
            }
        }
        Ok(count)
    }
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "cleanup field or nesting limit exceeded",
    )
}

struct Limited<T> {
    remaining: Rc<Cell<Option<usize>>>,
    value: PhantomData<T>,
}

impl<T> Limited<T> {
    fn new(remaining: &Rc<Cell<Option<usize>>>) -> Self {
        Self {
            remaining: Rc::clone(remaining),
            value: PhantomData,
        }
    }
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for Limited<T> {
    type Value = T;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<T, D::Error> {
        // Only fields needed by cleanup are materialized; other values are skipped
        let previous = self.remaining.replace(Some(FIELD_BYTES));
        let result = T::deserialize(deserializer);
        self.remaining.set(previous);
        result
    }
}

struct LocationsSeed {
    remaining: Rc<Cell<Option<usize>>>,
}

impl<'de> DeserializeSeed<'de> for LocationsSeed {
    type Value = Locations;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Locations, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for LocationsSeed {
    type Value = Locations;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an execution checkpoint envelope")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Locations, A::Error> {
        let mut version = None;
        let mut revision = None;
        let mut components = None;
        // A null revision must still count as present when checking duplicates
        let mut has_revision = false;
        while let Some(key) = map.next_key_seed(Limited::<String>::new(&self.remaining))? {
            match key.as_str() {
                "version" if version.is_none() => version = Some(map.next_value()?),
                "revision" if !has_revision => {
                    revision = map.next_value()?;
                    has_revision = true;
                }
                "components" if components.is_none() => {
                    components = Some(map.next_value_seed(ComponentsSeed {
                        remaining: Rc::clone(&self.remaining),
                    })?);
                }
                "version" | "revision" | "components" => {
                    return Err(de::Error::custom("duplicate checkpoint field"));
                }
                // Snapshot and metadata can be large but never need to be copied here
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Locations {
            version: version.ok_or_else(|| de::Error::missing_field("version"))?,
            revision,
            components: components.ok_or_else(|| de::Error::missing_field("components"))?,
        })
    }
}

struct ComponentsSeed {
    remaining: Rc<Cell<Option<usize>>>,
}

impl<'de> DeserializeSeed<'de> for ComponentsSeed {
    type Value = [Component; 3];

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ComponentsSeed {
    type Value = [Component; 3];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("three execution components")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // Read exactly three locations without collecting a variable-sized array
        let mut next = |index| {
            seq.next_element_seed(ComponentSeed {
                remaining: Rc::clone(&self.remaining),
            })?
            .ok_or_else(|| de::Error::invalid_length(index, &self))
        };
        let components = [next(0)?, next(1)?, next(2)?];
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(4, &self));
        }
        Ok(components)
    }
}

struct ComponentSeed {
    remaining: Rc<Cell<Option<usize>>>,
}

impl<'de> DeserializeSeed<'de> for ComponentSeed {
    type Value = Component;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Component, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ComponentSeed {
    type Value = Component;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an execution component")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Component, A::Error> {
        // Absent and null directories both represent the original file location
        let mut directory = None;
        let mut has_directory = false;
        let mut bytes = None;
        let mut sha256 = None;
        while let Some(key) = map.next_key_seed(Limited::<String>::new(&self.remaining))? {
            match key.as_str() {
                "directory" if !has_directory => {
                    directory =
                        map.next_value_seed(Limited::<Option<String>>::new(&self.remaining))?;
                    has_directory = true;
                }
                "bytes" if bytes.is_none() => bytes = Some(map.next_value()?),
                "sha256" if sha256.is_none() => {
                    sha256 = Some(map.next_value_seed(Limited::<String>::new(&self.remaining))?);
                }
                "directory" | "bytes" | "sha256" => {
                    return Err(de::Error::custom("duplicate component field"));
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Component {
            directory,
            bytes: bytes.ok_or_else(|| de::Error::missing_field("bytes"))?,
            sha256: sha256.ok_or_else(|| de::Error::missing_field("sha256"))?,
        })
    }
}

pub(super) fn read<R: Read>(input: R) -> Result<Locations, serde_json::Error> {
    let remaining = Rc::new(Cell::new(None));
    let input = BoundedReader {
        input,
        remaining: Rc::clone(&remaining),
        in_string: false,
        escaped: false,
        depth: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_reader(input);
    let locations = LocationsSeed { remaining }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(locations)
}
