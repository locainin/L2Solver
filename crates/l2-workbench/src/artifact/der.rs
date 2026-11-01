use core::{cmp::Ordering, fmt};

use der::{
    Decode, DecodeValue, DerOrd, Encode, FixedTag, Header, Reader, SliceReader, Tag, Tagged,
    asn1::{
        AnyRef, BitStringRef, GeneralizedTime, Ia5StringRef, IntRef, Null, ObjectIdentifier,
        OctetStringRef, PrintableStringRef, UtcTime, Utf8StringRef,
    },
};

use super::FileRange;
use admission::{Admission, Metered, Unmetered};

mod admission;

pub(super) use admission::DerMemoryError;

/// Default maximum for one DER object's encoded length
pub const MAX_DER_OBJECT_BYTES: usize = 4 * 1024 * 1024;
/// Stack-safety ceiling on recursive constructed-value nesting
pub const MAX_DER_DEPTH: usize = 64;
/// Default maximum number of inventoried DER nodes
pub const MAX_DER_NODES: usize = 65_536;
/// Default maximum preview bytes retained for each value
pub const MAX_DER_VALUE_PREVIEW_BYTES: usize = 256;

const MAX_OID_VALUE_BYTES: usize = 256;

/// Object, recursion, inventory, and preview limits for one DER boundary
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DerLimits {
    /// Largest complete DER object accepted from the source boundary
    pub max_object_bytes: usize,
    /// Largest nested constructed-value depth, with the root at depth zero
    pub max_depth: usize,
    /// Largest number of parsed values retained in the report
    pub max_nodes: usize,
    /// Largest raw value prefix retained for each parsed node
    pub max_value_preview_bytes: usize,
}

impl Default for DerLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: MAX_DER_OBJECT_BYTES,
            max_depth: MAX_DER_DEPTH,
            max_nodes: MAX_DER_NODES,
            max_value_preview_bytes: 32,
        }
    }
}

/// ASN.1 tag class used by one inventoried value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerTagClass {
    /// Universal ASN.1 type
    Universal,
    /// Application-defined type
    Application,
    /// Context-defined type
    ContextSpecific,
    /// Private type
    Private,
}

/// Class, number, and constructed bit from one DER identifier
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerTag {
    /// ASN.1 identifier class
    pub class: DerTagClass,
    /// Numeric tag number
    pub number: u32,
    /// Whether the value contains child DER values
    pub constructed: bool,
}

/// Minimal signed-integer facts retained without narrowing large values
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerIntegerMetadata {
    /// Whether the high bit marks the value as negative
    pub negative: bool,
    /// Exact nonnegative value when it fits in an unsigned 64-bit field
    pub unsigned_value: Option<u64>,
}

/// Octet-string content size
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerOctetStringMetadata {
    /// Number of content octets in the value
    pub length: usize,
}

/// One DER value and the source ranges that support its metadata
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerNode {
    /// Index of the enclosing constructed value, when present
    pub parent_index: Option<usize>,
    /// Root is depth zero; each constructed child increases depth by one
    pub depth: usize,
    /// Parsed class, number, and constructed flag
    pub tag: DerTag,
    /// Complete tag, length, and value range
    pub encoded_range: FileRange,
    /// Value bytes following the tag and length fields
    pub value_range: FileRange,
    /// Canonical dotted text for an OBJECT IDENTIFIER value
    pub oid: Option<String>,
    /// Integer sign and byte length for an INTEGER value
    pub integer: Option<DerIntegerMetadata>,
    /// Content length for an OCTET STRING value
    pub octet_string: Option<DerOctetStringMetadata>,
    /// Bounded prefix of the raw value bytes
    pub value_preview: Vec<u8>,
}

impl DerNode {
    /// Whether the raw value contained bytes beyond the retained preview
    #[must_use]
    pub const fn preview_truncated(&self) -> bool {
        self.value_range.length > self.value_preview.len()
    }
}

/// Inventory of one complete DER object at an explicit source boundary
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerReport {
    /// Exact source boundary that contained the complete object
    pub boundary_range: FileRange,
    /// Root and nested values in preorder; the root has no parent
    pub nodes: Vec<DerNode>,
}

/// Invalid DER input, source boundary, or configured resource budget
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerError {
    /// One or more configured limits are outside the supported range
    InvalidLimits,
    /// The requested source range overflowed or was outside the input
    InvalidBoundary {
        /// First byte requested from the source
        offset: usize,
        /// Number of requested source bytes
        length: usize,
        /// Number of available input bytes
        total: usize,
    },
    /// The object exceeded its configured encoded-size limit
    ObjectTooLarge { length: usize, maximum: usize },
    /// The input was malformed, non-canonical, or uses an unsupported value encoding
    InvalidDer,
    /// A nested value exceeded the configured recursion depth
    DepthLimitExceeded { maximum: usize },
    /// The object contained more values than the configured node count
    NodeLimitExceeded { maximum: usize },
    /// The parser could not allocate a bounded inventory or value
    AllocationFailure,
}

impl fmt::Display for DerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("DER parser limits exceed supported bounds"),
            Self::InvalidBoundary {
                offset,
                length,
                total,
            } => write!(
                formatter,
                "DER boundary {offset}+{length} is outside {total} source bytes"
            ),
            Self::ObjectTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "DER object has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidDer => {
                formatter.write_str("input is malformed, non-canonical, or unsupported DER")
            }
            Self::DepthLimitExceeded { maximum } => {
                write!(formatter, "DER nesting exceeds maximum depth {maximum}")
            }
            Self::NodeLimitExceeded { maximum } => {
                write!(formatter, "DER value count exceeds maximum {maximum}")
            }
            Self::AllocationFailure => formatter.write_str("DER parser allocation failed"),
        }
    }
}

impl std::error::Error for DerError {}

/// Parse and inventory one DER value inside `boundary`
///
/// The range uses offsets into `input`, so the DER object may be embedded in a
/// larger artifact. Bytes outside the range are never interpreted as part of
/// the DER value. Supported universal primitive types are checked for canonical
/// content; unsupported universal types are rejected. Application, context, and
/// private values retain schema-dependent content without semantic validation
///
/// # Errors
/// Returns an error for an invalid boundary, non-canonical or incomplete DER,
/// or an exceeded object, depth, node, or preview limit
pub fn parse_der(
    input: &[u8],
    boundary: FileRange,
    limits: DerLimits,
) -> Result<DerReport, DerError> {
    parse_der_with_admission(input, boundary, limits, &mut Unmetered)
}

pub(super) fn parse_der_with_memory(
    input: &[u8],
    boundary: FileRange,
    limits: DerLimits,
    memory: &mut crate::job::MemoryLease,
) -> Result<DerReport, DerMemoryError> {
    let before = memory.bytes();
    let result = parse_der_with_admission(input, boundary, limits, &mut Metered(&mut *memory));
    if result.is_err() {
        // The partial report has dropped before its charge is released
        memory.try_resize(before)?;
    }
    result
}

fn parse_der_with_admission<A: Admission>(
    input: &[u8],
    boundary: FileRange,
    limits: DerLimits,
    admission: &mut A,
) -> Result<DerReport, A::Error> {
    validate_limits(limits)?;

    let boundary_end =
        boundary
            .offset
            .checked_add(boundary.length)
            .ok_or(DerError::InvalidBoundary {
                offset: boundary.offset,
                length: boundary.length,
                total: input.len(),
            })?;
    let encoded = input
        .get(boundary.offset..boundary_end)
        .ok_or(DerError::InvalidBoundary {
            offset: boundary.offset,
            length: boundary.length,
            total: input.len(),
        })?;
    if encoded.len() > limits.max_object_bytes {
        return Err(DerError::ObjectTooLarge {
            length: encoded.len(),
            maximum: limits.max_object_bytes,
        }
        .into());
    }

    let root_length = first_value_length(encoded)?;
    if root_length != encoded.len() {
        return Err(DerError::InvalidDer.into());
    }
    let root = AnyRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
    let mut context = DerContext {
        limits,
        nodes: Vec::new(),
        admission,
    };
    visit_node(root, encoded, boundary.offset, None, 0, &mut context)?;

    Ok(DerReport {
        boundary_range: boundary,
        nodes: context.nodes,
    })
}

struct DerContext<'a, A> {
    limits: DerLimits,
    nodes: Vec<DerNode>,
    admission: &'a mut A,
}

fn visit_node<'a, A: Admission>(
    value: AnyRef<'a>,
    encoded: &'a [u8],
    source_offset: usize,
    parent_index: Option<usize>,
    depth: usize,
    context: &mut DerContext<'_, A>,
) -> Result<(), A::Error> {
    if depth > context.limits.max_depth {
        return Err(DerError::DepthLimitExceeded {
            maximum: context.limits.max_depth,
        }
        .into());
    }
    if context.nodes.len() >= context.limits.max_nodes {
        return Err(DerError::NodeLimitExceeded {
            maximum: context.limits.max_nodes,
        }
        .into());
    }

    let tag = value.tag();
    let raw_value = value.value();
    let header_length = usize::try_from(
        value
            .header()
            .encoded_len()
            .map_err(|_| DerError::InvalidDer)?,
    )
    .map_err(|_| DerError::InvalidDer)?;
    let encoded_length = header_length
        .checked_add(raw_value.len())
        .ok_or(DerError::InvalidDer)?;
    if encoded_length != encoded.len() {
        return Err(DerError::InvalidDer.into());
    }

    let value_offset = source_offset
        .checked_add(header_length)
        .ok_or(DerError::InvalidDer)?;
    let index = context.nodes.len();
    context.admission.reserve_node(&mut context.nodes)?;
    let preview_length = raw_value.len().min(context.limits.max_value_preview_bytes);
    let preview_bytes = raw_value
        .get(..preview_length)
        .ok_or(DerError::InvalidDer)?;
    let preview = context.admission.copy_preview(preview_bytes)?;
    let metadata = metadata_for(tag, value, encoded, &mut *context.admission)?;

    context.nodes.push(DerNode {
        parent_index,
        depth,
        tag: DerTag {
            class: tag_class(tag.class()),
            number: tag.number().0,
            constructed: tag.is_constructed(),
        },
        encoded_range: FileRange {
            offset: source_offset,
            length: encoded.len(),
        },
        value_range: FileRange {
            offset: value_offset,
            length: raw_value.len(),
        },
        oid: metadata.oid,
        integer: metadata.integer,
        octet_string: metadata.octet_string,
        value_preview: preview,
    });

    if tag.is_constructed() {
        visit_children(tag, raw_value, value_offset, index, depth, context)?;
    }

    Ok(())
}

fn visit_children<'a, A: Admission>(
    parent_tag: Tag,
    bytes: &'a [u8],
    source_offset: usize,
    parent_index: usize,
    parent_depth: usize,
    context: &mut DerContext<'_, A>,
) -> Result<(), A::Error> {
    let mut cursor = 0_usize;
    let mut previous_set_value: Option<AnyRef<'a>> = None;

    while cursor < bytes.len() {
        // Derive a child's full length from its canonical header, then give the
        // DER library that exact range so trailing sibling bytes cannot be accepted
        let remaining = bytes.get(cursor..).ok_or(DerError::InvalidDer)?;
        let child_length = first_value_length(remaining)?;
        let child_end = cursor
            .checked_add(child_length)
            .ok_or(DerError::InvalidDer)?;
        let child_encoded = remaining.get(..child_length).ok_or(DerError::InvalidDer)?;
        let child = AnyRef::from_der(child_encoded).map_err(|_| DerError::InvalidDer)?;

        // SET values must follow the ordering implemented by RustCrypto's DER tag model
        if parent_tag == Tag::Set {
            if let Some(previous) = previous_set_value {
                let order = previous.der_cmp(&child).map_err(|_| DerError::InvalidDer)?;
                if order == Ordering::Greater {
                    return Err(DerError::InvalidDer.into());
                }
            }
            previous_set_value = Some(child);
        }

        let next_depth = parent_depth.checked_add(1).ok_or(DerError::InvalidDer)?;
        let child_source_offset = source_offset
            .checked_add(cursor)
            .ok_or(DerError::InvalidDer)?;
        visit_node(
            child,
            child_encoded,
            child_source_offset,
            Some(parent_index),
            next_depth,
            context,
        )?;
        cursor = child_end;
    }

    if cursor != bytes.len() {
        return Err(DerError::InvalidDer.into());
    }
    Ok(())
}

fn first_value_length(bytes: &[u8]) -> Result<usize, DerError> {
    let mut reader = SliceReader::new(bytes).map_err(|_| DerError::InvalidDer)?;
    let header = Header::decode(&mut reader).map_err(|_| DerError::InvalidDer)?;
    let header_length = usize::try_from(reader.position()).map_err(|_| DerError::InvalidDer)?;
    let value_length = usize::try_from(header.length()).map_err(|_| DerError::InvalidDer)?;
    header_length
        .checked_add(value_length)
        .ok_or(DerError::InvalidDer)
}

#[derive(Default)]
struct DerValueMetadata {
    oid: Option<String>,
    integer: Option<DerIntegerMetadata>,
    octet_string: Option<DerOctetStringMetadata>,
}

fn metadata_for<A: Admission>(
    tag: Tag,
    value: AnyRef<'_>,
    encoded: &[u8],
    admission: &mut A,
) -> Result<DerValueMetadata, A::Error> {
    let raw_value = value.value();
    let mut metadata = DerValueMetadata::default();

    if tag.is_constructed() {
        // Universal constructed values are supported only when they are SEQUENCE or SET
        if tag.is_universal() && !matches!(tag, Tag::Sequence | Tag::Set) {
            return Err(DerError::InvalidDer.into());
        }
        return Ok(metadata);
    }

    // Typed decoders enforce the content rules for each supported universal primitive
    match tag {
        Tag::Boolean => {
            bool::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::Integer => {
            IntRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
            metadata.integer = Some(DerIntegerMetadata {
                negative: raw_value.first().is_some_and(|byte| byte & 0x80 != 0),
                unsigned_value: unsigned_integer(raw_value),
            });
        }
        Tag::Enumerated => validate_enumerated(raw_value)?,
        Tag::BitString => {
            BitStringRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::OctetString => {
            let _: &OctetStringRef =
                <&OctetStringRef>::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
            metadata.octet_string = Some(DerOctetStringMetadata {
                length: raw_value.len(),
            });
        }
        Tag::Null => {
            Null::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::ObjectIdentifier => {
            let decoded = ObjectIdentifier::<MAX_OID_VALUE_BYTES>::from_der(encoded)
                .map_err(|_| DerError::InvalidDer)?;
            metadata.oid = Some(admission.format_oid(&decoded)?);
        }
        Tag::Utf8String => {
            Utf8StringRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::PrintableString => {
            PrintableStringRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::Ia5String => {
            Ia5StringRef::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::UtcTime => {
            UtcTime::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        Tag::GeneralizedTime => {
            GeneralizedTime::from_der(encoded).map_err(|_| DerError::InvalidDer)?;
        }
        // These decoders are incomplete, f64-limited, or absent in der 0.8.2
        Tag::Real
        | Tag::RelativeOid
        | Tag::NumericString
        | Tag::TeletexString
        | Tag::VideotexString
        | Tag::VisibleString
        | Tag::GeneralString
        | Tag::BmpString => return Err(DerError::InvalidDer.into()),
        // Application, context-specific, and private values are opaque without a schema
        _ if !tag.is_universal() => (),
        // Unknown universal tags must never receive a canonical-value claim
        _ => return Err(DerError::InvalidDer.into()),
    }

    Ok(metadata)
}

fn unsigned_integer(bytes: &[u8]) -> Option<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    // DER may use one leading zero octet to keep a positive high bit clear
    let significant = if bytes.first() == Some(&0) {
        bytes.get(1..)?
    } else {
        bytes
    };
    if significant.len() > size_of::<u64>() {
        return None;
    }
    Some(
        significant
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn validate_enumerated(value: &[u8]) -> Result<(), DerError> {
    // ENUMERATED has INTEGER's signed content rules but a different universal tag
    let length = der::Length::try_from(value.len()).map_err(|_| DerError::InvalidDer)?;
    let header = Header::new(Tag::Integer, length);
    let mut reader = SliceReader::new(value).map_err(|_| DerError::InvalidDer)?;
    IntegerContent::decode_value(&mut reader, header).map_err(|_| DerError::InvalidDer)?;
    reader.finish().map_err(|_| DerError::InvalidDer)?;

    Ok(())
}

struct IntegerContent;

impl<'a> DecodeValue<'a> for IntegerContent {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let integer_header = Header::new(Tag::Integer, header.length());
        IntRef::decode_value(reader, integer_header)?;
        Ok(Self)
    }
}

impl FixedTag for IntegerContent {
    const TAG: Tag = Tag::Enumerated;
}

const fn tag_class(class: der::Class) -> DerTagClass {
    match class {
        der::Class::Universal => DerTagClass::Universal,
        der::Class::Application => DerTagClass::Application,
        der::Class::ContextSpecific => DerTagClass::ContextSpecific,
        der::Class::Private => DerTagClass::Private,
    }
}

const fn validate_limits(limits: DerLimits) -> Result<(), DerError> {
    if limits.max_object_bytes == 0 || limits.max_depth > MAX_DER_DEPTH || limits.max_nodes == 0 {
        return Err(DerError::InvalidLimits);
    }
    Ok(())
}
