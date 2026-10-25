use crate::{
    evidence::EvidenceStatus,
    query::{IpCidr, QueryError},
};

const MAX_FILTERS: usize = 32;
const MAX_FILTER_BYTES: usize = 256;
const MAX_KIND_BYTES: usize = 64;
const MAX_FIELD_BYTES: usize = 64;

/// Which packet endpoint an `ip` filter examines
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IpDirection {
    /// Either source or destination address
    #[default]
    Either,
    /// Source address only
    Source,
    /// Destination address only
    Destination,
}

/// A capture-local interface identity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceScope {
    /// Capture section or equivalent file-local namespace
    pub section: u32,
    /// Interface index inside the section
    pub index: u32,
}

/// Inclusive one-based packet record bounds
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRange {
    /// First packet number
    pub first: u64,
    /// Last packet number
    pub last: u64,
}

/// Inclusive Unix-second bounds used to select packet timestamps
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeRange {
    /// First inclusive epoch second
    pub first: i64,
    /// Last inclusive epoch second
    pub last: i64,
}

/// Exact decoded packet field name and expected string value
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldValue {
    /// Supported field identifier, such as `ip.src` or `tcp.dstport`
    pub name: String,
    /// Exact value expected in the retained packet bytes
    pub value: String,
}

/// A set of explicit, composable evidence filters
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Selector {
    /// General address filter, interpreted using `ip_direction`
    pub ip: Option<IpCidr>,
    /// Direction used by the general address filter
    pub ip_direction: IpDirection,
    /// Additional source address filter
    pub source_ip: Option<IpCidr>,
    /// Additional destination address filter
    pub destination_ip: Option<IpCidr>,
    /// IPv4/IPv6 next-header protocol name
    pub protocol: Option<String>,
    /// Exact source transport port
    pub source_port: Option<u16>,
    /// Exact destination transport port
    pub destination_port: Option<u16>,
    /// Match either transport port
    pub port: Option<u16>,
    /// Inclusive packet range
    pub packet_range: Option<PacketRange>,
    /// Inclusive Unix-second range
    pub time_range: Option<TimeRange>,
    /// Exact decoded packet fields
    pub fields: Vec<FieldValue>,
    /// Capture-local interface
    pub interface: Option<InterfaceScope>,
    /// VLAN identifier, in-band or auxiliary
    pub vlan: Option<u16>,
    /// Exact evidence node kind
    pub kind: Option<String>,
    /// Status on a graph edge connected to the selected evidence
    pub status: Option<EvidenceStatus>,
}

impl Selector {
    /// Parse bounded `key=value` filters without evaluating expressions
    ///
    /// # Errors
    /// Rejects unknown, duplicate, malformed, or out-of-range filters
    pub fn parse(filters: &[&str]) -> Result<Self, QueryError> {
        if filters.len() > MAX_FILTERS {
            return Err(invalid("query contains too many filters"));
        }
        let mut selector = Self::default();
        let mut seen = Vec::with_capacity(filters.len());
        for filter in filters {
            parse_one(filter, &mut selector, &mut seen)?;
        }
        if selector.ip.is_none() && selector.ip_direction != IpDirection::Either {
            return Err(invalid("ip_direction requires an ip filter"));
        }
        Ok(selector)
    }

    /// Return whether the selector constrains packet-derived network facts
    #[must_use]
    pub const fn has_network_filter(&self) -> bool {
        self.ip.is_some()
            || self.source_ip.is_some()
            || self.destination_ip.is_some()
            || self.protocol.is_some()
            || self.source_port.is_some()
            || self.destination_port.is_some()
            || self.port.is_some()
            || self.packet_range.is_some()
            || self.time_range.is_some()
            || !self.fields.is_empty()
            || self.interface.is_some()
            || self.vlan.is_some()
    }
}

fn parse_one(
    filter: &str,
    selector: &mut Selector,
    seen: &mut Vec<String>,
) -> Result<(), QueryError> {
    if filter.len() > MAX_FILTER_BYTES || filter.chars().any(char::is_whitespace) {
        return Err(invalid("query filter is oversized or contains whitespace"));
    }
    let (key, value) = filter
        .split_once('=')
        .ok_or_else(|| invalid("query filters must use key=value syntax"))?;
    if key.is_empty() || value.is_empty() || value.contains('=') {
        return Err(invalid(
            "query filter must contain one nonempty key and value",
        ));
    }
    let field_name = key
        .strip_prefix("field.")
        .map(parse_field_name)
        .transpose()?;
    let canonical = field_name
        .as_deref()
        .map(|name| format!("field.{name}"))
        .or_else(|| canonical_key(key).map(str::to_owned))
        .ok_or_else(|| invalid("unknown query filter key"))?;
    if seen.iter().any(|prior| prior == &canonical) {
        return Err(invalid("query filter key is repeated"));
    }
    seen.push(canonical.clone());
    if let Some(name) = field_name {
        selector.fields.push(FieldValue {
            name,
            value: value.to_owned(),
        });
    } else {
        match canonical.as_str() {
            "ip" => selector.ip = Some(IpCidr::parse(value)?),
            "ip_direction" => selector.ip_direction = parse_direction(value)?,
            "source_ip" => selector.source_ip = Some(IpCidr::parse(value)?),
            "destination_ip" => selector.destination_ip = Some(IpCidr::parse(value)?),
            "protocol" => selector.protocol = Some(parse_protocol(value)?),
            "source_port" => selector.source_port = Some(parse_port(value)?),
            "destination_port" => selector.destination_port = Some(parse_port(value)?),
            "port" => selector.port = Some(parse_port(value)?),
            "packet" => selector.packet_range = Some(parse_packet_range(value)?),
            "time" => selector.time_range = Some(parse_time_range(value)?),
            "interface" => selector.interface = Some(parse_interface(value)?),
            "vlan" => selector.vlan = Some(parse_vlan(value)?),
            "kind" => selector.kind = Some(parse_kind(value)?),
            "status" => selector.status = Some(parse_status(value)?),
            _ => return Err(invalid("unknown query filter key")),
        }
    }
    Ok(())
}

fn canonical_key(key: &str) -> Option<&'static str> {
    match key {
        "ip" => Some("ip"),
        "ip_direction" => Some("ip_direction"),
        "src" | "source" | "source_ip" => Some("source_ip"),
        "dst" | "destination" | "destination_ip" => Some("destination_ip"),
        "protocol" | "proto" => Some("protocol"),
        "sport" | "source_port" => Some("source_port"),
        "dport" | "destination_port" => Some("destination_port"),
        "port" => Some("port"),
        "packet" => Some("packet"),
        "time" => Some("time"),
        "interface" => Some("interface"),
        "vlan" => Some("vlan"),
        "kind" => Some("kind"),
        "status" => Some("status"),
        _ => None,
    }
}

fn parse_direction(value: &str) -> Result<IpDirection, QueryError> {
    match value {
        "either" => Ok(IpDirection::Either),
        "source" => Ok(IpDirection::Source),
        "destination" => Ok(IpDirection::Destination),
        _ => Err(invalid(
            "ip_direction must be either, source, or destination",
        )),
    }
}

fn parse_protocol(value: &str) -> Result<String, QueryError> {
    match value {
        "tcp" | "udp" | "arp" | "icmp" | "icmpv6" => Ok(value.to_owned()),
        _ if value.parse::<u8>().is_ok() => Ok(value.to_owned()),
        _ => Err(invalid(
            "protocol must be a supported name or an IP protocol number",
        )),
    }
}

fn parse_field_name(value: &str) -> Result<String, QueryError> {
    if value.len() > MAX_FIELD_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._".contains(&byte))
        || !SUPPORTED_FIELDS.contains(&value)
    {
        return Err(invalid("packet field name is unsupported"));
    }
    Ok(value.to_owned())
}

const SUPPORTED_FIELDS: &[&str] = &[
    "frame.number",
    "eth.src",
    "eth.dst",
    "eth.type",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "icmp.type",
    "icmpv6.type",
];

fn parse_port(value: &str) -> Result<u16, QueryError> {
    value
        .parse::<u16>()
        .map_err(|_| invalid("transport port must be between 0 and 65535"))
}

fn parse_packet_range(value: &str) -> Result<PacketRange, QueryError> {
    let (first, last) = value
        .split_once("..")
        .ok_or_else(|| invalid("packet filter must use first..last"))?;
    if last.contains("..") {
        return Err(invalid("packet filter must contain one range separator"));
    }
    let range = PacketRange {
        first: parse_positive(first, "packet range start")?,
        last: parse_positive(last, "packet range end")?,
    };
    if range.first > range.last {
        return Err(invalid("packet range start exceeds its end"));
    }
    Ok(range)
}

fn parse_time_range(value: &str) -> Result<TimeRange, QueryError> {
    let (first, last) = value
        .split_once("..")
        .ok_or_else(|| invalid("time filter must use first..last epoch seconds"))?;
    if last.contains("..") {
        return Err(invalid("time filter must contain one range separator"));
    }
    let range = TimeRange {
        first: first
            .parse::<i64>()
            .map_err(|_| invalid("time range start must be whole Unix seconds"))?,
        last: last
            .parse::<i64>()
            .map_err(|_| invalid("time range end must be whole Unix seconds"))?,
    };
    if range.first > range.last {
        return Err(invalid("time range start exceeds its end"));
    }
    Ok(range)
}

fn parse_positive(value: &str, name: &str) -> Result<u64, QueryError> {
    let parsed = value.parse::<u64>().map_err(|_| invalid(name))?;
    if parsed == 0 {
        return Err(invalid(name));
    }
    Ok(parsed)
}

fn parse_interface(value: &str) -> Result<InterfaceScope, QueryError> {
    let (section, index) = value
        .split_once(':')
        .ok_or_else(|| invalid("interface must use section:index"))?;
    if index.contains(':') {
        return Err(invalid("interface must contain one colon"));
    }
    Ok(InterfaceScope {
        section: section
            .parse()
            .map_err(|_| invalid("invalid interface section"))?,
        index: index
            .parse()
            .map_err(|_| invalid("invalid interface index"))?,
    })
}

fn parse_vlan(value: &str) -> Result<u16, QueryError> {
    let vlan = value
        .parse::<u16>()
        .map_err(|_| invalid("invalid VLAN id"))?;
    if vlan > 4094 {
        return Err(invalid("VLAN id must be between 0 and 4094"));
    }
    Ok(vlan)
}

fn parse_kind(value: &str) -> Result<String, QueryError> {
    if value.len() > MAX_KIND_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_:-".contains(&byte)
        })
    {
        return Err(invalid("node kind contains unsupported characters"));
    }
    Ok(value.to_owned())
}

fn parse_status(value: &str) -> Result<EvidenceStatus, QueryError> {
    match value {
        "observed" => Ok(EvidenceStatus::Observed),
        "hypothesis" => Ok(EvidenceStatus::Hypothesis),
        "constraint_satisfied" => Ok(EvidenceStatus::ConstraintSatisfied),
        "constraint_failed" => Ok(EvidenceStatus::ConstraintFailed),
        "unresolved" => Ok(EvidenceStatus::Unresolved),
        _ => Err(invalid("status is not a supported evidence status")),
    }
}

fn invalid(message: &str) -> QueryError {
    QueryError::InvalidFilter(message.to_owned())
}
