use super::{Flow, Result, Store, invalid};
use l2_discovery::NetworkAddress;
use rusqlite::{Connection, OptionalExtension, params};
use std::{collections::HashMap, net::IpAddr};

pub(super) const CACHE_ENTRIES: usize = 8192;

pub(super) struct Transport<'a> {
    pub scope: i64,
    pub protocol: u8,
    pub source: Vec<u8>,
    pub destination: Vec<u8>,
    pub ports: (u16, u16),
    pub payload: &'a [u8],
    pub payload_offset: u64,
}

type Endpoint<'a> = (&'a [u8], u16);

impl Transport<'_> {
    pub(super) fn endpoints(&self) -> [Endpoint<'_>; 2] {
        let first = (self.source.as_slice(), self.ports.0);
        let second = (self.destination.as_slice(), self.ports.1);
        if first <= second {
            [first, second]
        } else {
            [second, first]
        }
    }

    pub(super) fn direction(&self) -> u8 {
        u8::from(
            (self.source.as_slice(), self.ports.0) > (self.destination.as_slice(), self.ports.1),
        )
    }
}

pub(super) fn address_bytes(address: NetworkAddress) -> Vec<u8> {
    match address {
        NetworkAddress::Ipv4(bytes) => bytes.to_vec(),
        NetworkAddress::Ipv6(bytes) => bytes.to_vec(),
    }
}

pub(super) fn ip(bytes: &[u8]) -> Result<IpAddr> {
    match bytes.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(bytes)?)),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(bytes)?)),
        _ => Err(invalid("invalid indexed IP address length")),
    }
}

pub(super) fn retain(
    connection: &Connection,
    cache: &mut HashMap<Vec<u8>, i64>,
    source: i64,
    transport: &Transport<'_>,
) -> Result<i64> {
    let [a, b] = transport.endpoints();
    let key = canonical_key(source, transport)?;
    if let Some(id) = cache.get(&key) {
        return Ok(*id);
    }
    let inserted = connection.prepare_cached("INSERT INTO flows(source,scope,protocol,a,ap,b,bp) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(source,scope,protocol,a,ap,b,bp) DO NOTHING RETURNING id")?
        .query_row(params![source, transport.scope, transport.protocol, a.0, a.1, b.0, b.1], |row| row.get(0)).optional()?;
    let id = match inserted {
        Some(id) => id,
        None => connection
            .prepare_cached("SELECT id FROM flows WHERE source=?1 AND scope=?2 AND protocol=?3 AND a=?4 AND ap=?5 AND b=?6 AND bp=?7")?
            .query_row(params![source,transport.scope,transport.protocol,a.0,a.1,b.0,b.1], |row| row.get(0))?,
    };
    // The database owns lifetime state; this small cache only avoids repeated lookups
    if cache.len() == CACHE_ENTRIES {
        cache.clear();
    }
    cache.insert(key, id);
    Ok(id)
}

fn canonical_key(source: i64, transport: &Transport<'_>) -> Result<Vec<u8>> {
    let [a, b] = transport.endpoints();
    let mut key = source.to_be_bytes().to_vec();
    key.extend_from_slice(&transport.scope.to_be_bytes());
    key.push(transport.protocol);
    key.push(u8::try_from(a.0.len())?);
    key.extend_from_slice(a.0);
    key.extend_from_slice(&a.1.to_be_bytes());
    key.extend_from_slice(b.0);
    key.extend_from_slice(&b.1.to_be_bytes());
    Ok(key)
}

impl Store {
    /// Stream tuple summaries in stable index order without retaining all connections
    ///
    /// # Errors
    /// Returns storage or visitor errors and rejects malformed address fields
    pub fn visit_flows(
        &self,
        after: i64,
        maximum: Option<u64>,
        mut visitor: impl FnMut(Flow) -> Result<()>,
    ) -> Result<()> {
        let mut statement = self.connection.prepare("SELECT f.id,s.sha256,f.protocol,f.a,f.ap,f.b,f.bp,MIN(p.number),MAX(p.number),COUNT(*),SUM(p.length),SUM(p.payload_length),c.value FROM flows f JOIN sources s ON s.id=f.source JOIN scopes c ON c.id=f.scope JOIN packets p ON p.flow=f.id WHERE f.id>?1 GROUP BY f.id ORDER BY f.id LIMIT ?2")?;
        let mut rows = statement.query(params![
            after,
            maximum.map(i64::try_from).transpose()?.unwrap_or(-1)
        ])?;
        while let Some(row) = rows.next()? {
            visitor(Flow {
                id: row.get(0)?,
                source_id: row.get(1)?,
                scope: serde_json::from_slice(&row.get::<_, Vec<u8>>(12)?)?,
                protocol: row.get(2)?,
                endpoint_a: ip(&row.get::<_, Vec<u8>>(3)?)?,
                port_a: row.get(4)?,
                endpoint_b: ip(&row.get::<_, Vec<u8>>(5)?)?,
                port_b: row.get(6)?,
                first_packet: row.get(7)?,
                last_packet: row.get(8)?,
                packets: row.get(9)?,
                frame_bytes: row.get(10)?,
                payload_bytes: row.get(11)?,
            })?;
        }
        Ok(())
    }
}
