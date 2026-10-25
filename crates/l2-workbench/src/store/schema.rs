use super::{Options, Result, SCHEMA_VERSION, invalid};
use rusqlite::Connection;
use rusqlite::limits::Limit;

const APPLICATION_ID: i64 = 0x4c32_5349;

pub(super) fn configure(connection: &Connection, options: Options) -> Result<()> {
    // The database contains compact metadata, while large evidence bytes stay in source files
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 1)?;
    // A fixed page cache and file-backed temporary tables keep input size off the heap
    connection.pragma_update(None, "cache_size", -i64::from(options.cache_mib) * 1024)?;
    let effective: i64 = connection.pragma_query_value(None, "cache_size", |row| row.get(0))?;
    if effective != -i64::from(options.cache_mib) * 1024 {
        return Err(invalid(
            "requested cache budget exceeds SQLite's representable cache setting",
        ));
    }
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0;")?;
    connection.set_prepared_statement_cache_capacity(32);
    Ok(())
}

pub(super) fn create(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE sources(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, label TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0, unsupported INTEGER NOT NULL DEFAULT 0, collection_summary TEXT) STRICT;
        CREATE TABLE contexts(id INTEGER PRIMARY KEY, value TEXT NOT NULL UNIQUE) STRICT;
        CREATE TABLE scopes(id INTEGER PRIMARY KEY, value BLOB NOT NULL UNIQUE) STRICT;
        CREATE TABLE flows(id INTEGER PRIMARY KEY, source INTEGER NOT NULL REFERENCES sources(id), scope INTEGER NOT NULL REFERENCES scopes(id), protocol INTEGER NOT NULL, a BLOB NOT NULL, ap INTEGER NOT NULL, b BLOB NOT NULL, bp INTEGER NOT NULL, UNIQUE(source,scope,protocol,a,ap,b,bp)) STRICT;
        CREATE INDEX flows_source_scope_a_b ON flows(source,scope,a,b);
        CREATE TABLE packets(source INTEGER NOT NULL REFERENCES sources(id), number INTEGER NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, original_length INTEGER NOT NULL, context INTEGER NOT NULL REFERENCES contexts(id), ticks BLOB, framing_offset INTEGER NOT NULL, format INTEGER NOT NULL, flow INTEGER REFERENCES flows(id), payload_length INTEGER NOT NULL, direction INTEGER NOT NULL, sha256 BLOB NOT NULL, PRIMARY KEY(source,number)) WITHOUT ROWID, STRICT;
        CREATE INDEX packets_flow ON packets(flow,number);
        CREATE INDEX packets_flow_direction ON packets(flow,direction,number);
        CREATE TABLE shared_facts(kind TEXT NOT NULL CHECK(kind IN ('ip_address','dns_question','packet_bytes')), fact_key BLOB NOT NULL, source INTEGER NOT NULL, packet INTEGER NOT NULL, scope INTEGER REFERENCES scopes(id), offset INTEGER NOT NULL CHECK(offset>=0), length INTEGER NOT NULL CHECK(length>=0), PRIMARY KEY(kind,fact_key,source,packet), FOREIGN KEY(source,packet) REFERENCES packets(source,number), CHECK((kind='ip_address' AND length(fact_key) IN (4,16)) OR (kind='dns_question' AND length(fact_key)>0 AND length(fact_key)<=255) OR (kind='packet_bytes' AND length(fact_key)=32))) WITHOUT ROWID, STRICT;
        CREATE TABLE dns_pending(key BLOB NOT NULL, source INTEGER NOT NULL REFERENCES sources(id), packet INTEGER NOT NULL, PRIMARY KEY(key,packet)) WITHOUT ROWID, STRICT;
        CREATE TABLE dns_exchanges(source INTEGER NOT NULL REFERENCES sources(id), response INTEGER NOT NULL, request INTEGER, status TEXT NOT NULL, questions TEXT NOT NULL, PRIMARY KEY(source,response), FOREIGN KEY(source,response) REFERENCES packets(source,number), FOREIGN KEY(source,request) REFERENCES packets(source,number)) WITHOUT ROWID, STRICT;
        CREATE TABLE dns_addresses(source INTEGER NOT NULL REFERENCES sources(id), scope INTEGER NOT NULL REFERENCES scopes(id), response INTEGER NOT NULL, request INTEGER, requester BLOB NOT NULL, address BLOB NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, status TEXT NOT NULL, owner BLOB NOT NULL, PRIMARY KEY(source,response,offset), FOREIGN KEY(source,response) REFERENCES dns_exchanges(source,response)) WITHOUT ROWID, STRICT;
        CREATE INDEX dns_addresses_address ON dns_addresses(source,address,response);")?;
    Ok(())
}

pub(super) fn validate(connection: &Connection) -> Result<()> {
    let app: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if app != APPLICATION_ID || version != i64::from(SCHEMA_VERSION) {
        return Err(invalid("unsupported capture index schema"));
    }
    Ok(())
}
