//! JSON configuration reads retain the default parser depth limit and a byte ceiling

use serde::de::DeserializeOwned;
use std::{error::Error, io::Read};

pub fn read<T: DeserializeOwned>(reader: impl Read, maximum: u64) -> Result<T, Box<dyn Error>> {
    let probe = maximum.checked_add(1).ok_or("JSON size limit overflow")?;
    let mut bytes = Vec::new();
    reader.take(probe).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > maximum {
        return Err("JSON input exceeds its byte limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
