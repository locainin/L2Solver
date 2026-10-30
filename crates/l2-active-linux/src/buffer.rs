use std::io;

pub fn zeroed(length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub fn copy(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(io::Error::other)?;
    result.extend_from_slice(bytes);
    Ok(result)
}
