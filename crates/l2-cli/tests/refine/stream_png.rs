use super::{WORK_PER_BYTE, WorkHashReader, is_work_limit};
use std::{error::Error, io::Read};

#[test]
fn png_reader_charges_each_byte_and_stops_at_the_shared_work_limit() -> Result<(), Box<dyn Error>> {
    let input = b"abcdef";
    let mut remaining = 4 * WORK_PER_BYTE;
    let mut reader = WorkHashReader::new(input.as_slice(), &mut remaining);
    let mut output = [0_u8; 8];
    assert_eq!(reader.read(&mut output)?, 4);
    let error = reader.read(&mut output).err().ok_or("work limit ignored")?;
    assert!(is_work_limit(&error));
    let (work, digest) = reader.finish();
    assert_eq!(work, 4 * WORK_PER_BYTE);
    assert_eq!(digest, l2_workbench::sha256(b"abcd"));
    assert_eq!(remaining, 0);
    Ok(())
}
