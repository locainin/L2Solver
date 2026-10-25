use png::{BitDepth, ColorType, Encoder};
use std::error::Error;

pub(super) fn structural_png(extra_chunks: &[([u8; 4], &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = l2_workbench::artifact::PNG_SIGNATURE.to_vec();
    append_chunk(
        &mut bytes,
        *b"IHDR",
        &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
    )?;
    for (chunk_type, payload) in extra_chunks {
        append_chunk(&mut bytes, *chunk_type, payload)?;
    }
    append_chunk(&mut bytes, *b"IEND", &[])?;
    Ok(bytes)
}

fn append_chunk(
    output: &mut Vec<u8>,
    chunk_type: [u8; 4],
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let length = u32::try_from(payload.len())?;
    let mut checksum = crc32fast::Hasher::new();
    checksum.update(&chunk_type);
    checksum.update(payload);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&chunk_type);
    output.extend_from_slice(payload);
    output.extend_from_slice(&checksum.finalize().to_be_bytes());
    Ok(())
}

pub(super) fn encode_png(
    width: u32,
    height: u32,
    color_type: ColorType,
    bit_depth: BitDepth,
    data: &[u8],
    palette: Option<&[u8]>,
    transparency: Option<&[u8]>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = Encoder::new(&mut bytes, width, height);
        encoder.set_color(color_type);
        encoder.set_depth(bit_depth);
        if let Some(palette) = palette {
            encoder.set_palette(palette);
        }
        if let Some(transparency) = transparency {
            encoder.set_trns(transparency);
        }
        let mut writer = encoder.write_header()?;
        writer.write_image_data(data)?;
        writer.finish()?;
    }
    Ok(bytes)
}
