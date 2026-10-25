use std::error::Error;

pub(super) fn minimal_elf() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; 0x340];
    write_elf_header(&mut bytes)?;
    write_elf_text(&mut bytes)?;
    write_elf_sections(&mut bytes)?;
    write_elf_symbols(&mut bytes)?;
    Ok(bytes)
}

fn write_elf_header(bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    put(bytes, 0, b"\x7fELF\x02\x01\x01")?;
    put_u16(bytes, 16, 2)?;
    put_u16(bytes, 18, 62)?;
    put_u32(bytes, 20, 1)?;
    put_u64(bytes, 24, 0x0040_0004)?;
    put_u64(bytes, 32, 64)?;
    put_u64(bytes, 40, 0x200)?;
    put_u16(bytes, 52, 64)?;
    put_u16(bytes, 54, 56)?;
    put_u16(bytes, 56, 1)?;
    put_u16(bytes, 58, 64)?;
    put_u16(bytes, 60, 5)?;
    put_u16(bytes, 62, 2)?;
    Ok(())
}

fn write_elf_text(bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    put_u32(bytes, 64, 1)?;
    put_u32(bytes, 68, 5)?;
    put_u64(bytes, 72, 0x100)?;
    put_u64(bytes, 80, 0x0040_0000)?;
    put_u64(bytes, 88, 0x0040_0000)?;
    put_u64(bytes, 96, 16)?;
    put_u64(bytes, 104, 16)?;
    put_u64(bytes, 112, 0x1000)?;
    put(
        bytes,
        0x100,
        &[
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
            0x9e, 0x9f,
        ],
    )?;
    Ok(())
}

fn write_elf_sections(bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let section_names = b"\0.text\0.shstrtab\0.symtab\0.strtab\0";
    put(bytes, 0x120, section_names)?;
    let symbol_names = b"\0process_frame\0network_send\0";
    put(bytes, 0x1a0, symbol_names)?;
    let sections = [
        ElfSection {
            index: 1,
            name: 1,
            section_type: 1,
            flags: 6,
            address: 0x0040_0000,
            offset: 0x100,
            size: 16,
            link: 0,
            info: 0,
            alignment: 16,
            entry_size: 0,
        },
        ElfSection {
            index: 2,
            name: 7,
            section_type: 3,
            flags: 0,
            address: 0,
            offset: 0x120,
            size: section_names.len(),
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
        ElfSection {
            index: 3,
            name: 17,
            section_type: 11,
            flags: 0,
            address: 0,
            offset: 0x160,
            size: 72,
            link: 4,
            info: 1,
            alignment: 8,
            entry_size: 24,
        },
        ElfSection {
            index: 4,
            name: 25,
            section_type: 3,
            flags: 0,
            address: 0,
            offset: 0x1a0,
            size: symbol_names.len(),
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
    ];
    for section in &sections {
        write_elf_section(bytes, section)?;
    }
    Ok(())
}

fn write_elf_symbols(bytes: &mut [u8]) -> Result<(), Box<dyn Error>> {
    put_u32(bytes, 0x160 + 24, 1)?;
    put(bytes, 0x160 + 28, &[0x12])?;
    put_u16(bytes, 0x160 + 30, 1)?;
    put_u64(bytes, 0x160 + 32, 0x0040_0004)?;
    put_u64(bytes, 0x160 + 40, 4)?;
    put_u32(bytes, 0x160 + 48, 15)?;
    put(bytes, 0x160 + 52, &[0x12])?;
    put_u16(bytes, 0x160 + 54, 0)?;
    Ok(())
}

pub(super) fn minimal_pe() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; 0x400];
    put(&mut bytes, 0, b"MZ")?;
    put_u32(&mut bytes, 0x3c, 0x80)?;
    put(&mut bytes, 0x80, b"PE\0\0")?;
    put_u16(&mut bytes, 0x84, 0x014c)?;
    put_u16(&mut bytes, 0x86, 1)?;
    put_u16(&mut bytes, 0x94, 224)?;
    put_u16(&mut bytes, 0x96, 0x0102)?;
    put_u16(&mut bytes, 0x98, 0x010b)?;
    put_u32(&mut bytes, 0x98 + 16, 0x1000)?;
    put_u32(&mut bytes, 0x98 + 28, 0x0040_0000)?;
    put_u32(&mut bytes, 0x98 + 32, 0x1000)?;
    put_u32(&mut bytes, 0x98 + 36, 0x200)?;
    put_u32(&mut bytes, 0x98 + 56, 0x2000)?;
    put_u32(&mut bytes, 0x98 + 60, 0x200)?;
    put_u32(&mut bytes, 0x98 + 92, 16)?;
    put_u32(&mut bytes, 0x98 + 96 + 8, 0x1040)?;
    put_u32(&mut bytes, 0x98 + 96 + 12, 40)?;

    let section = 0x98 + 224;
    put(&mut bytes, section, b".text\0\0\0")?;
    put_u32(&mut bytes, section + 8, 0x200)?;
    put_u32(&mut bytes, section + 12, 0x1000)?;
    put_u32(&mut bytes, section + 16, 0x200)?;
    put_u32(&mut bytes, section + 20, 0x200)?;
    put_u32(&mut bytes, section + 36, 0x6000_0020)?;
    put(
        &mut bytes,
        0x200,
        &[
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
            0x9e, 0x9f,
        ],
    )?;

    put_u32(&mut bytes, 0x240, 0x10b0)?;
    put_u32(&mut bytes, 0x24c, 0x1080)?;
    put_u32(&mut bytes, 0x250, 0x10a0)?;
    put(&mut bytes, 0x280, b"sample.dll\0")?;
    put_u32(&mut bytes, 0x2a0, 0x10c0)?;
    put_u32(&mut bytes, 0x2b0, 0x10c0)?;
    put(&mut bytes, 0x2c2, b"send_packet\0")?;
    Ok(bytes)
}

pub(super) fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Box<dyn Error>> {
    put(bytes, offset, &value.to_le_bytes())
}

pub(super) fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Box<dyn Error>> {
    put(bytes, offset, &value.to_le_bytes())
}

pub(super) fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), Box<dyn Error>> {
    put(bytes, offset, &value.to_le_bytes())
}

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(value.len())
        .ok_or("fixture byte range overflow")?;
    bytes
        .get_mut(offset..end)
        .ok_or("fixture byte range outside buffer")?
        .copy_from_slice(value);
    Ok(())
}

#[derive(Clone, Copy)]
struct ElfSection {
    index: usize,
    name: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: usize,
}

fn write_elf_section(bytes: &mut [u8], section: &ElfSection) -> Result<(), Box<dyn Error>> {
    let base = section
        .index
        .checked_mul(64)
        .and_then(|offset| 0x200_usize.checked_add(offset))
        .ok_or("fixture section offset overflow")?;
    put_u32(bytes, base, section.name)?;
    put_u32(bytes, base + 4, section.section_type)?;
    put_u64(bytes, base + 8, section.flags)?;
    put_u64(bytes, base + 16, section.address)?;
    put_u64(bytes, base + 24, u64::try_from(section.offset)?)?;
    put_u64(bytes, base + 32, u64::try_from(section.size)?)?;
    put_u32(bytes, base + 40, section.link)?;
    put_u32(bytes, base + 44, section.info)?;
    put_u64(bytes, base + 48, section.alignment)?;
    put_u64(bytes, base + 56, u64::try_from(section.entry_size)?)?;
    Ok(())
}
