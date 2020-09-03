use std::{convert::TryInto, ops::Range, mem::size_of, cmp::min};

use crate::ByteOrder;
use crate::demangle::SymbolData;
use crate::parser::*;
use crate::ParseError;

mod elf {
    pub type Address = u32;
    pub type Offset = u32;
    pub type Half = u16;
    pub type Word = u32;
}

mod section_type {
    pub const SYMBOL_TABLE: super::elf::Word = 2;
    pub const STRING_TABLE: super::elf::Word = 3;
}

const RAW_ELF_HEADER_SIZE: usize = size_of::<Elf64Header>();
const RAW_SECTION_HEADER_SIZE: usize = size_of::<elf::Word>() * 8 +
    size_of::<elf::Address>() + size_of::<elf::Offset>();

#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub elf_type: elf::Half,
    pub machine: elf::Half,
    pub version: elf::Word,
    pub entry: elf::Address,
    pub phoff: elf::Offset,
    pub shoff: elf::Offset,
    pub flags: elf::Word,
    pub ehsize: elf::Half,
    pub phentsize: elf::Half,
    pub phnum: elf::Half,
    pub shentsize: elf::Half,
    pub shnum: elf::Half,
    pub shstrndx: elf::Half,
}

fn parse_elf_header(data: &[u8], byte_order: ByteOrder) -> Result<Elf64Header, UnexpectedEof> {
    let mut s = Stream::new(&data.get(16..).ok_or(UnexpectedEof{})?, byte_order);
    if s.remaining() >= RAW_ELF_HEADER_SIZE {
        Ok(Elf64Header {
            elf_type: s.read()?,
            machine: s.read()?,
            version: s.read()?,
            entry: s.read()?,
            phoff: s.read()?,
            shoff: s.read()?,
            flags: s.read()?,
            ehsize: s.read()?,
            phentsize: s.read()?,
            phnum: s.read()?,
            shentsize: s.read()?,
            shnum: s.read()?,
            shstrndx: s.read()?,
        })
    } else {
        Err(UnexpectedEof {})
    }

}
#[derive(Debug, Clone, Copy)]
pub struct Section {
    index: u16,
    name: u32,
    kind: u32,
    link: usize,
    offset: u32,
    size: u32,
    entries: usize,
}

fn parse_elf_sections(
    data: &[u8],
    byte_order: ByteOrder,
    header: &Elf64Header
) -> Result<Vec<Section>, ParseError> {
    let count: usize = header.shnum.into();
    let section_offset: usize = header.shoff.try_into()?;
    let mut s = Stream::new_at(data, section_offset, byte_order)?;
    // Don't preallocate space for more than 1024 entries; it's rare in the wild and may OOM
    let mut sections = Vec::with_capacity(min(count, 1024));
    while sections.len() < count && s.remaining() >= RAW_SECTION_HEADER_SIZE {
        let name  = s.read::<elf::Word>()?;
        let kind  = s.read::<elf::Word>()?;
        s.skip::<elf::Word>()?; // flags
        s.skip::<elf::Address>()?; // addr
        let offset = s.read::<elf::Offset>()?;
        let size = s.read::<elf::Word>()?;
        let link = s.read::<elf::Word>()? as usize;
        s.skip::<elf::Word>()?; // info
        s.skip::<elf::Word>()?; // addralign
        let entry_size = s.read::<elf::Word>()?;

        // TODO: harden?
        let entries = if entry_size == 0 { 0 } else { size / entry_size } as usize;

        sections.push(Section {
            index: sections.len() as u16,
            name,
            kind,
            link,
            offset,
            size,
            entries,
        });
    }
    Ok(sections)
}

impl Section {
    pub fn range(&self) -> Result<Range<usize>, ParseError> {
        let start: usize = self.offset.try_into()?;
        let end: usize = start.checked_add(self.size.try_into()?).ok_or(ParseError::MalformedInput)?;
        Ok(start..end)
    }
}

pub struct Elf64<'a> {
    data: &'a [u8],
    byte_order: ByteOrder,
    header: Elf64Header,
    sections: Vec<Section>,
}

pub fn parse(data: &[u8], byte_order: ByteOrder) -> Result<Elf64, ParseError> {
    let header = parse_elf_header(data, byte_order)?;
    let sections = parse_elf_sections(data, byte_order, &header)?;
    Ok(Elf64 { data, byte_order, header, sections })
}

impl<'a> Elf64<'a> {
    pub fn header(&self) -> Elf64Header {
        self.header.clone()
    }

    pub fn sections(&self) -> Vec<Section> {
        self.sections.clone()
    }

    pub fn section_with_name(&self, name: &str) -> Option<Section> {
        let sections = &self.sections;
        let section_names_data_range = sections.get(usize::from(self.header.shstrndx))?.range().ok()?;
        let section_name_strings = &self.data.get(section_names_data_range)?;
        Some(sections.iter().find(|s| {
            parse_null_string(section_name_strings, s.name as usize) == Some(name)
        }).cloned()?)
    }

    pub fn symbols(&self) -> Result<(Vec<SymbolData>, u64), ParseError> {
        let data = self.data;
        let sections = &self.sections;

        let text_section = self.section_with_name(".text")
            .ok_or(ParseError::MalformedInput)?;
        let symbols_section = sections.iter().find(|v| v.kind == section_type::SYMBOL_TABLE)
            .ok_or(ParseError::MalformedInput)?;
        let linked_section = sections.get(symbols_section.link)
            .ok_or(ParseError::MalformedInput)?;
        if linked_section.kind != section_type::STRING_TABLE {
            return Err(ParseError::MalformedInput);
        }
    
        let strings = &data[linked_section.range()?];
        let s = Stream::new(&data[symbols_section.range()?], self.byte_order);
        let symbols = parse_symbols(s, symbols_section.entries, strings, text_section)?;
        Ok((symbols, text_section.size.into()))
    }
}

fn parse_symbols(
    mut s: Stream,
    count: usize,
    strings: &[u8],
    text_section: Section,
) -> Result<Vec<SymbolData>, UnexpectedEof> {
    let mut symbols = Vec::with_capacity(count);
    while !s.at_end() {
        // Note: the order of fields in 32 and 64 bit ELF is different.
        let name_offset = s.read::<elf::Word>()? as usize;
        let value: elf::Address = s.read()?;
        let size: elf::Word = s.read()?;
        let info: u8 = s.read()?;
        s.skip::<u8>()?; // other
        let shndx: elf::Half = s.read()?;

        if shndx != text_section.index {
            continue;
        }

        // Ignore symbols with zero size.
        if size == 0 {
            continue;
        }

        // Ignore symbols without a name.
        if name_offset == 0 {
            continue;
        }

        // Ignore symbols that aren't functions.
        const STT_FUNC: u8 = 2;
        let kind = info & 0xf;
        if kind != STT_FUNC {
            continue;
        }

        if let Some(s) = parse_null_string(strings, name_offset) {
            symbols.push(SymbolData {
                name: crate::demangle::SymbolName::demangle(s),
                address: value as u64,
                size: size as u64,
            });
        }
    }

    Ok(symbols)
}
