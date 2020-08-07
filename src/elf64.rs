use std::ops::Range;

use crate::ByteOrder;
use crate::demangle::SymbolData;
use crate::parser::*;

mod elf {
    pub type Address = u64;
    pub type Offset = u64;
    pub type Half = u16;
    pub type Word = u32;
    pub type XWord = u64;
}

mod section_type {
    pub const SYMBOL_TABLE: super::elf::Word = 2;
    pub const STRING_TABLE: super::elf::Word = 3;
}

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

fn parse_elf_header(data: &[u8], byte_order: ByteOrder) -> Elf64Header {
    // TODO: ensure there's enough data
    let mut s = Stream::new(&data[16..], byte_order);
    Elf64Header {
        elf_type: s.read(),
        machine: s.read(),
        version: s.read(),
        entry: s.read(),
        phoff: s.read(),
        shoff: s.read(),
        flags: s.read(),
        ehsize: s.read(),
        phentsize: s.read(),
        phnum: s.read(),
        shentsize: s.read(),
        shnum: s.read(),
        shstrndx: s.read(),
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Section {
    index: u16,
    name: u32,
    kind: u32,
    link: usize,
    offset: u64,
    size: u64,
    entries: usize,
}

fn parse_elf_sections(
    data: &[u8],
    byte_order: ByteOrder,
    header: &Elf64Header
) -> Vec<Section> {
    let count = header.shnum;
    let section_offset = header.shoff as usize; // TODO: harden
    let mut s = Stream::new(&data[section_offset..], byte_order);
    let mut sections = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        // TODO: ensure there's enough data
        let name: elf::Word = s.read();
        let kind: elf::Word = s.read();
        s.skip::<elf::XWord>(); // flags
        s.skip::<elf::Address>(); // addr
        let offset = s.read::<elf::Offset>();
        let size = s.read::<elf::XWord>();
        let link = s.read::<elf::Word>() as usize;
        s.skip::<elf::Word>(); // info
        s.skip::<elf::XWord>(); // addralign
        let entry_size = s.read::<elf::XWord>();

        // TODO: harden
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
    sections
}

impl Section {
    pub fn range(&self) -> Range<usize> {
        self.offset as usize .. (self.offset as usize + self.size as usize)
    }
}

pub struct Elf64<'a> {
    data: &'a [u8],
    byte_order: ByteOrder,
    header: Elf64Header,
    sections: Vec<Section>,
}

pub fn parse(data: &[u8], byte_order: ByteOrder) -> Elf64 {
    let header = parse_elf_header(data, byte_order);
    let sections = parse_elf_sections(data, byte_order, &header);
    Elf64 { data, byte_order, header, sections }
}

impl<'a> Elf64<'a> {
    pub fn header(&self) -> Elf64Header {
        self.header.clone()
    }

    pub fn sections(&self) -> Vec<Section> {
        self.sections.clone()
    }

    pub fn section_with_name(&self, name: &str) -> Option<Section> {
        let data = self.data;
        let section_name_strings_index = self.header.shstrndx; // TODO: validate
        let sections = &self.sections;
    
        let section_name_strings = &data[sections[section_name_strings_index as usize].range()];
        Some(sections.iter().find(|s| {
            parse_null_string(section_name_strings, s.name as usize) == Some(name)
        }).cloned()?)
    }

    pub fn symbols(&self) -> (Vec<SymbolData>, u64) {
        match self.extract_symbols() {
            Some(v) => v,
            None => (Vec::new(), 0),
        }
    }

    fn extract_symbols(&self) -> Option<(Vec<SymbolData>, u64)> {
        let data = self.data;
        let sections = &self.sections;

        let text_section = self.section_with_name(".text")?;
        let symbols_section = sections.iter().find(|v| v.kind == section_type::SYMBOL_TABLE)?;
        let linked_section = sections.get(symbols_section.link)?;
        if linked_section.kind != section_type::STRING_TABLE {
            return None;
        }
    
        let strings = &data[linked_section.range()];
        let s = Stream::new(&data[symbols_section.range()], self.byte_order);
        let symbols = parse_symbols(s, symbols_section.entries, strings, text_section);
        Some((symbols, text_section.size))
    }
}


fn parse_symbols(
    mut s: Stream,
    count: usize,
    strings: &[u8],
    text_section: Section,
) -> Vec<SymbolData> {
    let mut symbols = Vec::with_capacity(count);
    while !s.at_end() {
        // Note: the order of fields in 32 and 64 bit ELF is different.
        let name_offset = s.read::<elf::Word>() as usize;
        let info: u8 = s.read();
        s.skip::<u8>(); // other
        let shndx: elf::Half = s.read();
        let value: elf::Address = s.read();
        let size: elf::XWord = s.read();

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
                address: value,
                size,
            });
        }
    }

    symbols
}
