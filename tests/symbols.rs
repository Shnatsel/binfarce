use binfarce::{elf32, elf64, macho, pe, ByteOrder, ParseError};

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// A 64-bit Mach-O header, a segment with one __text section, a symbol-table
// command, three string-table bytes, and one 16-byte symbol record.
fn macho_fixture() -> Vec<u8> {
    let mut data = vec![0; 227];
    put_u32(&mut data, 0, 0xfeedfacf);
    put_u32(&mut data, 16, 2); // command count
    put_u32(&mut data, 20, 176); // command bytes
    put_u32(&mut data, 32, 0x19); // LC_SEGMENT_64
    put_u32(&mut data, 36, 152);
    put_u32(&mut data, 96, 1); // section count
    data[104..110].copy_from_slice(b"__text");
    data[120..126].copy_from_slice(b"__TEXT");
    put_u64(&mut data, 136, 0x1000); // section address
    put_u64(&mut data, 144, 16); // section size
    put_u32(&mut data, 184, 2); // LC_SYMTAB
    put_u32(&mut data, 188, 24);
    put_u32(&mut data, 192, 211); // symbol offset
    put_u32(&mut data, 196, 1); // symbol count
    put_u32(&mut data, 200, 208); // string offset
    put_u32(&mut data, 204, 3); // string bytes
    data[208..211].copy_from_slice(b"\0x\0");
    put_u32(&mut data, 211, 1); // symbol name offset
    data[215] = 0x0e; // N_SECT
    data[216] = 1; // section number
    put_u64(&mut data, 219, 0x1000); // symbol address
    data
}

#[test]
fn macho_extracts_symbols_and_accepts_empty_text() {
    let mut data = macho_fixture();
    let (symbols, size) = macho::parse(&data).unwrap().symbols().unwrap();
    assert_eq!(size, 16);
    assert_eq!(symbols.len(), 1);
    assert_eq!(symbols[0].name.complete, "x");
    assert_eq!(symbols[0].address, 0x1000);
    assert_eq!(symbols[0].size, 16);

    put_u64(&mut data, 144, 0);
    put_u32(&mut data, 196, 0);
    let (symbols, size) = macho::parse(&data).unwrap().symbols().unwrap();
    assert_eq!(size, 0);
    assert!(symbols.is_empty());
}

#[test]
fn macho_rejects_invalid_or_truncated_commands() {
    for size in [0, 7, 8, 23, u32::MAX] {
        let mut data = macho_fixture();
        put_u32(&mut data, 188, size);
        assert!(macho::parse(&data).unwrap().symbols().is_err());
    }
    for end in 184..208 {
        let data = macho_fixture();
        assert!(macho::parse(&data[..end]).unwrap().symbols().is_err());
    }
    // The segment claims a section that doesn't fit inside its own command.
    let mut data = macho_fixture();
    put_u32(&mut data, 36, 72);
    assert!(macho::parse(&data).unwrap().symbols().is_err());
}

#[test]
fn macho_rejects_invalid_tables_before_allocating() {
    for (offset, value) in [
        (192, 228),      // symbol offset past EOF
        (196, 2),        // truncated symbol table
        (196, u32::MAX), // allocation/capacity overflow regression
        (200, 228),      // string offset past EOF
        (200, u32::MAX), // offset + size overflow on 32-bit targets
        (204, u32::MAX), // string size past EOF
    ] {
        let mut data = macho_fixture();
        put_u32(&mut data, offset, value);
        assert!(macho::parse(&data).unwrap().symbols().is_err());
    }
}

#[test]
fn macho_rejects_invalid_symbol_addresses() {
    for (offset, value) in [
        (136, u64::MAX), // section end overflows
        (219, 0x0fff),   // symbol precedes its section
        (219, 0x2000),   // symbol follows its section
    ] {
        let mut data = macho_fixture();
        put_u64(&mut data, offset, value);
        assert!(matches!(
            macho::parse(&data).unwrap().symbols(),
            Err(ParseError::MalformedInput)
        ));
    }
}

#[test]
fn macho_other_sections_do_not_extend_text_symbols() {
    let mut data = macho_fixture();
    data.extend_from_slice(&[0; 16]);
    put_u32(&mut data, 196, 2);
    put_u32(&mut data, 227, 1);
    data[231] = 0x0e;
    data[232] = 2;
    put_u64(&mut data, 235, 0x2000);
    let (symbols, _) = macho::parse(&data).unwrap().symbols().unwrap();
    assert_eq!(symbols.len(), 1);
    assert_eq!(symbols[0].size, 16);
}

// PE header at 64, COFF header at 68, one .text section at 88, followed by
// 18-byte symbol records and the string table (including its length field).
fn pe_fixture(symbols: &[(&str, u32)]) -> Vec<u8> {
    let mut data = vec![0; 128 + 18 * symbols.len()];
    data[..2].copy_from_slice(b"MZ");
    put_u32(&mut data, 60, 64);
    data[64..68].copy_from_slice(b"PE\0\0");
    put_u16(&mut data, 70, 1); // section count
    put_u32(&mut data, 76, 128); // symbol offset
    put_u32(&mut data, 80, symbols.len() as u32);
    data[88..93].copy_from_slice(b".text");
    put_u32(&mut data, 104, 16); // section size
    for (i, (name, address)) in symbols.iter().enumerate() {
        let start = 128 + 18 * i;
        assert!(name.len() <= 8);
        data[start..start + name.len()].copy_from_slice(name.as_bytes());
        put_u32(&mut data, start + 8, *address);
        put_u16(&mut data, start + 12, 1); // section number
        put_u16(&mut data, start + 14, 0x20); // function
        data[start + 16] = 2; // external
    }
    data.extend_from_slice(b"\x08\0\0\0foo\0");
    data
}

#[test]
fn pe_sizes_first_last_and_duplicate_symbols() {
    let data = pe_fixture(&[("foo", 0), ("alias", 0), ("bar", 8), ("end", 16)]);
    let (symbols, size) = pe::parse(&data).unwrap().symbols().unwrap();
    assert_eq!(size, 16);
    let result: Vec<_> = symbols
        .iter()
        .map(|s| (s.name.complete.as_str(), s.size))
        .collect();
    assert_eq!(result, [("foo", 8), ("alias", 8), ("bar", 8), ("end", 0)]);
}

#[test]
fn pe_ignores_invalid_section_numbers() {
    for section in [i16::MIN, -2, -1, 0, 2, i16::MAX] {
        let mut data = pe_fixture(&[("foo", 0)]);
        put_u16(&mut data, 140, section as u16);
        let (symbols, _) = pe::parse(&data).unwrap().symbols().unwrap();
        assert!(symbols.is_empty());
    }
}

#[test]
fn pe_string_offsets_do_not_wrap() {
    for offset in [4, u32::MAX] {
        let mut data = pe_fixture(&[("", 0)]);
        put_u32(&mut data, 132, offset);
        let (symbols, _) = pe::parse(&data).unwrap().symbols().unwrap();
        if offset == 4 {
            assert_eq!(symbols.len(), 1);
            assert_eq!(symbols[0].name.complete, "foo");
        } else {
            assert!(symbols.is_empty());
        }
    }
}

#[test]
fn pe_rejects_invalid_tables_before_allocating() {
    for (offset, value) in [(76, u32::MAX), (80, u32::MAX), (80, 2)] {
        let mut data = pe_fixture(&[("foo", 0)]);
        put_u32(&mut data, offset, value);
        assert!(pe::parse(&data).unwrap().symbols().is_err());
    }
    let mut data = pe_fixture(&[("foo", 0)]);
    data[145] = 1; // auxiliary record doesn't fit inside the symbol table
    assert!(pe::parse(&data).unwrap().symbols().is_err());
}

#[test]
fn pe_accepts_an_empty_symbol_table_at_eof() {
    let mut data = pe_fixture(&[]);
    data.truncate(128);
    let (symbols, size) = pe::parse(&data).unwrap().symbols().unwrap();
    assert!(symbols.is_empty());
    assert_eq!(size, 16);
}

#[test]
fn pe_rejects_symbols_past_the_section_end() {
    let data = pe_fixture(&[("foo", 17)]);
    assert!(matches!(
        pe::parse(&data).unwrap().symbols(),
        Err(ParseError::MalformedInput)
    ));
}

#[test]
fn pe_bounds_repeated_string_table_references() {
    let count = 1024;
    let mut data = pe_fixture(&vec![("", 0); count]);
    data.truncate(128 + 18 * count);
    for i in 0..count {
        put_u32(&mut data, 128 + 18 * i + 4, 4);
    }
    data.extend_from_slice(&65541u32.to_le_bytes());
    data.resize(data.len() + 65536, b'x');
    data.push(0);
    assert!(matches!(
        pe::parse(&data).unwrap().symbols(),
        Err(ParseError::ResourceLimitExceeded)
    ));
}

#[test]
fn macho_many_aliases_keep_their_order_and_sizes() {
    let mut data = macho_fixture();
    // Use the existing "x" name for every alias. Their order is distinguished
    // below by adding one final symbol at the next address.
    let record = data[211..227].to_vec();
    for _ in 1..10_000 {
        data.extend_from_slice(&record);
    }
    put_u32(&mut data, 196, 10_000);
    let last_address = data.len() - 8;
    put_u64(&mut data, last_address, 0x1008);
    let (symbols, _) = macho::parse(&data).unwrap().symbols().unwrap();
    assert_eq!(symbols.len(), 10_000);
    assert!(symbols[..9999]
        .iter()
        .all(|s| s.address == 0x1000 && s.size == 8));
    assert_eq!(symbols[9999].address, 0x1008);
    assert_eq!(symbols[9999].size, 8);
}

#[test]
fn elf_symbol_extraction_does_not_depend_on_allocation_hints() {
    for is_64 in [false, true] {
        let mut data = vec![0; 512];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = if is_64 { 2 } else { 1 };
        data[5] = 1;
        let header_size = if is_64 { 64 } else { 40 };
        if is_64 {
            put_u64(&mut data, 40, 64); // section header table
            put_u16(&mut data, 58, 64);
            put_u16(&mut data, 60, 4); // section count
            put_u16(&mut data, 62, 3); // section-name string table index
        } else {
            put_u32(&mut data, 32, 64);
            put_u16(&mut data, 46, 40);
            put_u16(&mut data, 48, 4);
            put_u16(&mut data, 50, 3);
        }
        let strings = b"\0.text\0.symtab\0.strtab\0foo\0";
        data[448..448 + strings.len()].copy_from_slice(strings);
        for (index, name, kind, offset, size) in [
            (1, 1, 1, 400, 16),
            (2, 7, 2, 416, if is_64 { 24 } else { 16 }),
            (3, 15, 3, 448, strings.len() as u32),
        ] {
            let start = 64 + index * header_size;
            put_u32(&mut data, start, name);
            put_u32(&mut data, start + 4, kind);
            if is_64 {
                put_u64(&mut data, start + 24, offset.into());
                put_u64(&mut data, start + 32, size.into());
            } else {
                put_u32(&mut data, start + 16, offset);
                put_u32(&mut data, start + 20, size);
            }
        }
        let symtab = 64 + 2 * header_size;
        put_u32(&mut data, symtab + if is_64 { 40 } else { 24 }, 3);
        put_u32(&mut data, 416, 23); // symbol name
        if is_64 {
            data[420] = 2; // STT_FUNC
            put_u16(&mut data, 422, 1); // section index
            put_u64(&mut data, 424, 0x1000);
            put_u64(&mut data, 432, 16);
        } else {
            put_u32(&mut data, 420, 0x1000);
            put_u32(&mut data, 424, 16);
            data[428] = 2;
            put_u16(&mut data, 430, 1);
        }
        // These entry sizes used to control the allocation, even though symbol
        // records are always read at their fixed width.
        for entry_size in [if is_64 { 24 } else { 16 }, 1, 0] {
            let result = if is_64 {
                put_u64(&mut data, symtab + 56, entry_size.into());
                elf64::parse(&data, ByteOrder::LittleEndian)
                    .unwrap()
                    .symbols(".text")
            } else {
                put_u32(&mut data, symtab + 36, entry_size);
                elf32::parse(&data, ByteOrder::LittleEndian)
                    .unwrap()
                    .symbols(".text")
            };
            let (symbols, size) = result.unwrap();
            assert_eq!(size, 16);
            assert_eq!(symbols.len(), 1);
            assert_eq!(symbols[0].name.complete, "foo");
            assert_eq!(symbols[0].address, 0x1000);
            assert_eq!(symbols[0].size, 16);
        }
    }
}

#[test]
fn sorting_preserves_alias_order_in_pe_and_macho() {
    let names: Vec<_> = (0..256).map(|i| format!("alias{}", i)).collect();
    let records: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), (i % 3) as u32 * 4))
        .collect();
    let pe_data = pe_fixture(&records);
    let (pe_symbols, _) = pe::parse(&pe_data).unwrap().symbols().unwrap();

    let mut macho_data = macho_fixture();
    let template = macho_data[211..227].to_vec();
    macho_data.truncate(211);
    let mut strings = vec![0];
    for (name, address) in &records {
        let start = macho_data.len();
        macho_data.extend_from_slice(&template);
        put_u32(&mut macho_data, start, strings.len() as u32);
        put_u64(&mut macho_data, start + 8, 0x1000 + u64::from(*address));
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    put_u32(&mut macho_data, 196, records.len() as u32);
    let strings_offset = macho_data.len() as u32;
    put_u32(&mut macho_data, 200, strings_offset);
    put_u32(&mut macho_data, 204, strings.len() as u32);
    macho_data.extend_from_slice(&strings);
    let (macho_symbols, _) = macho::parse(&macho_data).unwrap().symbols().unwrap();

    let mut expected = records;
    expected.sort_by_key(|(_, address)| *address);
    for (symbols, base) in [(pe_symbols, 0), (macho_symbols, 0x1000)] {
        let actual: Vec<_> = symbols
            .iter()
            .map(|s| (s.name.complete.as_str(), s.address - base, s.size))
            .collect();
        let expected: Vec<_> = expected
            .iter()
            .map(|(name, address)| {
                (
                    *name,
                    u64::from(*address),
                    if *address == 8 { 8 } else { 4 },
                )
            })
            .collect();
        assert_eq!(actual, expected);
    }
}
