use std::str;

use crate::parser::*;
use crate::symbol_budget::SymbolBudget;
use crate::{ByteOrder, ParseError};

pub fn parse(data: &[u8]) -> Result<Vec<String>, ParseError> {
    const MAGIC: &[u8] = b"!<arch>\x0A";

    if data.get(0..8) != Some(MAGIC) {
        return Ok(Vec::new());
    }

    let mut s = Stream::new(&data[8..], ByteOrder::BigEndian);
    while !s.at_end() {
        // Align the offset.
        if s.offset() & 1 == 1 {
            s.read_bytes(1)?;
            if s.at_end() {
                break;
            }
        }

        let identifier =
            str::from_utf8(s.read_bytes(16)?).map_err(|_| ParseError::MalformedInput)?;
        s.skip_len(12)?; // timestamp
        s.skip_len(6)?; // owner_id
        s.skip_len(6)?; // group_id
        s.skip_len(8)?; // mode
        let file_size: usize = str::from_utf8(s.read_bytes(10)?)
            .map_err(|_| ParseError::MalformedInput)?
            .trim()
            .parse()
            .map_err(|_| ParseError::MalformedInput)?;
        let terminator = s.read_bytes(2)?;

        if terminator != b"`\n" {
            return Err(ParseError::MalformedInput);
        }

        let mut contents = s.read_bytes(file_size)?;

        // Check for BSD name.
        let mut name = "";
        if identifier.starts_with("#1/") {
            let raw_name_len: usize = identifier[3..]
                .trim()
                .parse()
                .map_err(|_| ParseError::MalformedInput)?;
            let raw_name = contents
                .get(..raw_name_len)
                .ok_or(ParseError::MalformedInput)?;
            name = str::from_utf8(raw_name).map_err(|_| ParseError::MalformedInput)?;
            name = name.trim_end_matches('\0');
            contents = &contents[raw_name_len..];
        }

        if name.is_empty() && identifier == "/               " {
            return parse_sysv(contents);
        } else if name == "__.SYMDEF" {
            return parse_bsd(contents);
        }
    }

    Ok(Vec::new())
}

fn parse_sysv(data: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut symbols = Vec::new();
    let mut budget = SymbolBudget::new();

    let mut s = Stream::new(data, ByteOrder::BigEndian);
    let count = s.read::<u32>()? as usize;

    // Validate the offset table before looking for symbol names.
    let offsets_len = count.checked_mul(4).ok_or(UnexpectedEof {})?;
    s.read_bytes(offsets_len)?;
    let strings = s.read_bytes(s.remaining())?;
    for name in null_strings(strings).take(count).flatten() {
        let symbol = budget.demangle(name)?.complete;
        budget.push(&mut symbols, symbol)?;
    }

    Ok(symbols)
}

fn parse_bsd(data: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut symbols = Vec::new();
    let mut budget = SymbolBudget::new();

    let mut s = Stream::new(data, ByteOrder::LittleEndian);
    let entries_len = s.read::<u32>()? as usize;
    s.skip_len(entries_len)?;
    let strings_len = s.read::<u32>()? as usize;
    let strings = s.read_bytes(strings_len)?;

    for name in null_strings(strings).flatten() {
        let symbol = budget.demangle(name)?.complete;
        budget.push(&mut symbols, symbol)?;
    }

    Ok(symbols)
}

// Consume each record once, including invalid UTF-8 and unterminated records.
// Retrying at every byte of an invalid record would rescan its suffixes.
fn null_strings(data: &[u8]) -> impl Iterator<Item = Option<&str>> {
    data.split_inclusive(|&byte| byte == 0).map(|record| {
        let name = record.strip_suffix(&[0])?;
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(identifier: &str, contents: &[u8]) -> Vec<u8> {
        let mut data = b"!<arch>\n".to_vec();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            identifier,
            0,
            0,
            0,
            0,
            contents.len()
        );
        assert_eq!(header.len(), 60);
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(contents);
        data
    }

    #[test]
    fn invalid_identifier_utf8_returns_error() {
        let mut data = b"!<arch>\n".to_vec();
        data.extend_from_slice(&[0xff; 16]);
        assert!(matches!(parse(&data), Err(ParseError::MalformedInput)));
    }

    #[test]
    fn malformed_headers_return_errors() {
        for field in [
            &b"\xff         "[..],
            &b"invalid   "[..],
            &b"-1        "[..],
        ] {
            let mut data = archive("file/", b"");
            data[56..66].copy_from_slice(field);
            assert!(matches!(parse(&data), Err(ParseError::MalformedInput)));
        }

        let mut data = archive("file/", b"");
        data[66] = b'!';
        assert!(matches!(parse(&data), Err(ParseError::MalformedInput)));

        for (identifier, contents) in [
            ("#1/invalid", &b""[..]),
            ("#1/9999999999999", &b""[..]),
            ("#1/2", &b"a"[..]),
            ("#1/1", &b"\xff"[..]),
        ] {
            assert!(matches!(
                parse(&archive(identifier, contents)),
                Err(ParseError::MalformedInput)
            ));
        }
    }

    #[test]
    fn truncated_members_return_eof() {
        let data = archive("file/", b"abc");
        for end in 9..data.len() {
            assert!(
                matches!(parse(&data[..end]), Err(ParseError::UnexpectedEof)),
                "truncated at byte {}",
                end
            );
        }
    }

    #[test]
    fn parses_sysv_symbols_after_padded_member() {
        let mut data = archive("file/", b"x");
        data.push(b'\n');
        assert!(parse(&data).unwrap().is_empty());

        let mut index = 2u32.to_be_bytes().to_vec();
        index.extend_from_slice(&[0; 8]);
        index.extend_from_slice(b"foo\0bar\0");
        data.extend_from_slice(&archive("/", &index)[8..]);
        assert_eq!(parse(&data).unwrap(), ["foo", "bar"]);
    }

    #[test]
    fn parses_bsd_symbols() {
        let mut contents = b"__.SYMDEF\0\0\0".to_vec();
        contents.extend_from_slice(&0u32.to_le_bytes());
        contents.extend_from_slice(&8u32.to_le_bytes());
        contents.extend_from_slice(b"foo\0bar\0");
        assert_eq!(parse(&archive("#1/12", &contents)).unwrap(), ["foo", "bar"]);
    }

    #[test]
    fn rejects_invalid_sysv_offset_tables() {
        for count in [1u32, 0x3fff_ffff, 0x4000_0000, u32::MAX] {
            let data = archive("/", &count.to_be_bytes());
            assert!(matches!(parse(&data), Err(ParseError::UnexpectedEof)));
        }
        assert!(parse(&archive("/", &0u32.to_be_bytes()))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn handles_symbols_that_previously_crashed() {
        for (symbol, expected) in [
            ("_ZN1:E", ":"),
            ("_ZN6$ue9$:E", "é:"),
            ("_RNvB_1a", "_RNvB_1a"),
        ] {
            let mut strings = symbol.as_bytes().to_vec();
            strings.push(0);

            let mut sysv = 1u32.to_be_bytes().to_vec();
            sysv.extend_from_slice(&0u32.to_be_bytes());
            sysv.extend_from_slice(&strings);
            assert_eq!(parse(&archive("/", &sysv)).unwrap(), [expected]);

            let mut bsd = b"__.SYMDEF\0\0\0".to_vec();
            bsd.extend_from_slice(&0u32.to_le_bytes());
            bsd.extend_from_slice(&(strings.len() as u32).to_le_bytes());
            bsd.extend_from_slice(&strings);
            assert_eq!(parse(&archive("#1/12", &bsd)).unwrap(), [expected]);
        }
    }

    #[test]
    fn ignores_non_archives_and_empty_archives() {
        assert!(parse(b"not an archive").unwrap().is_empty());
        assert!(parse(b"!<arch>\n").unwrap().is_empty());
    }

    #[test]
    fn skips_invalid_names_as_whole_records() {
        let strings = b"\xffbad\0\0good\0unterminated";
        let mut sysv = 4u32.to_be_bytes().to_vec();
        sysv.extend_from_slice(&[0; 16]);
        sysv.extend_from_slice(strings);
        assert_eq!(parse(&archive("/", &sysv)).unwrap(), ["good"]);

        let mut bsd = b"__.SYMDEF\0\0\0".to_vec();
        bsd.extend_from_slice(&0u32.to_le_bytes());
        bsd.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        bsd.extend_from_slice(strings);
        assert_eq!(parse(&archive("#1/12", &bsd)).unwrap(), ["good"]);
    }

    #[test]
    fn bounds_aggregate_demangled_output() {
        let mut name = format!("_RMC0{}p", "T".repeat(15));
        for offset in (3..18).rev() {
            name.push_str(&format!(
                "B{}_E",
                b"0123456789abcdefghijklmnopqrstuvwxyz"[offset] as char
            ));
        }
        // Each short name expands successfully on its own, but repeating it
        // must not allocate hundreds of megabytes from a sub-100-KiB archive.
        assert!(crate::demangle::SymbolName::demangle(&name).complete.len() > 100_000);
        let mut contents = 1024u32.to_be_bytes().to_vec();
        contents.resize(4 + 4 * 1024, 0);
        for _ in 0..1024 {
            contents.extend_from_slice(name.as_bytes());
            contents.push(0);
        }
        assert!(matches!(
            parse(&archive("/", &contents)),
            Err(ParseError::ResourceLimitExceeded)
        ));
    }
}
