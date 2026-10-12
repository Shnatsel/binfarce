use std::str;

use crate::demangle::SymbolName;
use crate::parser::*;
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
            return Ok(parse_sysv(contents)?);
        } else if name == "__.SYMDEF" {
            return Ok(parse_bsd(contents)?);
        }
    }

    Ok(Vec::new())
}

fn parse_sysv(data: &[u8]) -> Result<Vec<String>, UnexpectedEof> {
    let mut symbols = Vec::new();

    let count = {
        let mut s = Stream::new(data, ByteOrder::BigEndian);
        s.read::<u32>()? as usize
    };

    // Skip offsets.
    let mut i = 4 + 4 * count; // u32 + u32 * size

    for _ in 0..count {
        if let Some(s) = parse_null_string(data, i) {
            symbols.push(SymbolName::demangle(s).complete);

            i += s.len() + 1;
        } else {
            i += 1;
        }

        if i >= data.len() {
            break;
        }
    }

    Ok(symbols)
}

fn parse_bsd(data: &[u8]) -> Result<Vec<String>, UnexpectedEof> {
    let mut symbols = Vec::new();

    let mut s = Stream::new(data, ByteOrder::LittleEndian);
    let entries_len = s.read::<u32>()? as usize;
    s.skip_len(entries_len)?;
    let strings_len = s.read::<u32>()? as usize;
    let strings = s.read_bytes(strings_len)?;

    let mut i = 0;
    while i < strings.len() {
        if let Some(s) = parse_null_string(strings, i) {
            symbols.push(SymbolName::demangle(s).complete);

            i += s.len() + 1;
        } else {
            i += 1;
        }
    }

    Ok(symbols)
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
    fn ignores_non_archives_and_empty_archives() {
        assert!(parse(b"not an archive").unwrap().is_empty());
        assert!(parse(b"!<arch>\n").unwrap().is_empty());
    }
}
