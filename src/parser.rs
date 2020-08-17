use std::{str, mem, convert::TryInto};
use crate::ByteOrder;
use std::io::{Error, ErrorKind::UnexpectedEof};

pub trait RawNumber: Sized {
    fn parse(s: &mut Stream) -> Self;
}

impl RawNumber for u8 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        s.data[s.offset]
    }
}

impl RawNumber for i8 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        s.data[s.offset] as i8
    }
}

impl RawNumber for u16 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        let start = s.offset;
        let end = s.offset + mem::size_of::<Self>();
        let num = u16::from_ne_bytes(s.data[start..end].try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => num,
            ByteOrder::BigEndian => num.to_be(),
        }
    }
}

impl RawNumber for i16 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        s.read::<u16>() as i16
    }
}

impl RawNumber for u32 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        let start = s.offset;
        let end = s.offset + mem::size_of::<Self>();
        let num = u32::from_ne_bytes(s.data[start..end].try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => num,
            ByteOrder::BigEndian => num.to_be(),
        }
    }
}

impl RawNumber for u64 {
    #[inline]
    fn parse(s: &mut Stream) -> Self {
        let start = s.offset;
        let end = s.offset + mem::size_of::<Self>();
        let num = u64::from_ne_bytes(s.data[start..end].try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => num,
            ByteOrder::BigEndian => num.to_be(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Stream<'a> {
    data: &'a [u8],
    offset: usize,
    byte_order: ByteOrder,
}

impl<'a> Stream<'a> {
    #[inline]
    pub fn new(data: &'a [u8], byte_order: ByteOrder) -> Self {
        Stream {
            data,
            offset: 0,
            byte_order,
        }
    }

    #[inline]
    pub fn new_at(data: &'a [u8], offset: usize, byte_order: ByteOrder) -> Self {
        // TODO: harden
        Stream {
            data,
            offset,
            byte_order,
        }
    }

    #[inline]
    pub fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }

    #[inline]
    pub fn at_end(&self) -> bool {
        self.offset >= self.data.len()
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub fn skip<T: RawNumber>(&mut self) -> Result<(), Error> {
        self.skip_len(mem::size_of::<T>())
    }

    #[inline]
    pub fn skip_len(&mut self, len: usize) -> Result<(), Error> {
        let new_offset = self.offset.checked_add(len);
        match new_offset {
            Some(valid_offset) => {self.offset = valid_offset; Ok(())}
            None => {Err(Error::new(UnexpectedEof, "Unexpected end of file"))}
        }
    }

    #[inline]
    pub fn read<T: RawNumber>(&mut self) -> T {
        let start = self.offset;
        let v = T::parse(self);
        self.offset = start + mem::size_of::<T>();
        v
    }

    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> &'a [u8] {
        let offset = self.offset;
        self.offset += len;
        &self.data[offset..(offset + len)]
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().checked_sub(self.offset).unwrap()
    }
}

pub fn parse_null_string(data: &[u8], start: usize) -> Option<&str> {
    match data.get(start..)?.iter().position(|c| *c == b'\0') {
        Some(i) if i != 0 => str::from_utf8(&data[start..start.checked_add(i)?]).ok(),
        _ => None,
    }
}
