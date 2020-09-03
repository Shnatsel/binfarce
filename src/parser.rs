use std::{str, mem, convert::TryInto};
use crate::ByteOrder;

#[derive(Debug, Copy, Clone)]
pub struct UnexpectedEof {}

impl std::fmt::Display for UnexpectedEof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unexpected end of file")
    }
}

impl std::error::Error for UnexpectedEof {}

pub trait RawNumber: Sized {
    fn parse(s: &mut Stream) -> Option<Self>;
}

impl RawNumber for u8 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        s.data.get(s.offset).copied()
    }
}

impl RawNumber for i8 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        s.data.get(s.offset).map(|x| *x as i8)
    }
}

impl RawNumber for u16 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        let start = s.offset;
        let end = s.offset.checked_add(mem::size_of::<Self>())?;
        let num = u16::from_ne_bytes(s.data.get(start..end)?.try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => Some(num),
            ByteOrder::BigEndian => Some(num.to_be()),
        }
    }
}

impl RawNumber for i16 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        u16::parse(s).map(|x| x as i16)
    }
}

impl RawNumber for u32 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        let start = s.offset;
        let end = s.offset.checked_add(mem::size_of::<Self>())?;
        let num = u32::from_ne_bytes(s.data.get(start..end)?.try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => Some(num),
            ByteOrder::BigEndian => Some(num.to_be()),
        }
    }
}

impl RawNumber for u64 {
    #[inline]
    fn parse(s: &mut Stream) -> Option<Self> {
        let start = s.offset;
        let end = s.offset.checked_add(mem::size_of::<Self>())?;
        let num = u64::from_ne_bytes(s.data.get(start..end)?.try_into().unwrap());
        match s.byte_order {
            ByteOrder::LittleEndian => Some(num),
            ByteOrder::BigEndian => Some(num.to_be()),
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
    pub fn new_at(data: &'a [u8], offset: usize, byte_order: ByteOrder) -> Result<Self, UnexpectedEof> {
        if offset < data.len() {
            Ok(Stream {
                data,
                offset,
                byte_order,
            })
        } else {
            Err(UnexpectedEof{})
        }
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
    pub fn skip<T: RawNumber>(&mut self) -> Result<(), UnexpectedEof> {
        self.skip_len(mem::size_of::<T>())
    }

    #[inline]
    pub fn skip_len(&mut self, len: usize) -> Result<(), UnexpectedEof> {
        let new_offset = self.offset.checked_add(len);
        match new_offset {
            Some(valid_offset) => {self.offset = valid_offset; Ok(())}
            None => {Err(UnexpectedEof{})}
        }
    }

    #[inline]
    pub fn read<T: RawNumber>(&mut self) -> T {
        let v = T::parse(self);
        self.offset += mem::size_of::<T>();
        v.unwrap() // TODO: harden
        // I'm leaving this as-is FOR NOW because I'm not done refactoring decoders yet,
        // and putting unwrap() on every single invocation only to change it later
        // is entirely useless. I'll revisit this once I've converted all 3 decoders
        // to return errors instead of panicking.
    }

    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> &'a [u8] {
        let offset = self.offset;
        self.offset += len; //TODO: harden
        &self.data[offset..(offset + len)]
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }
}

pub fn parse_null_string(data: &[u8], start: usize) -> Option<&str> {
    match data.get(start..)?.iter().position(|c| *c == b'\0') {
        Some(i) if i != 0 => str::from_utf8(&data[start..start.checked_add(i)?]).ok(),
        _ => None,
    }
}
