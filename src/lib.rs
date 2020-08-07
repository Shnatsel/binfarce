#![forbid(unsafe_code)]

// TODO: clean up all possible truncations and enable this
//#![warn(clippy::cast_possible_truncation)]

// For legacy code. TODO: stop suppressing these lints
#![allow(clippy::single_match)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::many_single_char_names)]

// I find this more readable
#![allow(clippy::skip_while_next)]

pub mod ar;
pub mod demangle;
pub mod elf32;
pub mod elf64;
pub mod macho;
pub mod pe;
mod parser;
mod error;

pub use crate::error::ParseError;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}