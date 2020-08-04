#![forbid(unsafe_code)]

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

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}