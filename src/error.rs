use std::{fmt::{Debug, Display}, error::Error};

#[derive(Debug, Copy, Clone)]
pub enum ParseError {
    MalformedInput,
    UnexpectedEof,
}

impl Error for ParseError {}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::MalformedInput => write!(f, "Malformed input file"),
            ParseError::UnexpectedEof => write!(f, "Unexpected end of file"),
        }
    }
}

impl From<std::num::TryFromIntError> for ParseError {
    fn from(_: std::num::TryFromIntError) -> Self {
        ParseError::MalformedInput
    }
}

impl From<crate::parser::UnexpectedEof> for ParseError {
    fn from(_: crate::parser::UnexpectedEof) -> Self {
        ParseError::UnexpectedEof
    }
}