use std::{fmt::{Debug, Display}, error::Error};

pub struct ParseError {}

impl Error for ParseError {}

impl Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Malformed input")
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Malformed input")
    }
}

impl From<std::num::TryFromIntError> for ParseError {
    fn from(_: std::num::TryFromIntError) -> Self {
        ParseError {}
    }
}

impl From<crate::parser::UnexpectedEof> for ParseError {
    fn from(_: crate::parser::UnexpectedEof) -> Self {
        ParseError {}
    }
}