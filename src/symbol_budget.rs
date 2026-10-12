use crate::demangle::SymbolName;
use crate::ParseError;
use std::mem::size_of;

// Shared by every symbol extraction API. A per-name demangling limit alone
// cannot bound repeated expansion or repeated references to a long name.
const MAX_SYMBOL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct SymbolBudget {
    remaining: usize,
}

impl SymbolBudget {
    pub(crate) fn new() -> Self {
        Self {
            remaining: MAX_SYMBOL_BYTES,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limit(remaining: usize) -> Self {
        Self { remaining }
    }

    pub(crate) fn demangle(&mut self, name: &str) -> Result<SymbolName, ParseError> {
        // Legacy demangling can expand separators, and the fallback copies the
        // input. Reject enormous names before making those infallible copies.
        if name.len() > self.remaining / 4 {
            return Err(ParseError::ResourceLimitExceeded);
        }
        let symbol = SymbolName::demangle(name);
        let bytes = [
            symbol.complete.capacity(),
            symbol.trimmed.capacity(),
            symbol.crate_name.as_ref().map_or(0, String::capacity),
        ];
        for size in bytes {
            self.remaining = self
                .remaining
                .checked_sub(size)
                .ok_or(ParseError::ResourceLimitExceeded)?;
        }
        Ok(symbol)
    }

    // Account for allocated capacity, including unused slots, before growing
    // either an output vector or a temporary symbol table. Grow geometrically
    // to avoid quadratic reallocations, but stay within the shared budget.
    pub(crate) fn push<T>(&mut self, values: &mut Vec<T>, value: T) -> Result<(), ParseError> {
        if values.len() == values.capacity() && size_of::<T>() != 0 {
            let available = self.remaining / size_of::<T>();
            let additional = values.capacity().max(4).min(available);
            if additional == 0 {
                return Err(ParseError::ResourceLimitExceeded);
            }
            let old_capacity = values.capacity();
            values
                .try_reserve_exact(additional)
                .map_err(|_| ParseError::ResourceLimitExceeded)?;
            let bytes = values
                .capacity()
                .checked_sub(old_capacity)
                .and_then(|n| n.checked_mul(size_of::<T>()))
                .ok_or(ParseError::ResourceLimitExceeded)?;
            self.remaining = self
                .remaining
                .checked_sub(bytes)
                .ok_or(ParseError::ResourceLimitExceeded)?;
        }
        values.push(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_vector_capacity_across_temporary_and_output_tables() {
        let mut budget = SymbolBudget { remaining: 64 };
        let mut temporary = Vec::new();
        let mut output = Vec::new();
        budget.push(&mut temporary, 1u64).unwrap();
        budget.push(&mut output, 2u64).unwrap();
        assert_eq!(budget.remaining, 0);
        for _ in 1..4 {
            budget.push(&mut temporary, 1u64).unwrap();
            budget.push(&mut output, 2u64).unwrap();
        }
        assert!(matches!(
            budget.push(&mut temporary, 1u64),
            Err(ParseError::ResourceLimitExceeded)
        ));
        assert!(matches!(
            budget.push(&mut output, 2u64),
            Err(ParseError::ResourceLimitExceeded)
        ));
        assert_eq!(temporary.capacity() + output.capacity(), 8);
    }
}
