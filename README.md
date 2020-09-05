## binfarce

Extremely minimal parser for ELF/PE/Mach-o/ar.

This crate is used mostly for sharing code between `cargo-bloat` and `auditable-extract` crates. It implements just enough features for those tools to work. If you're looking for a fully-featured parser, see [`goblin`](https://crates.io/crates/goblin).

Section extraction is used by both tools. It is is zero-allocation and hardened against untrusted inputs. `#[forbid(unsafe_code)]` ensures absence of code execution vulnerabilities. Pedantic clippy lints and fuzzing are used to ensure absence of panics. Absence of heap allocations ensures you can't exhaust RAM.

Symbol extraction is used by `cargo-bloat` only. It allocates unbounded amounts of memory on the heap and may panic given an untrusted input.

**Goals:**

 - 100% safe code all the way down. This includes all dependencies.
 - Simple code that's easy to audit. No fancy tricks such as proc macros.

**Non-goals:**
 
 - Highest possible performance. Parsing these things is stupidly cheap anyway.
 - Full format support.

 PRs with functionality required for your own tool are welcome as long as they adhere to the above goals and keep existing tools working.

_This project was briefly known as "kuduk"._
