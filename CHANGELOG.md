# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Fixed
- The `ar` parser is now hardened against malformed input and will no longer panic on certain inputs.
- `ar::parse` now returns `ParseError` instead of `UnexpectedEof` as the error type.
- ar: Bound BSD extended names to their archive member and handle trailing member padding.

## [0.2.2] - 2026-09-17
### Fixed
- Fixed parsing on big-endian hosts.

## [0.2.1] - 2021-07-03
### Fixed
- Make `UnexpectedEof` type public.

## [0.2.0] - 2021-07-03
### Added
- Allow selecting a custom symbols section for ELF.

### Changed
- Improve error processing.

[Unreleased]: https://github.com/Shnatsel/binfarce/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Shnatsel/binfarce/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Shnatsel/binfarce/compare/v0.1.0...v0.2.0
