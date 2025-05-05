# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/bbaldino/rtp-parse/compare/v0.1.0...v0.2.0) - 2025-05-02

### Added

- rtcp sr support
- most of tcc packet done (write logic not all there yet)
- add support for rtcp rr
- rtp packet impl
- fixing up rtp header and extensions reading/writing

### Fixed

- optimize some vec usage in tcc packet parsing
- fix padding consumption for tcc packets

### Other

- remove local link to bits-io
- update deps
- clean up deps
- adapt to parsely changes
- implement rtp header extension parsing
- update parsely version and adapt to api changes
- use parsely for parsing ([#3](https://github.com/bbaldino/rtp-parse/pull/3))
- release ([#1](https://github.com/bbaldino/rtp-parse/pull/1))

## [0.1.0](https://github.com/bbaldino/rtp-parse/releases/tag/v0.1.0) - 2024-09-06

### Other
- update crate name/cargo.toml
- add actions workflows
- update deps, use ZERO/ONE constants in new nsw_types version
- tcc fb unit test
- add getter for ssrc in rtp packet
- update reference to bit-cursor in readme
- update to new bitcursor/nsw_types lib
- remove notes
- get rid of old rtp packet/header extensions impl in favor of the new one
- more work on new rtppacket model
- new modeling for rtp packets
- code tweaks/add pli impl
- use different rtp packet parsing scheme
- demux logic, work on rtp.  playing with different rtp packet approaches
- add readme
- adapt to bitcursor changes
- add tcc packet
- various tweaks/fixes from integration
- more packet types
- add more packet types
- add support for writing rtcp bye + add unit tests
- some basic rtcp
- initial commit
