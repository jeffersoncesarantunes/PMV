# Changelog

All notable changes to PMV will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CHANGELOG, CONTRIBUTING, CODE_OF_CONDUCT and issue/PR templates
- Unit test suite for `pmv_parse_int`, `pmv_json_escape`, `pmv_csv_field`,
  `compute_security_score` and `pmv_snapshot_encode/decode`
- GitHub Actions workflows: CI, CodeQL, Gitleaks, fuzzing, evidence gathering

### Changed
- Hardened compiler flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`,
  `-fPIE`, `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`)

## [1.0.0] - 2024-01-01

### Added
- Initial public release
- Kernel process table inspection via `libkvm(3)` / `struct kinfo_proc`
- `pledge(2)` and `unveil(2)` presence detection
- W^X-related indicators per process
- PID filtering (`--pid`) and parent process mapping (PPID)
- Per-process security scoring (-2 to 6)
- W^X memory region scan (`--scan-wx`)
- Self-hardening at runtime (`pledge` + `unveil`)
- Self-audit on startup (W^X integrity check)
- Structured export (JSON, CSV)
- Diff mode (`--diff`) — change detection across runs
- Silent mode (`--quiet`)
- Man page (`man/pmv.1`)
- SECURITY.md disclosure policy
- OpenBSD CI via `vmactions/openbsd-vm` (release 8.0)

[Unreleased]: https://github.com/jeffersoncesarantunes/PMV/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jeffersoncesarantunes/PMV/releases/tag/v1.0.0
