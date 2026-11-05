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

