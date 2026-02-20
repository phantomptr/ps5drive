# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI workflow to run host integration tests on pushes and pull requests.
- Root-level project docs (`README.md`, `FAQ.md`) and this changelog file.
- Test suite split: `tests/unit`, `tests/integration/mock`, and `tests/integration/real`.
- New Make targets: `test-unit`, `test-integration-mock`, and `test-integration-real`.
- Root docs for developer and project metadata: `docs/BUILD_AND_TEST.md`, `SUPPORT.md`, `CREDITS.md`, and `LICENSE`.
- Discord button in the web UI header linking the community invite.

### Changed

- Moved README/FAQ from `payload/` to repository root.
- `make test` now runs only unit + mock integration suites by default.
- CI now runs only unit + mock integration tests (no real PS5 integration).
- README refocused on sending/using payload features; build/test-heavy content moved to dedicated docs.
