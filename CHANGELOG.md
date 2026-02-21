# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-21

### Added

- Browser-based file manager with upload (files/folders), download (`.tar` for folders), move, copy, rename, delete, and recursive `chmod 777`.
- Upload resume mode (destination size check), queue risk warnings for very large selections, and progress/ETA feedback.
- Payload-side upload lock to prevent concurrent uploads from multiple tabs/devices.
- `Games` tab scanner for title-id style folders (`CUSA*`, `PPSA*`) and `param.sfo`-based detection.
- Optional secure mode using HTTP Basic Auth, plus config download/upload/reset from the UI.
- Debug service endpoints on `8905` (`/health`, `/logs`) with automatic disable if the port is busy.
- PS5 and PS4 payload outputs (`payload/ps5drive.elf`, `payload/ps4drive.elf`) with documented loader defaults.
- Test suite structure for common/unit, mock integration (PS5/PS4), and real PS5 integration.
- CI workflow for unit and mock integration tests on pushes and pull requests.
- Tag-driven release workflow that publishes GitHub releases and uses `CHANGELOG.md` as release notes.
- Root documentation set: `README.md`, `FAQ.md`, `docs/BUILD_AND_TEST.md`, `SUPPORT.md`, `CREDITS.md`, and `LICENSE`.
- Discord link in the UI header for community support.

### Changed

- Moved user-facing docs (`README.md`, `FAQ.md`) to repository root.
- `make test` and CI defaults now run unit + mock integration tests only.
- Build and testing details were moved out of README into `docs/BUILD_AND_TEST.md`.
