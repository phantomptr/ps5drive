# PS5 Drive Payload

<p>
  <img src="payload/assets/ps5drive_logo_light.svg" alt="PS5Drive logo" height="52">
</p>

Additional docs:

- [FAQ](FAQ.md)
- [API + Debug Docs](payload/API.md)

`ps5drive.elf` is a supervised multi-port server payload:

- Web UI on port `8903`
- API on port `8904`
- Debug on port `8905` (`/health`, `/logs`)
- Parent watchdog process that restarts crashed server child
- Reload-safe PID handling (new load kills previous instance)

## Persistent Config (`config.ini`)

On startup, payload ensures `PS5DRIVE_STATE_DIR` exists (default `/data/ps5drive`) and creates:

- `/data/ps5drive/config.ini` (or `<PS5DRIVE_STATE_DIR>/config.ini`)

Default config:

```ini
[security]
mode=unsecure
username=
password=
```

To enable protection, set:

```ini
mode=secure
username=your_user
password=your_pass
```

When secure mode is active:

- Web UI (`8903`) requires HTTP Basic Auth
- API (`8904`) requires HTTP Basic Auth
- Debug (`8905`) stays available for diagnostics

UI includes:

- mode indicator (`Secure`/`Insecure`)
- `Download Config` button
- `Upload Config` button
- `Reset Config` button (no credentials in unsecure mode; confirm username/password only in secure mode)
- language selector (`English`, `Español`, `Français`, `Deutsch`, `日本語`, `中文`)
- `Files` / `Games` tabs
- games scanner tab (scan by path and jump to game directory)

## Build

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
make
```

PS5 outputs:

- `payload/ps5drive.elf`

Build PS4 payloads:

```bash
export PS4_PAYLOAD_SDK=/path/to/sdk
make ps4
```

Notes:

- PS4 target auto-detects either:
  - toolchain makefile mode (`orbis.mk` / `ps4.mk`), or
  - `libPS4` SDK layout (`<PS4_PAYLOAD_SDK>/libPS4/libPS4.a`).
- To force a specific makefile, set `PS4_TOOLCHAIN_MK=/path/to/orbis.mk`.

PS4 outputs:

- `payload/ps4drive.elf`

Build both PS5 + PS4 in one run:

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
export PS4_PAYLOAD_SDK=/path/to/sdk
make both
```

## Test Suites

```bash
make host
make test-unit
make test-integration-mock
make test
```

Suite layout:

- Unit tests: `tests/unit/`
- Mock integration tests (host binary): `tests/integration/mock/`
- Real integration tests (console required): `tests/integration/real/`

`make test` runs unit + mock integration tests (no real hardware tests).
GitHub Actions also runs only unit + mock integration suites.

## Remote PS5 Integration Tests

This suite sends payloads to your loader with `nc` (or raw socket fallback), then validates `8903`, `8904`, and `8905` against a real console.

```bash
make test-integration-real PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
# alias:
make test-remote PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
```

Optional vars:

- `PS5_IP` (default `192.168.137.2`)
- `PS5_LOADER_PORT` (default `9021`)
- `PS5_WEB_PORT` (default `8903`)
- `PS5_API_PORT` (default `8904`)
- `PS5_DEBUG_PORT` (default `8905`)
- `PS5_PAYLOAD_PATH` (default `payload/ps5drive.elf`)
- `PS5_TEST_ROOT` (default `/data/ps5drive_test`)
- `PS5_AUTH_USER` / `PS5_AUTH_PASS` (optional, for secure-mode API/UI auth during tests)

## Optional Stress Coverage

Both host and remote suites include an opt-in stress test that exercises:

- deep directory trees
- wide directories with many small files
- large binary upload/stat flow

Disabled by default to keep CI fast.

Host stress:

```bash
PS5DRIVE_STRESS=1 make test-integration-mock
```

Remote stress:

```bash
PS5DRIVE_REMOTE_STRESS=1 make test-integration-real PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
```

Tune load shape with env vars (same idea for host and remote):

- `PS5DRIVE_STRESS_BIG_MB` / `PS5DRIVE_REMOTE_STRESS_BIG_MB` (large file size in MiB)
- `PS5DRIVE_STRESS_DEEP_LEVELS` / `PS5DRIVE_REMOTE_STRESS_DEEP_LEVELS` (directory depth)
- `PS5DRIVE_STRESS_WIDE_FILES` / `PS5DRIVE_REMOTE_STRESS_WIDE_FILES` (small-file count; set to very large values like `200000` only for long soak runs)
- `PS5DRIVE_STRESS_SMALL_BYTES` / `PS5DRIVE_REMOTE_STRESS_SMALL_BYTES` (per small-file size)
- `PS5DRIVE_STRESS_LIST_PAGE` / `PS5DRIVE_REMOTE_STRESS_LIST_PAGE` (pagination size during verification)

## API Endpoints (port 8904)

- `GET /api/health`
- `GET /api/config/download`
- `POST /api/config/upload`
- `POST /api/config/reset`
- `GET /api/storage/list`
- `GET /api/list?path=/...`
- `GET /api/games/scan?path=/...&max_depth=...&max_dirs=...`
- `GET /api/games/cover?path=/...`
- `PUT /api/upload?path=/...` (raw body + `Content-Length`)
- `GET /api/download?path=/...`
- `GET /api/download-folder?path=/...` (streams `.tar`)
- `POST /api/mkdir?path=/...`
- `POST /api/move?src=/...&dst=/...`
- `POST /api/copy?src=/...&dst=/...`
- `POST /api/chmod777?path=/...`
- `DELETE /api/delete?path=/...`

## Debug Endpoints (port 8905)

- `GET /health`
- `GET /logs`

If `8905` is already in use, debug listener is auto-disabled and main web/api ports continue running.

For integration tests only (when `PS5DRIVE_ENABLE_TEST_ADMIN=1`):

- `GET /api/admin/pid`
- `POST /api/admin/exit`

## Browser Usage

Open `http://<ps5-ip>:8903` to:

- browse folders
- upload files
- upload folders (`webkitdirectory`)
- download files
- download current folder as `.tar`
- create/delete folders and files
- switch UI language
- scan game presets across detected storage roots (Games tab), filter by storage, and jump to selected path

## Runtime Environment Overrides

- `PS5DRIVE_STATE_DIR` (default `/data/ps5drive`)
- `PS5DRIVE_ROOT_OVERRIDE` (default `/`)
- `PS5DRIVE_WEB_PORT` (default `8903`)
- `PS5DRIVE_API_PORT` (default `8904`)
- `PS5DRIVE_DEBUG_PORT` (default `8905`)
- `PS5DRIVE_MAX_CLIENTS` (default `64`)
- `PS5DRIVE_ENABLE_TEST_ADMIN` (default `0`)

`PS5DRIVE_ROOT_OVERRIDE` must point to an existing directory.
If the server child exits too many times in a row shortly after startup, the parent stops instead of looping forever.
