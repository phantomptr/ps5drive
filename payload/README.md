# PS5 Drive Payload

`ps5drive.elf` is a supervised multi-port server payload:

- Web UI on port `8903`
- API on port `8904`
- Debug on port `8905` (`/health`, `/logs`)
- Parent watchdog process that restarts crashed server child
- Reload-safe PID handling (new load kills previous instance)

## Build (PS5 ELF)

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
make
```

Outputs:

- `payload/ps5drive.elf`
- `payload/ps5drivekiller.elf`

## Host Integration Build

```bash
make host
make test
```

This builds `build/ps5drive_host` and runs integration tests from `tests/test_integration.py`.
Tests use Python `requests` as the HTTP test client framework.

## Remote PS5 Integration Tests

This suite sends payloads to your loader with `nc` (or raw socket fallback), then validates `8903`, `8904`, and `8905` against a real console.

```bash
make test-remote PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
```

Optional vars:

- `PS5_IP` (default `192.168.137.2`)
- `PS5_LOADER_PORT` (default `9021`)
- `PS5_WEB_PORT` (default `8903`)
- `PS5_API_PORT` (default `8904`)
- `PS5_DEBUG_PORT` (default `8905`)
- `PS5_PAYLOAD_PATH` (default `payload/ps5drive.elf`)
- `PS5_KILLER_PATH` (default `payload/ps5drivekiller.elf`)
- `PS5_TEST_ROOT` (default `/data/ps5drive_test`)

## API Endpoints (port 8904)

- `GET /api/health`
- `GET /api/list?path=/...`
- `PUT /api/upload?path=/...` (raw body + `Content-Length`)
- `GET /api/download?path=/...`
- `GET /api/download-folder?path=/...` (streams `.tar`)
- `POST /api/mkdir?path=/...`
- `POST /api/move?src=/...&dst=/...`
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

## Runtime Environment Overrides

- `PS5DRIVE_STATE_DIR` (default `/data/ps5drive`)
- `PS5DRIVE_ROOT_OVERRIDE` (default `/`)
- `PS5DRIVE_WEB_PORT` (default `8903`)
- `PS5DRIVE_API_PORT` (default `8904`)
- `PS5DRIVE_DEBUG_PORT` (default `8905`)
- `PS5DRIVE_MAX_CLIENTS` (default `64`)
- `PS5DRIVE_ENABLE_TEST_ADMIN` (default `0`)

Startup does not create directories. `PS5DRIVE_ROOT_OVERRIDE` must point to an existing directory.
If the server child exits too many times in a row shortly after startup, the parent stops instead of looping forever.
