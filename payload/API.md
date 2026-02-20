# PS5Drive API and Debug Docs

## Base URLs

- Web UI: `http://<ps5-ip>:8903`
- API: `http://<ps5-ip>:8904`
- Debug: `http://<ps5-ip>:8905`

## Authentication

Security mode is controlled by `config.ini` (`<PS5DRIVE_STATE_DIR>/config.ini`):

- `mode=unsecure` (default): no auth on UI/API
- `mode=secure`: UI/API require HTTP Basic Auth using `username`/`password`
- `mode=insecure` is accepted by upload parser as alias for `mode=unsecure`

Debug endpoints on `8905` are not behind Basic Auth.

## Request Conventions

- Paths are passed as query params (for example `?path=/data`).
- URL-encode query values.
- Uploads use raw request body and must include `Content-Length`.
- All JSON endpoints return `{"ok": true, ...}` on success or `{"ok": false, "error": "..."}`
  on failure.

## API Endpoints (port 8904)

### Health

- `GET /api/health`
- Returns process/port/runtime info.
- Includes `security_mode` (`secure` or `unsecure`) and `auth_enabled`.
- Also includes upload lock state fields:
  - `upload_lock_busy`
  - `upload_lock_owner`
  - `upload_lock_path`
  - `upload_lock_started_at`
  - `upload_lock_last_seen_at`

Example:

```bash
curl -sS http://<ps5-ip>:8904/api/health
```

### Download Config

- `GET /api/config/download`
- Downloads current `config.ini`.

Example:

```bash
curl -sS -o config.ini http://<ps5-ip>:8904/api/config/download
```

### Upload Config

- `POST /api/config/upload`
- Body: raw `config.ini` text.
- Validates config and applies mode immediately.
- Max body size: `64 KiB`.

Example:

```bash
curl -sS -X POST \
  --data-binary @config.ini \
  -H "Content-Type: text/plain; charset=utf-8" \
  http://<ps5-ip>:8904/api/config/upload
```

### Reset Config to Defaults

- `POST /api/config/reset`
- Resets `config.ini` to default unsecure template.
- In unsecure mode, no confirmation headers are required.
- In secure mode, request must include confirmation headers:
  - `X-PS5Drive-Reset-User`
  - `X-PS5Drive-Reset-Pass`

Example:

```bash
curl -sS -X POST \
  -H "X-PS5Drive-Reset-User: your_user" \
  -H "X-PS5Drive-Reset-Pass: your_pass" \
  http://<ps5-ip>:8904/api/config/reset
```

### List Directory

- `GET /api/list?path=/...&limit=500&offset=0`
- `limit` max is `2000`.

Example:

```bash
curl -sS "http://<ps5-ip>:8904/api/list?path=/data&limit=100&offset=0"
```

### Storage List

- `GET /api/storage/list`
- Returns detected storage roots used by the Games tab presets.
- Each item includes:
  - `path`
  - `free_gb`
  - `total_gb`
  - `writable`

Example:

```bash
curl -sS "http://<ps5-ip>:8904/api/storage/list"
```

### Games Scan

- `GET /api/games/scan?path=/...&max_depth=5&max_dirs=8000`
- Recursively scans directories for likely game folders.
- Match rules:
  - title-id-like folder names (for example `CUSA...`, `PPSA...`)
  - folders containing `param.sfo` or `sce_sys/param.sfo`
- Limits:
  - `max_depth` max is `16`
  - `max_dirs` max is `50000`

Example:

```bash
curl -sS "http://<ps5-ip>:8904/api/games/scan?path=/data/games&max_depth=6&max_dirs=20000"
```

### Game Cover

- `GET /api/games/cover?path=/...`
- Streams `icon0.*` from the selected game folder (`sce_sys/icon0.*` first, then root-level fallback).

Example:

```bash
curl -sS -o cover.png "http://<ps5-ip>:8904/api/games/cover?path=/data/games/PPSA00000"
```

### Upload File

- `PUT /api/upload?path=/...`
- Body: raw bytes
- Header: `Content-Length: <n>`
- Optional query:
  - `owner=<client-id>` for lock ownership tracking
- If upload lock is held by another owner, returns `423` with lock state JSON.

Example:

```bash
curl -sS -X PUT \
  --data-binary @local.bin \
  -H "Content-Length: $(stat -c%s local.bin)" \
  "http://<ps5-ip>:8904/api/upload?path=/data/local.bin"
```

### Upload Lock State

- `GET /api/upload/state`
- Returns current payload-side upload lock state.

Example:

```bash
curl -sS "http://<ps5-ip>:8904/api/upload/state"
```

### Upload Lock Acquire/Release

- `POST /api/upload/lock?action=acquire&owner=<client-id>&path=/...`
- `POST /api/upload/lock?action=release&owner=<client-id>`
- Notes:
  - Acquire returns `200` with JSON `acquired=true|false`.
  - Release only clears lock when owner matches active lock owner.

Examples:

```bash
curl -sS -X POST \
  "http://<ps5-ip>:8904/api/upload/lock?action=acquire&owner=tab-a&path=/data/games"
```

```bash
curl -sS -X POST \
  "http://<ps5-ip>:8904/api/upload/lock?action=release&owner=tab-a"
```

### Download File

- `GET /api/download?path=/...`

Example:

```bash
curl -sS -o out.bin "http://<ps5-ip>:8904/api/download?path=/data/local.bin"
```

### Download Folder as TAR

- `GET /api/download-folder?path=/...`
- Streams a tar archive.

Example:

```bash
curl -sS -o folder.tar "http://<ps5-ip>:8904/api/download-folder?path=/data/mydir"
```

### Create Directory

- `POST /api/mkdir?path=/...`

Example:

```bash
curl -sS -X POST "http://<ps5-ip>:8904/api/mkdir?path=/data/newdir"
```

### Move (Rename)

- `POST /api/move?src=/...&dst=/...`

If `dst` is an existing directory, source basename is kept.

Example:

```bash
curl -sS -X POST \
  "http://<ps5-ip>:8904/api/move?src=/data/a.txt&dst=/data/archive"
```

### Copy

- `POST /api/copy?src=/...&dst=/...`

If `dst` is an existing directory, source basename is kept.

Example:

```bash
curl -sS -X POST \
  "http://<ps5-ip>:8904/api/copy?src=/data/a.txt&dst=/data/archive"
```

### CHMOD 777 (Recursive for Directories)

- `POST /api/chmod777?path=/...`

Example:

```bash
curl -sS -X POST "http://<ps5-ip>:8904/api/chmod777?path=/data/mydir"
```

### Delete File or Directory

- `DELETE /api/delete?path=/...`
- Directories are removed recursively.

Example:

```bash
curl -sS -X DELETE "http://<ps5-ip>:8904/api/delete?path=/data/old"
```

### Stat

- `GET /api/stat?path=/...`
- Returns metadata, including `exists`, `is_dir`, `size`, `mtime`, `mode`.

Example:

```bash
curl -sS "http://<ps5-ip>:8904/api/stat?path=/data/local.bin"
```

### Stop Payload

- `POST /api/stop`
- Requests payload shutdown.

Example:

```bash
curl -sS -X POST "http://<ps5-ip>:8904/api/stop"
```

## Debug Endpoints (port 8905)

### Root Help

- `GET /`
- Returns a short plain-text endpoint list.

### Debug Health

- `GET /health`
- Returns debug service status and log metadata.

Example:

```bash
curl -sS http://<ps5-ip>:8905/health
```

### Debug Logs

- `GET /logs`
- Returns recent log lines (plain text).

Example:

```bash
curl -sS http://<ps5-ip>:8905/logs
```

### Debug Port Behavior

- Debug listener is optional.
- If port `8905` is already occupied, debug is disabled automatically.
- Web/API ports still start and continue working.

## Test-Only Admin Endpoints

Only available when `PS5DRIVE_ENABLE_TEST_ADMIN=1`:

- `GET /api/admin/pid`
- `POST /api/admin/exit`

These are intended for integration test control, not production use.

## Common Error Cases

- Invalid/missing path params: `400`
- Not found: `404`
- Method not allowed (debug non-GET): `405`
- Missing upload length: `411`
- Destination exists (for move/copy): `409`
- Upload lock busy: `423`

## Related Docs

- [README.md](README.md)
- [FAQ.md](FAQ.md)
