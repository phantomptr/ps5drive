# PS5Drive FAQ

<p>
  <img src="payload/assets/ps5drive_logo_light.svg" alt="PS5Drive logo" height="52">
</p>

## What is PS5Drive?

PS5Drive turns your console into a browser-powered transfer dock, so apps, homebrew, and files move in fast and stay easy to manage.

If you want a more comprehensive upload-focused tool, use **PS5Upload**:
`https://github.com/phantomptr/ps5upload`

`ps5drive.elf` is a PS5 payload with:

- Web UI on `8903`
- File API on `8904`
- Debug service on `8905` (`/health`, `/logs`)
- Parent watchdog process that restarts the server child when needed

## How do I build it?

See [docs/BUILD_AND_TEST.md](docs/BUILD_AND_TEST.md) for PS5/PS4 build steps and test targets.

## How do I send the payload?

Use your loader IP/port:

```bash
nc -N -w 1 192.168.137.2 9021 < payload/ps5drive.elf
```

If your `nc` flavor does not support `-N`, keep `-w 1` to avoid hanging too long.

## Why does `nc` look stuck?

Some `nc` variants wait for remote close even after stdin ends. Use:

- `-N` to close on EOF (OpenBSD netcat), and/or
- `-w 1` for short timeout.

## How do I stop an existing payload instance?

Options:

- UI button: `Stop PS5Drive`
- API: `POST /api/stop`

## Where is the config file and when is it created?

On startup, payload ensures the state directory exists and creates:

- `<PS5DRIVE_STATE_DIR>/config.ini`
- default path: `/data/ps5drive/config.ini`

## How do I enable protected mode?

Edit `config.ini`:

```ini
[security]
mode=secure
username=your_user
password=your_pass
```

Then reload payload. UI/API will require HTTP Basic Auth.

To disable protection, set:

```ini
mode=unsecure
username=
password=
```

(`insecure` is standard English; payload currently uses `unsecure` in generated defaults and also accepts `insecure` on upload.)

## Where do uploads go from the UI?

Uploads always target the current directory shown in the UI:

- `Current Path`
- `Upload target: ...` (shown in Upload section)

## Can I change UI language?

Yes. Use the language selector in the top-right of the UI.

Current built-in options:

- English
- Español
- Français
- Deutsch
- 日本語
- 中文

## How do I download or reset config from the UI?

Use header buttons:

- `Download Config`: downloads current `config.ini`
- `Upload Config`: uploads a local `config.ini` and applies mode immediately
- `Reset Config`: resets to default unsecure config

In unsecure mode, `Reset Config` does not require password confirmation.
In secure mode, `Reset Config` asks for username/password confirmation.

## What does the `Resume` button do?

`Resume` checks each destination file via `/api/stat` during upload:

- if destination exists and size is the same: skip
- if destination exists and size differs: upload (overwrite)
- if destination does not exist: upload

This is size-based resume, not hash-based.

## What does the `Upload` button do?

`Upload` is normal mode:

- prompts before overwriting existing files
- lets you skip per file

## What is the `Games` tab for?

The `Games` tab scans directories for likely game folders.

It detects folders by:

- title-id-like names (for example `CUSA...`, `PPSA...`)
- presence of `param.sfo` or `sce_sys/param.sfo`

After scan, use `Open` on a row to jump to that path in the file browser.

## How do I run integration tests?

See [docs/BUILD_AND_TEST.md](docs/BUILD_AND_TEST.md).

## How do I run heavy stress tests?

See [docs/BUILD_AND_TEST.md](docs/BUILD_AND_TEST.md).

## What is the debug port used for?

Debug service listens on `8905` and is useful for health and logs:

- `GET /health`
- `GET /logs`

If `8905` is already in use, debug is automatically disabled and web/api still run.

## Where is full API documentation?

See [payload/API.md](payload/API.md), including API and debug endpoints with examples.
