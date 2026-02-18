# PS5 Drive Payload

Minimal PS5 payload with:

- notification on load (`Hello world`)
- single-instance behavior on reload (new instance terminates old instance)
- version injected from repo root `VERSION`

## Build

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
make
```

Output: `payload/ps5drive.elf`
Also builds: `payload/ps5drivekiller.elf`

## Behavior

- On startup, reads `/data/ps5drive/payload.pid`.
- If an older process is still running, it sends `SIGTERM`, then `SIGKILL` fallback.
- Writes current PID to `/data/ps5drive/payload.pid`.
- Displays notification:
  `PS5 Drive Payload: Hello world (v<version>)`

## Killer payload

Send `ps5drivekiller.elf` to stop a stuck/running instance manually.

- Reads PID from `/data/ps5drive/payload.pid`
- Sends `SIGTERM` then `SIGKILL` fallback
- Shows success/failure notification
