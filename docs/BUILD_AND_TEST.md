# Build and Test

This document keeps developer-oriented build/test details out of the main README.

## Build Outputs

- PS5: `payload/ps5drive.elf`
- PS4: `payload/ps4drive.elf`

## Build PS5

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
make ps5
```

`make` defaults to `ps5`.

## Build PS4

```bash
export PS4_PAYLOAD_SDK=/path/to/sdk
make ps4
```

PS4 build auto-detects:

- toolchain makefile mode (`orbis.mk` / `ps4.mk`), or
- `libPS4` layout (`<PS4_PAYLOAD_SDK>/libPS4/libPS4.a`)

Force a specific PS4 makefile:

```bash
export PS4_TOOLCHAIN_MK=/path/to/orbis.mk
make ps4
```

## Build Both

```bash
export PS5_PAYLOAD_SDK=/path/to/sdk
export PS4_PAYLOAD_SDK=/path/to/sdk
make both
```

## Test Targets

- `make test-common`: common/unit tests (`tests/common/unit/`)
- `make test-unit`: alias of `make test-common`
- `make test-ps5-mock`: PS5 mock integration tests (`tests/ps5/integration/mock/`)
- `make test-ps4-mock`: PS4 mock integration tests (`tests/ps4/integration/mock/`)
- `make test-integration-mock`: PS5 + PS4 mock integration groups
- `make test`: common + mock integration (default CI path)
- `make test-ps5-real`: PS5 real console integration (`tests/ps5/integration/real/`)
- `make test-integration-real`: alias of `make test-ps5-real`
- `make test-remote`: alias of `make test-integration-real`

CI (`.github/workflows/ci.yml`) runs only unit + mock integration tests.

## Remote Real Integration Example

```bash
make test-integration-real PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
```

Optional vars:

- `PS5_IP` (default `192.168.137.2`)
- `PS5_LOADER_PORT` (default `9021`)
- `PS5_WEB_PORT` (default `8903`)
- `PS5_API_PORT` (default `8904`)
- `PS5_DEBUG_PORT` (default `8905`)
- `PS5_PAYLOAD_PATH` (default `payload/ps5drive.elf`)
- `PS5_TEST_ROOT` (default `/data/ps5drive_test`)
- `PS5_AUTH_USER` / `PS5_AUTH_PASS` (optional)

## Stress Modes

Mock stress:

```bash
PS5DRIVE_STRESS=1 make test-integration-mock
```

Real stress:

```bash
PS5DRIVE_REMOTE_STRESS=1 make test-integration-real PS5_IP=192.168.137.2 PS5_LOADER_PORT=9021
```

Stress tuning vars:

- `PS5DRIVE_STRESS_BIG_MB` / `PS5DRIVE_REMOTE_STRESS_BIG_MB`
- `PS5DRIVE_STRESS_DEEP_LEVELS` / `PS5DRIVE_REMOTE_STRESS_DEEP_LEVELS`
- `PS5DRIVE_STRESS_WIDE_FILES` / `PS5DRIVE_REMOTE_STRESS_WIDE_FILES`
- `PS5DRIVE_STRESS_SMALL_BYTES` / `PS5DRIVE_REMOTE_STRESS_SMALL_BYTES`
- `PS5DRIVE_STRESS_LIST_PAGE` / `PS5DRIVE_REMOTE_STRESS_LIST_PAGE`
