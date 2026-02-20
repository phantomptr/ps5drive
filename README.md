# PS5Drive (PS5 Upload)

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="payload/assets/ps5drive_logo_dark.svg">
    <img src="payload/assets/ps5drive_logo_light.svg" alt="PS5Drive logo" height="52">
  </picture>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="payload/assets/ps4drive_logo_dark.svg">
    <img src="payload/assets/ps4drive_logo_light.svg" alt="PS4Drive logo" height="52">
  </picture>
</p>

PS5Drive turns your console into a browser-powered transfer dock, so apps, homebrew, and files move in fast and stay easy to manage.

Quick links:

- [FAQ](FAQ.md)
- [API + Debug Docs](payload/API.md)
- [Build + Test Docs](docs/BUILD_AND_TEST.md)
- [Support](SUPPORT.md)
- [Credits](CREDITS.md)
- [License](LICENSE)
- [Changelog](CHANGELOG.md)

For a more comprehensive upload-focused tool, use **PS5Upload**:
`https://github.com/phantomptr/ps5upload`

## What It Can Do

- Browse console storage from a web UI.
- Upload files and full folders from your browser.
- Download single files or full folders (`.tar` stream).
- Move, copy, rename, delete, and `chmod 777 -R` from the UI.
- Resume uploads with destination-size checks.
- Scan for game folders and jump directly to them.
- Run with optional secure mode (HTTP Basic Auth on web/API).
- Expose debug health/log endpoints for diagnostics.

## Send the Payload

Use your loader IP/port. The port depends on your loader/exploit host.

PS5 payload:

```bash
nc -N -w 1 <console-ip> 9021 < payload/ps5drive.elf
```

PS4 payload:

```bash
nc -N -w 1 <console-ip> 9090 < payload/ps4drive.elf
```

Notes:

- PS5 loaders are commonly `9021`.
- PS4 hosts are often `9090` (some setups use other ports).

If your `nc` variant does not support `-N`, keep `-w 1` to avoid hanging.

## Open and Use

After sending payload:

- Web UI: `http://<console-ip>:8903`
- API: `http://<console-ip>:8904`
- Debug: `http://<console-ip>:8905`

Typical workflow:

1. Open `8903` in a browser.
2. Navigate to the destination path.
3. Upload files or folders.
4. Use `Resume` for interrupted transfers.
5. Manage items with rename/move/copy/delete/chmod actions.
6. Use the `Games` tab to scan known game paths and jump into results.

## Security and Config

Config file location:

- `<PS5DRIVE_STATE_DIR>/config.ini` (default `/data/ps5drive/config.ini`)

Default:

```ini
[security]
mode=unsecure
username=
password=
```

Secure mode:

```ini
mode=secure
username=your_user
password=your_pass
```

You can also manage config directly in the UI with:

- `Download Config`
- `Upload Config`
- `Reset Config`

## Stop and Reload Behavior

- Stop from UI: `Stop PS5Drive`
- Stop from API: `POST /api/stop`
- Loading the payload again is reload-safe and replaces previous instances.

## License

GNU General Public License v3.0 (GPLv3).
Free to use, free to modify.

## Credits

Created by **PhantomPtr**.
- [Follow me on X (@phantomptr)](https://x.com/phantomptr)

## Support

If you find this tool useful, consider buying me a coffee.

- Ko-fi: `https://ko-fi.com/B0B81S0WUA`
- Discord server: `https://discord.gg/fzK3xddtrM`
