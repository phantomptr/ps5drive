import base64
import io
import json
import os
import re
import signal
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

import requests

from tests.common import env_flag, env_int, find_repo_root

REPO_ROOT = find_repo_root(__file__)
HOST_BINARY = REPO_ROOT / "build" / "ps5drive_host"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Ps5DriveIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.TemporaryDirectory(prefix="ps5drive_test-")
        base = Path(cls.tempdir.name)
        cls.root_dir = base / "root"
        cls.state_dir = base / "state"
        cls.root_dir.mkdir(parents=True, exist_ok=True)
        cls.state_dir.mkdir(parents=True, exist_ok=True)

        cls.web_port = _free_port()
        cls.api_port = _free_port()
        cls.debug_port = _free_port()

        env = os.environ.copy()
        env["PS5DRIVE_ROOT_OVERRIDE"] = str(cls.root_dir)
        env["PS5DRIVE_ROOT"] = str(cls.root_dir)
        env["PS5DRIVE_STATE_DIR"] = str(cls.state_dir)
        env["PS5DRIVE_WEB_PORT"] = str(cls.web_port)
        env["PS5DRIVE_API_PORT"] = str(cls.api_port)
        env["PS5DRIVE_DEBUG_PORT"] = str(cls.debug_port)
        env["PS5DRIVE_ENABLE_TEST_ADMIN"] = "1"

        cls.proc = subprocess.Popen(
            [str(HOST_BINARY)],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls._wait_for_health()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "proc") and cls.proc and cls.proc.poll() is None:
            cls.proc.send_signal(signal.SIGTERM)
            try:
                cls.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if hasattr(cls, "tempdir"):
            cls.tempdir.cleanup()

    @classmethod
    def _wait_for_health(cls, timeout: float = 15.0) -> None:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                status, _, body = cls.api_request("GET", "/api/health")
                if status == 200:
                    payload = json.loads(body.decode("utf-8"))
                    if payload.get("ok") is True:
                        return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
            time.sleep(0.2)
        raise RuntimeError(f"server did not become healthy: {last_err}")

    @classmethod
    def api_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        resp = requests.request(
            method=method,
            url=f"http://127.0.0.1:{cls.api_port}{path}",
            data=body,
            headers=headers or {},
            timeout=10,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @classmethod
    def web_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        resp = requests.request(
            method=method,
            url=f"http://127.0.0.1:{cls.web_port}{path}",
            data=body,
            headers=headers or {},
            timeout=10,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @classmethod
    def debug_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        resp = requests.request(
            method=method,
            url=f"http://127.0.0.1:{cls.debug_port}{path}",
            data=body,
            headers=headers or {},
            timeout=10,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @staticmethod
    def _q(path: str) -> str:
        return urllib.parse.quote(path, safe="/")

    @staticmethod
    def _basic_auth(user: str, password: str) -> str:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def test_health(self) -> None:
        status, _, body = self.api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertGreater(int(payload.get("pid", 0)), 0)
        self.assertGreater(int(payload.get("ppid", 0)), 0)
        self.assertEqual(payload["api_port"], self.api_port)
        self.assertEqual(payload["web_port"], self.web_port)
        self.assertEqual(payload["debug_port"], self.debug_port)
        self.assertTrue(payload["debug_enabled"])
        self.assertEqual(payload["security_mode"], "unsecure")
        self.assertFalse(bool(payload["auth_enabled"]))

    def test_web_port_api_health(self) -> None:
        status, _, body = self.web_request("GET", "/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])

    def test_debug_port_health_and_logs(self) -> None:
        status, _, body = self.debug_request("GET", "/health")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["debug_port"], self.debug_port)

        _ = self.web_request("GET", "/")
        status, headers, body = self.debug_request("GET", "/logs")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers.get("Content-Type", ""))
        self.assertGreater(len(body), 0)

    def test_debug_port_rejects_non_get(self) -> None:
        status, _, _ = self.debug_request("POST", "/health")
        self.assertEqual(status, 405)

    def test_web_ui_served(self) -> None:
        status, headers, body = self.web_request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("PS5Drive", text)
        self.assertIn(str(self.api_port), text)
        self.assertIn("id=\"versionText\"", text)
        self.assertIn("Buy Me a Coffee", text)
        self.assertIn("id=\"renameBtn\">Rename", text)
        self.assertIn("id=\"moveBtn\">Move To", text)
        self.assertIn("id=\"copyBtn\">Copy To", text)
        self.assertIn("id=\"chmodBtn\">CHMOD 777 -R", text)
        self.assertIn("Debug Port:", text)
        self.assertIn("id=\"moveInput\"", text)
        self.assertIn("id=\"loadMoreBtn\"", text)
        self.assertIn("id=\"uploadStopBtn\"", text)
        self.assertIn("id=\"resumeUploadBtn\"", text)
        self.assertIn("id=\"overwriteAllBtn\"", text)
        self.assertIn("Overwrite: Ask", text)
        self.assertIn("id=\"queueList\"", text)
        self.assertIn("id=\"uploadStatusMain\"", text)
        self.assertIn("id=\"uploadStatusDetail\"", text)
        self.assertIn("id=\"uploadStatusFile\"", text)
        self.assertIn("id=\"downloadConfigBtn\"", text)
        self.assertIn("id=\"uploadConfigBtn\"", text)
        self.assertIn("id=\"resetConfigBtn\"", text)
        self.assertIn("id=\"modeChip\"", text)
        self.assertIn("id=\"langSelect\"", text)
        self.assertIn("id=\"tabGamesBtn\"", text)
        self.assertIn("id=\"gamesScanBtn\"", text)
        self.assertIn("Upload target:", text)
        self.assertNotIn("Upload Selected", text)
        self.assertIn("Activity Log", text)
        self.assertNotIn("Status: Online", text)

    def test_web_i18n_locale_coverage(self) -> None:
        status, _, body = self.web_request("GET", "/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8", "ignore")

        expected_locales = [
            "en",
            "zh-cn",
            "zh-tw",
            "hi",
            "es",
            "ar",
            "bn",
            "pt-br",
            "ru",
            "ja",
            "de",
            "fr",
            "ko",
            "tr",
            "vi",
            "id",
            "it",
            "th",
        ]
        required_button_keys = {
            "upload",
            "resume",
            "stop",
            "go_to",
            "download",
            "delete",
            "rename",
            "move_to",
            "copy_to",
            "chmod",
            "download_config",
            "upload_config",
            "reset_config",
            "buy_me_coffee",
            "refresh",
            "scan",
        }

        for locale in expected_locales:
            self.assertIn(f'<option value="{locale}">', text)

        match = re.search(
            r"const I18N=\{(.*?)\};\s*const SUPPORTED=\[([^\]]+)\];",
            text,
            re.S,
        )
        self.assertIsNotNone(match)
        i18n_blob = match.group(1)
        supported = re.findall(r"'([^']+)'", match.group(2))
        self.assertEqual(supported, expected_locales)

        def locale_block(locale: str) -> str:
            key = re.escape(locale)
            row = re.search(rf"(?:'{key}'|{key}):\{{(.*?)\}}(?:,|$)", i18n_blob)
            self.assertIsNotNone(row, f"missing locale block for {locale}")
            return row.group(1)

        base_keys = set(re.findall(r"([a-z_]+):'", locale_block("en")))
        self.assertGreater(len(base_keys), 60)
        self.assertTrue(required_button_keys.issubset(base_keys))

        for locale in expected_locales:
            keys = set(re.findall(r"([a-z_]+):'", locale_block(locale)))
            self.assertEqual(keys, base_keys, f"locale key mismatch for {locale}")

    def test_web_logo_assets_served(self) -> None:
        status, headers, body = self.web_request("GET", "/assets/logo-light.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("Content-Type", ""))
        self.assertIn(b"<svg", body)
        self.assertIn(b"PS5Drive", body)

        status, headers, body = self.web_request("GET", "/assets/logo-dark.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("Content-Type", ""))
        self.assertIn(b"<svg", body)
        self.assertIn(b"PS5Drive", body)

    def test_config_ini_created_and_downloadable(self) -> None:
        config_path = Path(self.state_dir) / "config.ini"
        self.assertTrue(config_path.exists())
        content = config_path.read_text(encoding="utf-8")
        self.assertIn("mode=unsecure", content)

        status, headers, body = self.api_request("GET", "/api/config/download")
        self.assertEqual(status, 200)
        self.assertIn("application/octet-stream", headers.get("Content-Type", ""))
        text = body.decode("utf-8", "ignore")
        self.assertIn("mode=unsecure", text)
        self.assertIn("username=", text)
        self.assertIn("password=", text)

    def test_config_upload_invalid_rejected(self) -> None:
        bad = (
            "# PS5Drive persistent config\n"
            "[security]\n"
            "mode=secure\n"
            "username=only\n"
        ).encode("utf-8")
        status, _, body = self.api_request(
            "POST",
            "/api/config/upload",
            body=bad,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload["ok"])

        status, _, body = self.api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertEqual(health["security_mode"], "unsecure")
        self.assertFalse(bool(health["auth_enabled"]))

    def test_config_upload_secure_and_reset_flow(self) -> None:
        auth = {"Authorization": self._basic_auth("alice", "s3cret")}
        confirm_headers = {
            **auth,
            "X-PS5Drive-Reset-User": "alice",
            "X-PS5Drive-Reset-Pass": "s3cret",
        }
        secure_config = (
            "# PS5Drive persistent config\n"
            "[security]\n"
            "mode=secure\n"
            "username=alice\n"
            "password=s3cret\n"
        ).encode("utf-8")

        try:
            status, _, body = self.api_request(
                "POST",
                "/api/config/upload",
                body=secure_config,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["security_mode"], "secure")
            self.assertTrue(bool(payload["auth_enabled"]))

            status, _, _ = self.api_request("GET", "/api/health")
            self.assertEqual(status, 401)

            status, _, body = self.api_request("GET", "/api/health", headers=auth)
            self.assertEqual(status, 200)
            health = json.loads(body.decode("utf-8"))
            self.assertEqual(health["security_mode"], "secure")
            self.assertTrue(bool(health["auth_enabled"]))

            status, _, _ = self.api_request("POST", "/api/config/reset", headers=auth)
            self.assertEqual(status, 401)

            status, _, body = self.api_request("POST", "/api/config/reset", headers=confirm_headers)
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["security_mode"], "unsecure")

            status, _, body = self.api_request("GET", "/api/health")
            self.assertEqual(status, 200)
            health = json.loads(body.decode("utf-8"))
            self.assertEqual(health["security_mode"], "unsecure")
            self.assertFalse(bool(health["auth_enabled"]))
        finally:
            try:
                self.api_request("POST", "/api/config/reset", headers=confirm_headers)
            except Exception:
                pass

    def test_config_reset_defaults(self) -> None:
        config_path = Path(self.state_dir) / "config.ini"
        config_path.write_text(
            "# PS5Drive persistent config\n"
            "[security]\n"
            "mode=secure\n"
            "username=tester\n"
            "password=secret\n",
            encoding="utf-8",
        )

        status, _, body = self.api_request("POST", "/api/config/reset")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["security_mode"], "unsecure")

        content = config_path.read_text(encoding="utf-8")
        self.assertIn("mode=unsecure", content)
        self.assertIn("username=", content)
        self.assertIn("password=", content)

        status, _, body = self.api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertEqual(health["security_mode"], "unsecure")
        self.assertFalse(bool(health["auth_enabled"]))

    def test_secure_mode_requires_auth_and_allows_reset_with_confirmation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ps5drive_secure_test-") as tempdir:
            base = Path(tempdir)
            root_dir = base / "root"
            state_dir = base / "state"
            root_dir.mkdir(parents=True, exist_ok=True)
            state_dir.mkdir(parents=True, exist_ok=True)

            (state_dir / "config.ini").write_text(
                "# PS5Drive persistent config\n"
                "[security]\n"
                "mode=secure\n"
                "username=alice\n"
                "password=s3cret\n",
                encoding="utf-8",
            )

            web_port = _free_port()
            api_port = _free_port()
            debug_port = _free_port()
            env = os.environ.copy()
            env["PS5DRIVE_ROOT_OVERRIDE"] = str(root_dir)
            env["PS5DRIVE_STATE_DIR"] = str(state_dir)
            env["PS5DRIVE_WEB_PORT"] = str(web_port)
            env["PS5DRIVE_API_PORT"] = str(api_port)
            env["PS5DRIVE_DEBUG_PORT"] = str(debug_port)
            env["PS5DRIVE_ENABLE_TEST_ADMIN"] = "1"

            proc = subprocess.Popen(
                [str(HOST_BINARY)],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                good_auth = {"Authorization": self._basic_auth("alice", "s3cret")}
                deadline = time.time() + 15.0
                last_err = None
                while time.time() < deadline:
                    try:
                        resp = requests.get(
                            f"http://127.0.0.1:{api_port}/api/health",
                            headers=good_auth,
                            timeout=2,
                        )
                        if resp.status_code == 200 and resp.json().get("ok") is True:
                            break
                    except Exception as exc:  # noqa: BLE001
                        last_err = exc
                    time.sleep(0.2)
                else:
                    self.fail(f"secure server did not become ready: {last_err}")

                resp = requests.get(f"http://127.0.0.1:{api_port}/api/health", timeout=3)
                self.assertEqual(resp.status_code, 401)
                self.assertIn("WWW-Authenticate", resp.headers)

                resp = requests.get(f"http://127.0.0.1:{web_port}/", timeout=3)
                self.assertEqual(resp.status_code, 401)

                wrong_auth = {"Authorization": self._basic_auth("alice", "wrong")}
                resp = requests.get(f"http://127.0.0.1:{api_port}/api/health", headers=wrong_auth, timeout=3)
                self.assertEqual(resp.status_code, 401)

                resp = requests.get(f"http://127.0.0.1:{api_port}/api/health", headers=good_auth, timeout=3)
                self.assertEqual(resp.status_code, 200)
                health = resp.json()
                self.assertEqual(health["security_mode"], "secure")
                self.assertTrue(bool(health["auth_enabled"]))

                resp = requests.post(f"http://127.0.0.1:{api_port}/api/config/reset", headers=good_auth, timeout=3)
                self.assertEqual(resp.status_code, 401)

                confirm_headers = {
                    **good_auth,
                    "X-PS5Drive-Reset-User": "alice",
                    "X-PS5Drive-Reset-Pass": "s3cret",
                }
                resp = requests.post(
                    f"http://127.0.0.1:{api_port}/api/config/reset",
                    headers=confirm_headers,
                    timeout=3,
                )
                self.assertEqual(resp.status_code, 200)
                payload = resp.json()
                self.assertEqual(payload["security_mode"], "unsecure")

                resp = requests.get(f"http://127.0.0.1:{api_port}/api/health", timeout=3)
                self.assertEqual(resp.status_code, 200)
                health = resp.json()
                self.assertEqual(health["security_mode"], "unsecure")
                self.assertFalse(bool(health["auth_enabled"]))

                config_text = (state_dir / "config.ini").read_text(encoding="utf-8")
                self.assertIn("mode=unsecure", config_text)
                self.assertIn("username=", config_text)
                self.assertIn("password=", config_text)
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    def test_abort_client_does_not_kill_server(self) -> None:
        status, _, body = self.api_request("GET", "/api/admin/pid")
        self.assertEqual(status, 200)
        first_pid = int(json.loads(body.decode("utf-8"))["pid"])

        for _ in range(30):
            sock = socket.create_connection(("127.0.0.1", self.web_port), timeout=3)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            sock.close()

        time.sleep(1.0)
        status, _, body = self.api_request("GET", "/api/admin/pid")
        self.assertEqual(status, 200)
        second_pid = int(json.loads(body.decode("utf-8"))["pid"])
        self.assertEqual(first_pid, second_pid)

    def test_mkdir_and_list(self) -> None:
        target = "/cases/list"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(target)}")
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", "/api/list?path=/cases")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        names = [entry["name"] for entry in payload["entries"]]
        self.assertIn("list", names)

    def test_list_pagination(self) -> None:
        folder = "/cases/paginate"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(folder)}")
        self.assertEqual(status, 200)

        for i in range(23):
            file_path = f"{folder}/f{i:03d}.txt"
            blob = f"file-{i}\n".encode("utf-8")
            status, _, _ = self.api_request(
                "PUT",
                f"/api/upload?path={self._q(file_path)}",
                body=blob,
                headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
            )
            self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", f"/api/list?path={self._q(folder)}&limit=10&offset=0")
        self.assertEqual(status, 200)
        page1 = json.loads(body.decode("utf-8"))
        self.assertEqual(int(page1["limit"]), 10)
        self.assertLessEqual(len(page1["entries"]), 10)
        self.assertTrue(bool(page1["has_more"]))
        next_offset = int(page1["next_offset"])
        self.assertGreaterEqual(next_offset, 10)

        status, _, body = self.api_request("GET", f"/api/list?path={self._q(folder)}&limit=10&offset={next_offset}")
        self.assertEqual(status, 200)
        page2 = json.loads(body.decode("utf-8"))
        self.assertEqual(int(page2["offset"]), next_offset)
        self.assertLessEqual(len(page2["entries"]), 10)

    def test_list_invalid_pagination_rejected(self) -> None:
        status, _, _ = self.api_request("GET", "/api/list?path=/&limit=0")
        self.assertEqual(status, 400)

        status, _, _ = self.api_request("GET", "/api/list?path=/&limit=2001")
        self.assertEqual(status, 400)

        status, _, _ = self.api_request("GET", "/api/list?path=/&offset=-1")
        self.assertEqual(status, 400)

    def test_storage_list_reports_mounts(self) -> None:
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q('/data')}")
        self.assertEqual(status, 200)
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q('/mnt/usb0')}")
        self.assertEqual(status, 200)
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q('/mnt/usb0/.probe')}",
            body=b"x",
            headers={"Content-Length": "1", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", "/api/storage/list")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        rows = payload.get("storage", [])
        self.assertIsInstance(rows, list)

        paths = {row.get("path") for row in rows if isinstance(row, dict)}
        self.assertIn("/", paths)
        self.assertIn("/data", paths)
        self.assertIn("/mnt/usb0", paths)

        data_row = next((row for row in rows if isinstance(row, dict) and row.get("path") == "/data"), {})
        self.assertIn("free_gb", data_row)
        self.assertIn("total_gb", data_row)
        self.assertIn("writable", data_row)

    def test_games_scan_finds_title_id_and_param_sfo(self) -> None:
        base = "/cases/games_scan"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(base)}")
        self.assertEqual(status, 200)

        title_dir = f"{base}/PPSA12345"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(title_dir)}")
        self.assertEqual(status, 200)
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(title_dir + '/eboot.bin')}",
            body=b"x",
            headers={"Content-Length": "1", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        sfo_path = f"{base}/custom_game/sce_sys/param.sfo"
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(sfo_path)}",
            body=b"PARAM",
            headers={"Content-Length": "5", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        cover_path = f"{base}/custom_game/sce_sys/icon0.png"
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(cover_path)}",
            body=b"\x89PNG\r\n\x1a\n",
            headers={"Content-Length": "8", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request(
            "GET",
            f"/api/games/scan?path={self._q(base)}&max_depth=6&max_dirs=2000",
        )
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], base)
        self.assertFalse(bool(payload.get("truncated", False)))

        rows = payload.get("games", [])
        paths = {row.get("path") for row in rows}
        self.assertIn(title_dir, paths)
        self.assertIn(f"{base}/custom_game", paths)

        by_path = {row.get("path"): row for row in rows}
        title_row = by_path.get(title_dir, {})
        self.assertEqual(title_row.get("title_id"), "PPSA12345")
        self.assertEqual(title_row.get("platform"), "PS5")
        sfo_row = by_path.get(f"{base}/custom_game", {})
        self.assertTrue(bool(sfo_row.get("has_param_sfo", False)))
        self.assertTrue(bool(sfo_row.get("has_cover", False)))

        status, headers, body = self.api_request("GET", f"/api/games/cover?path={self._q(base + '/custom_game')}")
        self.assertEqual(status, 200)
        self.assertIn("image/png", headers.get("Content-Type", ""))
        self.assertEqual(body, b"\x89PNG\r\n\x1a\n")

    def test_upload_and_download_file(self) -> None:
        target = "/cases/upload/hello.txt"
        blob = b"hello from integration tests\n"

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(target)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", f"/api/download?path={self._q(target)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

    def test_folder_upload_and_download_tar(self) -> None:
        files = {
            "/cases/folder/a.txt": b"a\n",
            "/cases/folder/sub/b.txt": b"bbb\n",
        }
        for path, data in files.items():
            status, _, _ = self.api_request(
                "PUT",
                f"/api/upload?path={self._q(path)}",
                body=data,
                headers={"Content-Length": str(len(data)), "Content-Type": "application/octet-stream"},
            )
            self.assertEqual(status, 200)

        status, headers, body = self.api_request("GET", f"/api/download-folder?path={self._q('/cases/folder')}")
        self.assertEqual(status, 200)
        self.assertIn("application/x-tar", headers.get("Content-Type", ""))

        with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
            names = set(archive.getnames())
            self.assertIn("folder/a.txt", names)
            self.assertIn("folder/sub/b.txt", names)
            with archive.extractfile("folder/sub/b.txt") as fh:
                self.assertEqual(fh.read(), b"bbb\n")

    def test_download_folder_on_file_rejected(self) -> None:
        file_path = "/cases/not_a_folder.txt"
        blob = b"single file\n"
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request("GET", f"/api/download-folder?path={self._q(file_path)}")
        self.assertEqual(status, 404)

    def test_move_and_delete(self) -> None:
        src = "/cases/move/src.txt"
        dst = "/cases/move/dst.txt"
        blob = b"move me\n"

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob))},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "POST",
            f"/api/move?src={self._q(src)}&dst={self._q(dst)}",
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request("GET", f"/api/download?path={self._q(src)}")
        self.assertEqual(status, 404)
        status, _, body = self.api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

        status, _, _ = self.api_request("DELETE", f"/api/delete?path={self._q(dst)}")
        self.assertEqual(status, 200)
        status, _, _ = self.api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 404)

    def test_move_into_existing_directory_keeps_name(self) -> None:
        src = "/cases/move_dir/src.txt"
        dst_dir = "/cases/move_dir/target"
        dst = f"{dst_dir}/src.txt"
        blob = b"move into existing dir\n"

        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob))},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "POST",
            f"/api/move?src={self._q(src)}&dst={self._q(dst_dir)}",
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request("GET", f"/api/download?path={self._q(src)}")
        self.assertEqual(status, 404)
        status, _, body = self.api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

    def test_copy_into_existing_directory_keeps_name(self) -> None:
        src = "/cases/copy_dir/src.txt"
        dst_dir = "/cases/copy_dir/target"
        dst = f"{dst_dir}/src.txt"
        blob = b"copy into existing dir\n"

        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob))},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "POST",
            f"/api/copy?src={self._q(src)}&dst={self._q(dst_dir)}",
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", f"/api/download?path={self._q(src)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

        status, _, body = self.api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

    def test_copy_same_path_rejected(self) -> None:
        src = "/cases/copy_same/file.txt"
        blob = b"same path copy\n"

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request("POST", f"/api/copy?src={self._q(src)}&dst={self._q(src)}")
        self.assertEqual(status, 400)

    def test_copy_directory_into_itself_rejected(self) -> None:
        src_dir = "/cases/copy_loop/src"
        nested_dst = "/cases/copy_loop/src/child"
        file_path = f"{src_dir}/seed.txt"
        blob = b"seed\n"

        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(src_dir)}")
        self.assertEqual(status, 200)
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self.api_request("POST", f"/api/copy?src={self._q(src_dir)}&dst={self._q(nested_dst)}")
        self.assertEqual(status, 400)

        status, _, body = self.api_request("GET", f"/api/stat?path={self._q(nested_dst)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload.get("exists"))

    def test_chmod777_recursive(self) -> None:
        folder = "/cases/chmod/sub"
        file_path = f"{folder}/exec.bin"
        blob = b"chmod target\n"

        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(folder)}")
        self.assertEqual(status, 200)

        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("POST", f"/api/chmod777?path={self._q('/cases/chmod')}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        self.assertGreaterEqual(int(payload.get("touched", 0)), 2)

        status, _, body = self.api_request("GET", f"/api/stat?path={self._q('/cases/chmod/sub')}")
        self.assertEqual(status, 200)
        mode_dir = int(json.loads(body.decode("utf-8"))["mode"])
        self.assertEqual(mode_dir & 0o777, 0o777)

        status, _, body = self.api_request("GET", f"/api/stat?path={self._q(file_path)}")
        self.assertEqual(status, 200)
        mode_file = int(json.loads(body.decode("utf-8"))["mode"])
        self.assertEqual(mode_file & 0o777, 0o777)

    def test_traversal_rejected(self) -> None:
        status, _, _ = self.api_request("GET", "/api/list?path=/../")
        self.assertIn(status, (400, 403))

    def test_stat_reports_missing_and_existing(self) -> None:
        missing_path = "/cases/stat/nope.txt"
        status, _, body = self.api_request("GET", f"/api/stat?path={self._q(missing_path)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], missing_path)
        self.assertFalse(payload["exists"])

        file_path = "/cases/stat/existing.txt"
        blob = b"stat coverage\n"
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", f"/api/stat?path={self._q(file_path)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], file_path)
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["is_dir"])
        self.assertEqual(int(payload["size"]), len(blob))

    def test_stress_big_file_deep_tree_and_wide_folder(self) -> None:
        if not env_flag("PS5DRIVE_STRESS"):
            self.skipTest("set PS5DRIVE_STRESS=1 to run deep/wide/large stress coverage")

        big_mb = env_int("PS5DRIVE_STRESS_BIG_MB", 64)
        deep_levels = env_int("PS5DRIVE_STRESS_DEEP_LEVELS", 24)
        wide_files = env_int("PS5DRIVE_STRESS_WIDE_FILES", 5000)
        small_bytes = env_int("PS5DRIVE_STRESS_SMALL_BYTES", 64)
        list_page = env_int("PS5DRIVE_STRESS_LIST_PAGE", 1000)

        base = "/cases/stress"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(base)}")
        self.assertEqual(status, 200)

        deep_root = f"{base}/deep"
        deep_leaf = deep_root
        for idx in range(deep_levels):
            deep_leaf = f"{deep_leaf}/d{idx:04d}"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(deep_leaf)}")
        self.assertEqual(status, 200)

        deep_file = f"{deep_leaf}/leaf.txt"
        deep_blob = (b"deep\n" * ((small_bytes + 4) // 5))[:small_bytes]
        status, _, _ = self.api_request(
            "PUT",
            f"/api/upload?path={self._q(deep_file)}",
            body=deep_blob,
            headers={"Content-Length": str(len(deep_blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self.api_request("GET", f"/api/download?path={self._q(deep_file)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, deep_blob)

        big_dir = f"{base}/big"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(big_dir)}")
        self.assertEqual(status, 200)

        big_target = f"{big_dir}/big.bin"
        big_size = big_mb * 1024 * 1024
        pattern = b"0123456789abcdef" * 4096
        with tempfile.NamedTemporaryFile(prefix="ps5drive-big-", delete=False) as tmp:
            remaining = big_size
            while remaining > 0:
                chunk = pattern if remaining >= len(pattern) else pattern[:remaining]
                tmp.write(chunk)
                remaining -= len(chunk)
            tmp_path = Path(tmp.name)
        try:
            with tmp_path.open("rb") as fh:
                status, _, _ = self.api_request(
                    "PUT",
                    f"/api/upload?path={self._q(big_target)}",
                    body=fh,
                    headers={"Content-Length": str(big_size), "Content-Type": "application/octet-stream"},
                )
            self.assertEqual(status, 200)
        finally:
            tmp_path.unlink(missing_ok=True)

        status, _, body = self.api_request("GET", f"/api/stat?path={self._q(big_target)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["is_dir"])
        self.assertEqual(int(payload["size"]), big_size)

        wide_dir = f"{base}/wide"
        status, _, _ = self.api_request("POST", f"/api/mkdir?path={self._q(wide_dir)}")
        self.assertEqual(status, 200)

        unit = b"x" * small_bytes
        for idx in range(wide_files):
            file_path = f"{wide_dir}/f{idx:06d}.bin"
            status, _, _ = self.api_request(
                "PUT",
                f"/api/upload?path={self._q(file_path)}",
                body=unit,
                headers={"Content-Length": str(len(unit)), "Content-Type": "application/octet-stream"},
            )
            self.assertEqual(status, 200)

        seen = 0
        offset = 0
        page = max(1, list_page)
        while True:
            status, _, body = self.api_request(
                "GET",
                f"/api/list?path={self._q(wide_dir)}&limit={page}&offset={offset}",
            )
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            seen += len(payload["entries"])
            if not bool(payload["has_more"]):
                break
            offset = int(payload["next_offset"])
        self.assertEqual(seen, wide_files)

    def test_child_restart(self) -> None:
        status, _, body = self.api_request("GET", "/api/admin/pid")
        self.assertEqual(status, 200)
        first_pid = int(json.loads(body.decode("utf-8"))["pid"])

        status, _, _ = self.api_request("POST", "/api/admin/exit")
        self.assertEqual(status, 200)

        self._wait_for_health(timeout=20)
        status, _, body = self.api_request("GET", "/api/admin/pid")
        self.assertEqual(status, 200)
        second_pid = int(json.loads(body.decode("utf-8"))["pid"])
        self.assertNotEqual(first_pid, second_pid)


if __name__ == "__main__":
    unittest.main()
