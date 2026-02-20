import base64
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

import requests

from tests.common import env_flag, env_int, find_repo_root

REPO_ROOT = find_repo_root(__file__)


class Ps5DriveRemoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ps5_ip = os.getenv("PS5_IP", "192.168.137.2").strip()
        cls.loader_port = int(os.getenv("PS5_LOADER_PORT", "9021"))
        cls.web_port = int(os.getenv("PS5_WEB_PORT", "8903"))
        cls.api_port = int(os.getenv("PS5_API_PORT", "8904"))
        cls.debug_port = int(os.getenv("PS5_DEBUG_PORT", "8905"))
        cls.payload_path = Path(os.getenv("PS5_PAYLOAD_PATH", str(REPO_ROOT / "payload" / "ps5drive.elf")))
        cls.test_root = os.getenv("PS5_TEST_ROOT", "/data/ps5drive_test")
        cls.auth_user = os.getenv("PS5_AUTH_USER", "").strip()
        cls.auth_pass = os.getenv("PS5_AUTH_PASS", "")
        cls.auth_headers: dict[str, str] = {}
        if cls.auth_user:
            token = base64.b64encode(f"{cls.auth_user}:{cls.auth_pass}".encode("utf-8")).decode("ascii")
            cls.auth_headers = {"Authorization": f"Basic {token}"}
        cls.test_id = f"remote-{int(time.time())}"
        cls.case_root = f"{cls.test_root}/{cls.test_id}"

        if not cls.payload_path.exists():
            raise RuntimeError(f"payload not found: {cls.payload_path}")

        sent, send_error = cls._send_payload(cls.payload_path)
        cls._wait_for_server(timeout=40.0, send_error=send_error if not sent else None)

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._api_request("DELETE", f"/api/delete?path={cls._q(cls.case_root)}")
        except Exception:
            pass
        try:
            cls._api_request("POST", "/api/stop")
        except Exception:
            pass

    @classmethod
    def _send_payload(cls, payload: Path) -> tuple[bool, str]:
        errors: list[str] = []
        if shutil.which("nc"):
            with payload.open("rb") as fh:
                proc = subprocess.run(
                    ["nc", "-w", "1", cls.ps5_ip, str(cls.loader_port)],
                    stdin=fh,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            if proc.returncode == 0:
                return True, "sent via nc"
            errors.append(f"nc rc={proc.returncode} stderr={proc.stderr.decode('utf-8', 'ignore').strip()}")

        data = payload.read_bytes()
        try:
            with socket.create_connection((cls.ps5_ip, cls.loader_port), timeout=4) as sock:
                sock.sendall(data)
            return True, "sent via raw socket"
        except OSError as exc:
            errors.append(f"socket error={exc}")
            return False, "; ".join(errors)

    @classmethod
    def _wait_for_server(cls, timeout: float, send_error: str | None = None) -> None:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                web_status, _, web_body = cls._web_request("GET", "/")
                api_status, _, api_body = cls._api_request("GET", "/api/health")
                if (web_status == 401 or api_status == 401) and not cls.auth_headers:
                    raise RuntimeError("target requires auth; set PS5_AUTH_USER and PS5_AUTH_PASS")
                if web_status == 200 and api_status == 200:
                    health = json.loads(api_body.decode("utf-8"))
                    if health.get("ok") is True and b"PS5Drive" in web_body:
                        return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
            time.sleep(0.5)
        extra = f"; send_error={send_error}" if send_error else ""
        raise RuntimeError(
            f"ps5drive did not become ready on {cls.ps5_ip}:{cls.api_port}/{cls.web_port}: {last_err}{extra}"
        )

    @classmethod
    def _api_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        merged_headers = dict(cls.auth_headers)
        if headers:
            merged_headers.update(headers)
        resp = requests.request(
            method=method,
            url=f"http://{cls.ps5_ip}:{cls.api_port}{path}",
            data=body,
            headers=merged_headers,
            timeout=15,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @classmethod
    def _web_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        merged_headers = dict(cls.auth_headers)
        if headers:
            merged_headers.update(headers)
        resp = requests.request(
            method=method,
            url=f"http://{cls.ps5_ip}:{cls.web_port}{path}",
            data=body,
            headers=merged_headers,
            timeout=15,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @classmethod
    def _debug_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        resp = requests.request(
            method=method,
            url=f"http://{cls.ps5_ip}:{cls.debug_port}{path}",
            data=body,
            headers=headers or {},
            timeout=15,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @staticmethod
    def _q(path: str) -> str:
        return urllib.parse.quote(path, safe="/")

    def test_web_8903_index(self) -> None:
        status, headers, body = self._web_request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8", "ignore")
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
        self.assertIn("const UPLOAD_WARN_FILE_COUNT=20000;", text)
        self.assertIn("const UPLOAD_BLOCK_FILE_COUNT=0;", text)
        self.assertIn("function shouldAcceptLargeSelection(", text)
        self.assertIn("function acquireUploadLock(", text)
        self.assertIn("/api/upload/state", text)
        self.assertIn("/api/upload/lock", text)
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

    def test_web_8903_i18n_locale_coverage(self) -> None:
        status, _, body = self._web_request("GET", "/")
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
        status, headers, body = self._web_request("GET", "/assets/logo-light.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("Content-Type", ""))
        self.assertIn(b"<svg", body)
        self.assertIn(b"PS5Drive", body)

        status, headers, body = self._web_request("GET", "/assets/logo-dark.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("Content-Type", ""))
        self.assertIn(b"<svg", body)
        self.assertIn(b"PS5Drive", body)

    def test_config_download(self) -> None:
        status, headers, body = self._api_request("GET", "/api/config/download")
        self.assertEqual(status, 200)
        self.assertIn("application/octet-stream", headers.get("Content-Type", ""))
        text = body.decode("utf-8", "ignore")
        self.assertIn("mode=", text)
        self.assertIn("username=", text)
        self.assertIn("password=", text)

    def test_config_upload_roundtrip(self) -> None:
        status, _, config_body = self._api_request("GET", "/api/config/download")
        self.assertEqual(status, 200)
        self.assertGreater(len(config_body), 0)

        status, _, body = self._api_request(
            "POST",
            "/api/config/upload",
            body=config_body,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertIn(str(payload.get("security_mode", "")), ("secure", "unsecure"))

    def test_api_health_8904(self) -> None:
        status, _, body = self._api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertTrue(health["ok"])
        self.assertGreater(int(health.get("pid", 0)), 0)
        self.assertGreater(int(health.get("ppid", 0)), 0)
        self.assertEqual(int(health["api_port"]), self.api_port)
        self.assertEqual(int(health["web_port"]), self.web_port)
        self.assertEqual(int(health["debug_port"]), self.debug_port)
        self.assertIn(str(health.get("security_mode", "")), ("secure", "unsecure"))
        if str(health.get("security_mode", "")) == "secure":
            self.assertTrue(bool(health.get("auth_enabled", False)))
        self.assertFalse(bool(health.get("upload_lock_busy", False)))
        self.assertEqual(str(health.get("upload_lock_owner", "")), "")
        self.assertEqual(str(health.get("upload_lock_path", "")), "")

    def test_web_port_api_health(self) -> None:
        status, _, body = self._web_request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertTrue(health["ok"])

    def test_storage_list_endpoint(self) -> None:
        status, _, body = self._api_request("GET", "/api/storage/list")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        rows = payload.get("storage", [])
        self.assertIsInstance(rows, list)
        paths = {row.get("path") for row in rows if isinstance(row, dict)}
        self.assertIn("/", paths)

    def test_debug_8905_health_and_logs(self) -> None:
        status, _, body = self._api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        api_health = json.loads(body.decode("utf-8"))
        if not bool(api_health.get("debug_enabled", False)):
            self.skipTest("debug port is disabled on target (likely port bind conflict)")

        status, _, body = self._debug_request("GET", "/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertTrue(health["ok"])
        self.assertEqual(int(health["debug_port"]), self.debug_port)
        self.assertTrue(bool(health["debug_enabled"]))

        status, headers, body = self._debug_request("GET", "/logs")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers.get("Content-Type", ""))
        self.assertGreater(len(body), 0)

    def test_web_abort_clients_do_not_kill_payload(self) -> None:
        for _ in range(20):
            sock = socket.create_connection((self.ps5_ip, self.web_port), timeout=4)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: ps5\r\n\r\n")
            sock.close()

        deadline = time.time() + 10.0
        last_err = None
        while time.time() < deadline:
            try:
                status, _, body = self._api_request("GET", "/api/health")
                if status == 200 and json.loads(body.decode("utf-8")).get("ok") is True:
                    return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
            time.sleep(0.5)
        self.fail(f"payload health did not recover after web aborts: {last_err}")

    def test_web_repeated_requests_keep_pid(self) -> None:
        status, _, body = self._api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        start_pid = int(json.loads(body.decode("utf-8"))["pid"])

        for _ in range(40):
            status, _, _ = self._web_request("GET", "/")
            self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        end_pid = int(json.loads(body.decode("utf-8"))["pid"])
        self.assertEqual(start_pid, end_pid)

    def test_remote_upload_browse_download(self) -> None:
        folder = f"{self.case_root}/files"
        file_path = f"{folder}/hello.txt"
        blob = b"hello from remote ps5 test\n"

        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(folder)}")
        self.assertEqual(status, 200)

        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", f"/api/list?path={self._q(folder)}")
        self.assertEqual(status, 200)
        listing = json.loads(body.decode("utf-8"))
        names = [entry["name"] for entry in listing["entries"]]
        self.assertIn("hello.txt", names)

        status, _, downloaded = self._api_request("GET", f"/api/download?path={self._q(file_path)}")
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, blob)

        status, _, _ = self._api_request("DELETE", f"/api/delete?path={self._q(file_path)}")
        self.assertEqual(status, 200)

    def test_remote_list_pagination(self) -> None:
        folder = f"{self.case_root}/paginate"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(folder)}")
        self.assertEqual(status, 200)

        for i in range(21):
            file_path = f"{folder}/f{i:03d}.txt"
            blob = f"remote-file-{i}\n".encode("utf-8")
            status, _, _ = self._api_request(
                "PUT",
                f"/api/upload?path={self._q(file_path)}",
                body=blob,
                headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
            )
            self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", f"/api/list?path={self._q(folder)}&limit=8&offset=0")
        self.assertEqual(status, 200)
        page1 = json.loads(body.decode("utf-8"))
        self.assertEqual(int(page1["limit"]), 8)
        self.assertLessEqual(len(page1["entries"]), 8)
        self.assertTrue(bool(page1["has_more"]))
        next_offset = int(page1["next_offset"])
        self.assertGreaterEqual(next_offset, 8)

        status, _, body = self._api_request("GET", f"/api/list?path={self._q(folder)}&limit=8&offset={next_offset}")
        self.assertEqual(status, 200)
        page2 = json.loads(body.decode("utf-8"))
        self.assertEqual(int(page2["offset"]), next_offset)
        self.assertLessEqual(len(page2["entries"]), 8)

    def test_remote_games_scan_finds_title_id_and_param_sfo(self) -> None:
        base = f"{self.case_root}/games_scan"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(base)}")
        self.assertEqual(status, 200)

        title_dir = f"{base}/CUSA00001"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(title_dir)}")
        self.assertEqual(status, 200)
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(title_dir + '/eboot.bin')}",
            body=b"x",
            headers={"Content-Length": "1", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        sfo_path = f"{base}/custom_game/sce_sys/param.sfo"
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(sfo_path)}",
            body=b"PARAM",
            headers={"Content-Length": "5", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        cover_path = f"{base}/custom_game/sce_sys/icon0.png"
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(cover_path)}",
            body=b"\x89PNG\r\n\x1a\n",
            headers={"Content-Length": "8", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self._api_request(
            "GET",
            f"/api/games/scan?path={self._q(base)}&max_depth=6&max_dirs=2000",
        )
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        rows = payload.get("games", [])
        paths = {row.get("path") for row in rows}
        self.assertIn(title_dir, paths)
        self.assertIn(f"{base}/custom_game", paths)

        by_path = {row.get("path"): row for row in rows}
        self.assertTrue(bool(by_path.get(f"{base}/custom_game", {}).get("has_cover", False)))

        status, headers, body = self._api_request("GET", f"/api/games/cover?path={self._q(base + '/custom_game')}")
        self.assertEqual(status, 200)
        self.assertIn("image/png", headers.get("Content-Type", ""))
        self.assertEqual(body, b"\x89PNG\r\n\x1a\n")

    def test_remote_move_into_existing_directory_keeps_name(self) -> None:
        src = f"{self.case_root}/move_src.txt"
        dst_dir = f"{self.case_root}/move_target"
        dst = f"{dst_dir}/move_src.txt"
        blob = b"remote move into existing dir\n"

        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._api_request("POST", f"/api/move?src={self._q(src)}&dst={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, _ = self._api_request("GET", f"/api/download?path={self._q(src)}")
        self.assertEqual(status, 404)
        status, _, body = self._api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

    def test_remote_copy_into_existing_directory_keeps_name(self) -> None:
        src = f"{self.case_root}/copy_src.txt"
        dst_dir = f"{self.case_root}/copy_target"
        dst = f"{dst_dir}/copy_src.txt"
        blob = b"remote copy into existing dir\n"

        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._api_request("POST", f"/api/copy?src={self._q(src)}&dst={self._q(dst_dir)}")
        self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", f"/api/download?path={self._q(src)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)
        status, _, body = self._api_request("GET", f"/api/download?path={self._q(dst)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, blob)

    def test_remote_copy_same_path_rejected(self) -> None:
        src = f"{self.case_root}/copy_same.txt"
        blob = b"remote same path copy\n"

        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(src)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._api_request("POST", f"/api/copy?src={self._q(src)}&dst={self._q(src)}")
        self.assertEqual(status, 400)

    def test_remote_copy_directory_into_itself_rejected(self) -> None:
        src_dir = f"{self.case_root}/copy_loop/src"
        nested_dst = f"{src_dir}/child"
        file_path = f"{src_dir}/seed.txt"
        blob = b"seed\n"

        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(src_dir)}")
        self.assertEqual(status, 200)
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._api_request("POST", f"/api/copy?src={self._q(src_dir)}&dst={self._q(nested_dst)}")
        self.assertEqual(status, 400)

        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(nested_dst)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload.get("exists"))

    def test_remote_chmod777_recursive(self) -> None:
        folder = f"{self.case_root}/chmod/sub"
        file_path = f"{folder}/exec.bin"
        blob = b"remote chmod target\n"

        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(folder)}")
        self.assertEqual(status, 200)

        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self._api_request("POST", f"/api/chmod777?path={self._q(self.case_root + '/chmod')}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        self.assertGreaterEqual(int(payload.get("touched", 0)), 2)

        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(self.case_root + '/chmod/sub')}")
        self.assertEqual(status, 200)
        mode_dir = int(json.loads(body.decode("utf-8"))["mode"])
        self.assertEqual(mode_dir & 0o777, 0o777)

        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(file_path)}")
        self.assertEqual(status, 200)
        mode_file = int(json.loads(body.decode("utf-8"))["mode"])
        self.assertEqual(mode_file & 0o777, 0o777)

    def test_remote_stat_reports_missing_and_existing(self) -> None:
        missing_path = f"{self.case_root}/stat/nope.txt"
        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(missing_path)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], missing_path)
        self.assertFalse(payload["exists"])

        file_path = f"{self.case_root}/stat/existing.txt"
        blob = b"remote stat coverage\n"
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(file_path)}",
            body=blob,
            headers={"Content-Length": str(len(blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(file_path)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], file_path)
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["is_dir"])
        self.assertEqual(int(payload["size"]), len(blob))

    def test_remote_traversal_rejected(self) -> None:
        status, _, _ = self._api_request("GET", "/api/list?path=/../")
        self.assertIn(status, (400, 403))

    def test_remote_stress_big_file_deep_tree_and_wide_folder(self) -> None:
        if not env_flag("PS5DRIVE_REMOTE_STRESS"):
            self.skipTest("set PS5DRIVE_REMOTE_STRESS=1 to run remote deep/wide/large stress coverage")

        big_mb = env_int("PS5DRIVE_REMOTE_STRESS_BIG_MB", 32)
        deep_levels = env_int("PS5DRIVE_REMOTE_STRESS_DEEP_LEVELS", 16)
        wide_files = env_int("PS5DRIVE_REMOTE_STRESS_WIDE_FILES", 2000)
        small_bytes = env_int("PS5DRIVE_REMOTE_STRESS_SMALL_BYTES", 64)
        list_page = env_int("PS5DRIVE_REMOTE_STRESS_LIST_PAGE", 500)

        base = f"{self.case_root}/stress"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(base)}")
        self.assertEqual(status, 200)

        deep_root = f"{base}/deep"
        deep_leaf = deep_root
        for idx in range(deep_levels):
            deep_leaf = f"{deep_leaf}/d{idx:04d}"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(deep_leaf)}")
        self.assertEqual(status, 200)

        deep_file = f"{deep_leaf}/leaf.txt"
        deep_blob = (b"deep\n" * ((small_bytes + 4) // 5))[:small_bytes]
        status, _, _ = self._api_request(
            "PUT",
            f"/api/upload?path={self._q(deep_file)}",
            body=deep_blob,
            headers={"Content-Length": str(len(deep_blob)), "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)

        status, _, body = self._api_request("GET", f"/api/download?path={self._q(deep_file)}")
        self.assertEqual(status, 200)
        self.assertEqual(body, deep_blob)

        big_dir = f"{base}/big"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(big_dir)}")
        self.assertEqual(status, 200)

        big_target = f"{big_dir}/big.bin"
        big_size = big_mb * 1024 * 1024
        pattern = b"0123456789abcdef" * 4096
        with tempfile.NamedTemporaryFile(prefix="ps5drive-remote-big-", delete=False) as tmp:
            remaining = big_size
            while remaining > 0:
                chunk = pattern if remaining >= len(pattern) else pattern[:remaining]
                tmp.write(chunk)
                remaining -= len(chunk)
            tmp_path = Path(tmp.name)
        try:
            with tmp_path.open("rb") as fh:
                status, _, _ = self._api_request(
                    "PUT",
                    f"/api/upload?path={self._q(big_target)}",
                    body=fh,
                    headers={"Content-Length": str(big_size), "Content-Type": "application/octet-stream"},
                )
            self.assertEqual(status, 200)
        finally:
            tmp_path.unlink(missing_ok=True)

        status, _, body = self._api_request("GET", f"/api/stat?path={self._q(big_target)}")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["is_dir"])
        self.assertEqual(int(payload["size"]), big_size)

        wide_dir = f"{base}/wide"
        status, _, _ = self._api_request("POST", f"/api/mkdir?path={self._q(wide_dir)}")
        self.assertEqual(status, 200)

        unit = b"x" * small_bytes
        for idx in range(wide_files):
            file_path = f"{wide_dir}/f{idx:06d}.bin"
            status, _, _ = self._api_request(
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
            status, _, body = self._api_request(
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

    def test_web_8903_alive_after_api_ops(self) -> None:
        status, _, body = self._web_request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"PS5Drive", body)


if __name__ == "__main__":
    unittest.main()
