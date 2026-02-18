import json
import os
import shutil
import socket
import subprocess
import time
import unittest
import urllib.parse
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]


class Ps5DriveRemoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ps5_ip = os.getenv("PS5_IP", "192.168.137.2").strip()
        cls.loader_port = int(os.getenv("PS5_LOADER_PORT", "9021"))
        cls.web_port = int(os.getenv("PS5_WEB_PORT", "8903"))
        cls.api_port = int(os.getenv("PS5_API_PORT", "8904"))
        cls.debug_port = int(os.getenv("PS5_DEBUG_PORT", "8905"))
        cls.payload_path = Path(os.getenv("PS5_PAYLOAD_PATH", str(REPO_ROOT / "payload" / "ps5drive.elf")))
        cls.killer_path = Path(os.getenv("PS5_KILLER_PATH", str(REPO_ROOT / "payload" / "ps5drivekiller.elf")))
        cls.test_root = os.getenv("PS5_TEST_ROOT", "/data/ps5drive_test")
        cls.test_id = f"remote-{int(time.time())}"
        cls.case_root = f"{cls.test_root}/{cls.test_id}"

        if not cls.payload_path.exists():
            raise RuntimeError(f"payload not found: {cls.payload_path}")
        if not cls.killer_path.exists():
            raise RuntimeError(f"killer payload not found: {cls.killer_path}")

        cls._send_payload(cls.killer_path)
        sent, send_error = cls._send_payload(cls.payload_path)
        cls._wait_for_server(timeout=40.0, send_error=send_error if not sent else None)

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._api_request("DELETE", f"/api/delete?path={cls._q(cls.case_root)}")
        except Exception:
            pass
        cls._send_payload(cls.killer_path)

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
        resp = requests.request(
            method=method,
            url=f"http://{cls.ps5_ip}:{cls.api_port}{path}",
            data=body,
            headers=headers or {},
            timeout=15,
        )
        return resp.status_code, dict(resp.headers), resp.content

    @classmethod
    def _web_request(cls, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        resp = requests.request(
            method=method,
            url=f"http://{cls.ps5_ip}:{cls.web_port}{path}",
            data=body,
            headers=headers or {},
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
        self.assertIn("id=\"chmodBtn\">CHMOD 777", text)
        self.assertIn("Debug Port:", text)
        self.assertIn("id=\"moveInput\"", text)
        self.assertIn("id=\"loadMoreBtn\"", text)
        self.assertIn("id=\"uploadStopBtn\"", text)
        self.assertIn("Activity Log", text)
        self.assertNotIn("Status: Online", text)

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

    def test_web_port_api_health(self) -> None:
        status, _, body = self._web_request("GET", "/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body.decode("utf-8"))
        self.assertTrue(health["ok"])

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

    def test_web_8903_alive_after_api_ops(self) -> None:
        status, _, body = self._web_request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"PS5Drive", body)


if __name__ == "__main__":
    unittest.main()
