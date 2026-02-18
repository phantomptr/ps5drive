import io
import json
import os
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


REPO_ROOT = Path(__file__).resolve().parents[1]
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

    def test_health(self) -> None:
        status, _, body = self.api_request("GET", "/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["api_port"], self.api_port)
        self.assertEqual(payload["web_port"], self.web_port)
        self.assertEqual(payload["debug_port"], self.debug_port)
        self.assertTrue(payload["debug_enabled"])

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
        self.assertIn("id=\"chmodBtn\">CHMOD 777", text)
        self.assertIn("Debug Port:", text)
        self.assertIn("id=\"moveInput\"", text)
        self.assertIn("id=\"uploadStopBtn\"", text)
        self.assertIn("Activity Log", text)
        self.assertNotIn("Status: Online", text)

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
