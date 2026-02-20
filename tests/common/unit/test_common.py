import os
import tempfile
import unittest
from pathlib import Path

from tests.common import env_flag, env_int, find_repo_root


class TestCommonHelpers(unittest.TestCase):
    def test_env_flag_truthy_values(self) -> None:
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                os.environ["PS5DRIVE_TEST_FLAG"] = value
                self.assertTrue(env_flag("PS5DRIVE_TEST_FLAG"))
        os.environ.pop("PS5DRIVE_TEST_FLAG", None)

    def test_env_flag_falsey_values(self) -> None:
        for value in ("0", "false", "off", "", "garbage"):
            with self.subTest(value=value):
                os.environ["PS5DRIVE_TEST_FLAG"] = value
                self.assertFalse(env_flag("PS5DRIVE_TEST_FLAG"))
        os.environ.pop("PS5DRIVE_TEST_FLAG", None)

    def test_env_int_parsing(self) -> None:
        os.environ["PS5DRIVE_TEST_INT"] = "42"
        self.assertEqual(env_int("PS5DRIVE_TEST_INT", 7), 42)

        os.environ["PS5DRIVE_TEST_INT"] = "not-a-number"
        self.assertEqual(env_int("PS5DRIVE_TEST_INT", 7), 7)

        os.environ["PS5DRIVE_TEST_INT"] = "0"
        self.assertEqual(env_int("PS5DRIVE_TEST_INT", 7, minimum=1), 7)
        os.environ.pop("PS5DRIVE_TEST_INT", None)

    def test_find_repo_root_from_nested_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
            (root / "VERSION").write_text("0.0.0\n", encoding="utf-8")

            nested = root / "tests" / "integration" / "mock" / "sample.py"
            nested.parent.mkdir(parents=True, exist_ok=True)
            nested.write_text("# sample\n", encoding="utf-8")

            self.assertEqual(find_repo_root(str(nested)), root)


if __name__ == "__main__":
    unittest.main()
