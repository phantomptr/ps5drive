import unittest


@unittest.skip("PS4 mock integration test suite pending dedicated PS4 host harness")
class Ps4MockPlaceholderTests(unittest.TestCase):
    def test_placeholder(self) -> None:
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
