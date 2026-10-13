import json
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard


class ScpGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.protected = self.root / "protected"
        self.protected.mkdir()
        config = self.root / "config.json"
        config.write_text(json.dumps({
            "sensitive_directories": [str(self.protected)],
            "sensitive_files": ["*.pem", ".env"],
            "scan_content": True,
        }), encoding="utf-8")
        self.policy = guard.load_policy(config)

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, *args):
        return guard.scan_launch({"argv": ["scp.exe", *args], "cwd": str(self.root)}, self.policy)

    def test_clean_upload_is_allowed(self):
        (self.root / "clean.txt").write_text("hello", encoding="utf-8")
        self.assertFalse(self.scan("-P", "22", "clean.txt", "user@host:/tmp/x")["deny"])

    def test_content_marker_is_blocked(self):
        (self.root / "blocked.txt").write_text("DEMO_SECRET_12345678", encoding="utf-8")
        self.assertTrue(self.scan("blocked.txt", "host:/tmp/x")["deny"])

    def test_protected_path_is_blocked(self):
        secret = self.protected / "plain.txt"
        secret.write_text("plain", encoding="utf-8")
        self.assertTrue(self.scan(str(secret), "host:/tmp/x")["deny"])

    def test_download_is_not_treated_as_upload(self):
        self.assertFalse(self.scan("host:/tmp/x", "download.txt")["deny"])


if __name__ == "__main__":
    unittest.main()
