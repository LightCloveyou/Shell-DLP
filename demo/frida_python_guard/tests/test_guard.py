import json
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard


class PythonGuardTests(unittest.TestCase):
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
        return guard.scan_launch({"argv": ["python.exe", *args], "cwd": str(self.root)}, self.policy)

    def test_clean_script_is_allowed(self):
        (self.root / "clean.py").write_text("print('ok')", encoding="utf-8")
        self.assertFalse(self.scan("-u", "clean.py")["deny"])

    def test_script_content_is_blocked(self):
        (self.root / "blocked.py").write_text("print('DEMO_SECRET_12345678')", encoding="utf-8")
        self.assertTrue(self.scan("-I", "-u", "blocked.py")["deny"])

    def test_inline_content_is_blocked(self):
        self.assertTrue(self.scan("-c", "print('DEMO_SECRET_12345678')")["deny"])

    def test_module_and_version_are_allowed(self):
        self.assertFalse(self.scan("--version")["deny"])
        self.assertFalse(self.scan("-m", "pip", "--version")["deny"])

    def test_protected_script_is_blocked(self):
        script = self.protected / "plain.py"
        script.write_text("print('plain')", encoding="utf-8")
        self.assertTrue(self.scan(str(script))["deny"])


if __name__ == "__main__":
    unittest.main()
