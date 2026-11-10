import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = sys.argv.pop(1)


class WebCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=5)

    def test_help(self):
        for flag in ("-h", "--help"):
            result = self.run_cli("web", flag)
            self.assertEqual(result.returncode, 0)
            self.assertIn("--allow-origin", result.stdout)
            self.assertIn("--ca-file", result.stdout)

    def test_invalid_inputs(self):
        for args in [(), ("example.test",), ("file:///etc/passwd",),
                     ("https://user:pass@example.test/",),
                     ("http://localhost/", "--timeout-ms", "0"),
                     ("http://localhost/", "--max-redirects", "11"),
                     ("http://localhost/", "--connect-ip", "invalid"),
                     ("http://localhost/", "--allow-origin", "http://other.test/path"),
                     ("http://localhost/", "--allow-origin", "http://other.test/?query=1"),
                     ("http://localhost/", "--json"),
                     ("http://localhost/", "--insecure"),
                     ("http://localhost/", "--timeout-ms", "1", "-t", "2")]:
            with self.subTest(args=args):
                result = self.run_cli("web", *args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_output_validation_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("preserve")
            result = self.run_cli("web", "http://127.0.0.1:1/", "--json", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_text(), "preserve")
            absent = str(Path(directory) / "new")
            result = self.run_cli("web", "http://127.0.0.1:1/", "--json", absent, "--markdown", absent)
            self.assertEqual(result.returncode, 2)

    def test_error_report_is_valid_json(self):
        # Local port 0 is rejected, so use an invalid CA fixture to fail before connection.
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "bad.pem"
            ca.write_text("not a CA")
            report = Path(directory) / "error.json"
            result = self.run_cli("web", "https://127.0.0.1:1/", "--ca-file", str(ca),
                                  "--timeout-ms", "50", "--json", str(report))
            self.assertEqual(result.returncode, 1)
            data = json.loads(report.read_text())
            self.assertEqual(data["stop_reason"], "request_error")
            self.assertTrue(data["hops"][0]["error"])
            self.assertEqual(data["findings"], [])


if __name__ == "__main__":
    unittest.main()
