"""Real libcurl + local HTTP/TLS fixtures. No internet needed; sockets required."""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

BINARY = sys.argv.pop(1)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
from server import certificates, running


class CertificateTests(unittest.TestCase):
    def test_lab_trust_and_name(self):
        with tempfile.TemporaryDirectory() as directory:
            ca, cert, _ = certificates(directory)
            valid = subprocess.run(["openssl", "verify", "-CAfile", str(ca),
                                    "-verify_hostname", "localhost", str(cert)], capture_output=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            wrong = subprocess.run(["openssl", "verify", "-CAfile", str(ca),
                                    "-verify_hostname", "wrong.test", str(cert)], capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            with socket.socket() as check:
                check.bind(("127.0.0.1", 0))
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES):
                if os.environ.get("ZEROSEE_REQUIRE_NETWORK_TESTS") == "1":
                    raise
                raise unittest.SkipTest("Environment prohibits sockets; run this suite locally")
            raise
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.lab = running(Path(cls.temp.name) / "certs")
        cls.plain, cls.secure, cls.ca = cls.lab.__enter__()
        cls.addClassCleanup(cls.lab.__exit__, None, None, None)
        cls.http = f"http://127.0.0.1:{cls.plain.server_port}"
        cls.https = f"https://localhost:{cls.secure.server_port}"

    def web(self, url, *args):
        with tempfile.TemporaryDirectory() as directory:
            report, markdown = Path(directory) / "report.json", Path(directory) / "report.md"
            env = os.environ.copy()
            # Prove environment proxy variables do not alter direct scope checks.
            env.update(http_proxy="http://127.0.0.1:1", https_proxy="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1")
            process = subprocess.run([BINARY, "web", url, "--no-banner", "--json", str(report),
                                      "--markdown", str(markdown), *args],
                                     capture_output=True, text=True, timeout=10, env=env)
            self.assertTrue(report.exists(), process.stderr)
            self.assertNotIn("LAB_SECRET", report.read_text())
            self.assertNotIn("LAB_SECRET", markdown.read_text())
            self.assertNotIn("LAB_SECRET", process.stdout)
            return process, json.loads(report.read_text())

    def test_relative_redirect_and_cookies(self):
        process, report = self.web(self.http + "/redirect")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual([h["status"] for h in report["hops"]], [302, 200])
        self.assertEqual(len(report["hops"][-1]["cookies"]), 2)
        self.assertIn("cookie-none-without-secure", {f["id"] for f in report["findings"]})

    def test_scope_then_allow_origin(self):
        before = len(self.plain.seen)
        process, report = self.web(self.http + "/cross")
        self.assertEqual(report["stop_reason"], "out_of_scope")
        self.assertEqual(len(self.plain.seen) - before, 1)
        process, report = self.web(self.http + "/cross", "--allow-origin", f"http://localhost:{self.plain.server_port}")
        self.assertEqual(report["stop_reason"], "complete")
        self.assertEqual(len(report["hops"]), 2)

    def test_tls_trust_and_hostname(self):
        process, report = self.web(self.https + "/strong", "--ca-file", str(self.ca), "--connect-ip", "127.0.0.1")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(report["hops"][0]["tls"]["state"], "verified")
        self.assertTrue(report["hops"][0]["tls"]["certificates"])
        # BaseHTTPRequestHandler sends Server: Python, intentionally an informational hint.
        self.assertFalse([f for f in report["findings"] if f["level"] == "review"])
        process, report = self.web(self.https + "/strong", "--connect-ip", "127.0.0.1")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["hops"][0]["tls"]["state"], "verification_failed")
        process, report = self.web(f"https://127.0.0.1:{self.secure.server_port}/strong", "--ca-file", str(self.ca))
        self.assertEqual(report["hops"][0]["tls"]["state"], "verification_failed")
        self.assertEqual(process.returncode, 1)

    def test_downgrade_blocked(self):
        before = len(self.plain.seen)
        _, report = self.web(self.https + "/downgrade", "--ca-file", str(self.ca),
                             "--connect-ip", "127.0.0.1", "--allow-origin", f"http://localhost:{self.plain.server_port}")
        self.assertEqual(report["stop_reason"], "https_downgrade_blocked")
        self.assertEqual(len(self.plain.seen), before)

    def test_no_cookie_replay(self):
        _, report = self.web(self.http + "/cookie-redirect")
        self.assertEqual(report["stop_reason"], "complete")
        self.assertEqual(self.plain.seen[-1], ("/echo", None))

    def test_loop_limits_and_ambiguous_location(self):
        for path, flags, reason in [("/loop", (), "redirect_loop"),
                                    ("/redirect", ("--max-redirects", "0"), "redirect_limit"),
                                    ("/duplicate-location", (), "invalid_location")]:
            process, report = self.web(self.http + path, *flags)
            self.assertEqual(report["stop_reason"], reason)
            self.assertEqual(process.returncode, 1)

    def test_response_limits_timeout_and_interim(self):
        process, report = self.web(self.http + "/large")
        self.assertEqual(process.returncode, 0)
        self.assertTrue(report["hops"][0]["body_truncated"])
        process, report = self.web(self.http + "/huge-header")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["stop_reason"], "request_error")
        self.assertEqual(report["findings"], [])
        process, report = self.web(self.http + "/slow", "--timeout-ms", "30")
        self.assertEqual(process.returncode, 1)
        process, report = self.web(self.http + "/interim")
        self.assertEqual(process.returncode, 0)
        self.assertEqual(report["hops"][0]["status"], 200)
        self.assertNotIn("Link", [h["name"] for h in report["hops"][0]["headers"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
