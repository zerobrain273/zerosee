"""Exercise the public CLI contract, including boundaries and malformed input."""
import socket
import errno
import os
import subprocess
import sys
import unittest

BINARY = sys.argv.pop(1)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=5)

    def test_help(self):
        for args in [(), ("--help",), ("-h",), ("scan", "-h"), ("scan", "--help"), ("scan", "127.0.0.1", "-h")]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0)
                self.assertIn("Usage:", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_short_flags(self):
        result = self.run_cli("scan", "127.0.0.1", "-p", "80,443", "-t", "250",
                              "-c", "4", "--dry-run", "--no-banner")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ports: 80,443", result.stdout)
        self.assertIn("Timeout: 250 ms", result.stdout)
        self.assertIn("Concurrency: 4", result.stdout)
        self.assertNotIn("[ z ]", result.stdout)

    def test_version(self):
        for flag in ["-V", "--version"]:
            result = self.run_cli(flag)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "zerosee 0.2.0\n")

    def test_concurrency_and_duplicate_flags(self):
        cases = [["-c", value] for value in ["0", "-1", "257", "2x", "", "999999999999"]]
        cases += [["-c"], ["-c", "2", "--concurrency", "3"],
                  ["-t", "2", "--timeout-ms", "3"], ["-p", "81"],
                  ["--no-banner", "--no-banner"]]
        for extra in cases:
            with self.subTest(extra=extra):
                result = self.run_cli("scan", "127.0.0.1", "--ports", "80", "--dry-run", *extra)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
        for value in ["1", "256"]:
            result = self.run_cli("scan", "127.0.0.1", "-p", "80", "-c", value, "--dry-run")
            self.assertEqual(result.returncode, 0)

    def test_ports_are_sorted_and_deduplicated(self):
        result = self.run_cli("scan", "127.0.0.1", "--ports", "8000-8002,22,8001,1,65535", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ports: 1,22,8000,8001,8002,65535\n", result.stdout)
        self.assertIn("no network connections", result.stdout)

    def test_entire_port_range(self):
        result = self.run_cli("scan", "127.0.0.1", "--ports", "1-65535", "--dry-run")
        self.assertEqual(result.returncode, 0)
        ports = result.stdout.splitlines()[1].removeprefix("Ports: ").split(",")
        self.assertEqual(len(ports), 65535)
        self.assertEqual(ports[-1], "65535")

    def test_tcp_open_and_refused(self):
        try:
            check = socket.socket()
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES):
                if os.environ.get("ZEROSEE_REQUIRE_NETWORK_TESTS") == "1":
                    raise
                self.skipTest("Environment prohibits network sockets; run locally to verify TCP")
            raise
        check.close()
        with socket.socket() as listener, socket.socket() as reserved:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            reserved.bind(("127.0.0.1", 0))
            opened = listener.getsockname()[1]
            refused = reserved.getsockname()[1]
            result = self.run_cli("scan", "127.0.0.1", "--ports",
                                  f"{opened},{refused}", "--timeout-ms", "200")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"127.0.0.1:{opened}  OPEN", result.stdout)
            self.assertIn(f"127.0.0.1:{refused}  REFUSED", result.stdout)

    def test_invalid_timeout(self):
        for value in ["0", "-1", "60001", "abc", "1ms", "", "99999999999999"]:
            with self.subTest(value=value):
                result = self.run_cli("scan", "127.0.0.1", "--ports", "80",
                                      "--timeout-ms", value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_timeout_bounds(self):
        for value in ["1", "60000"]:
            result = self.run_cli("scan", "127.0.0.1", "--ports", "80",
                                  "--timeout-ms", value, "--dry-run")
            self.assertEqual(result.returncode, 0)
            self.assertIn(f"Timeout: {value} ms", result.stdout)

    def test_invalid_ports(self):
        for ports in ["", "0", "65536", "-1", "+80", "80abc", "1.5", "1e2",
                      "80,", ",80", "80,,81", "90-80", "80-", "-80", "1-2-3",
                      "99999999999999999999999999", "80, 81"]:
            with self.subTest(ports=ports):
                result = self.run_cli("scan", "127.0.0.1", "--ports", ports)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Error:", result.stderr)

    def test_invalid_commands(self):
        for args in [
            ["unknown"], ["scan"], ["scan", "127.0.0.1"],
            ["scan", "127.0.0.1", "--ports"],
            ["scan", "localhost", "--ports", "80"],
            ["scan", "999.1.1.1", "--ports", "80"],
            ["scan", "::1", "--ports", "80"],
            ["scan", "127.0.0.1", "--ports", "80", "--ports", "81"],
            ["scan", "127.0.0.1", "--ports", "80", "--typo"],
        ]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
