#!/usr/bin/env python3
"""Start an isolated lab, run representative checks, and leave JSON/Markdown reports."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from server import running


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "build/zerosee")
    parser.add_argument("--output", type=Path, default=Path("reports/demo"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error("Build zerosee first")
    if args.output.exists():
        parser.error("Choose a new output directory; existing reports are never overwritten")
    args.output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="zerosee-demo-") as directory:
        with running(directory) as (plain, secure, ca):
            http = f"http://127.0.0.1:{plain.server_port}"
            https = f"https://localhost:{secure.server_port}"
            cases = [
                ("http-weak", http + "/redirect", [], 0, "complete"),
                ("https-strong", https + "/strong", ["--ca-file", str(ca), "--connect-ip", "127.0.0.1"], 0, "complete"),
                ("scope-blocked", http + "/cross", [], 0, "out_of_scope"),
                ("tls-untrusted", https + "/strong", ["--connect-ip", "127.0.0.1"], 1, "request_error"),
            ]
            for name, url, flags, code, reason in cases:
                report = args.output / (name + ".json")
                print(f"\n--- {name} ---", flush=True)
                result = subprocess.run([str(binary), "web", url, *flags, "--no-banner",
                                         "--json", str(report), "--markdown", str(args.output / (name + ".md"))])
                if result.returncode != code:
                    raise SystemExit(f"Unexpected exit code for {name}: {result.returncode}")
                data = json.loads(report.read_text())
                if data["stop_reason"] != reason:
                    raise SystemExit(f"Unexpected stop reason for {name}")
                if name == "https-strong" and data["hops"][0]["tls"]["state"] != "verified":
                    raise SystemExit("Lab TLS verification did not succeed")
                if name == "tls-untrusted" and data["hops"][0]["tls"]["state"] != "verification_failed":
                    raise SystemExit("Untrusted certificate was not rejected as expected")
    print(f"\nDemo passed. Reports: {args.output.resolve()}")
    print("Temporary lab servers and private keys have been removed.")


if __name__ == "__main__":
    main()
