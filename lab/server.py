#!/usr/bin/env python3
"""Local-only HTTP/HTTPS fixtures. Intentionally weak endpoints are for testing zerosee."""
import argparse
import contextlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time


def certificates(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca, cert = directory / "ca.pem", directory / "server.pem"
    key = directory / "server.key"
    if all(p.exists() for p in (ca, cert, key)):
        return ca, cert, key
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
            "-subj", "/CN=zerosee local lab CA", "-keyout", directory / "ca.key", "-out", ca,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
            "-keyout", key, "-out", directory / "server.csr")
    extension = directory / "server.ext"
    extension.write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", directory / "server.csr", "-CA", ca,
            "-CAkey", directory / "ca.key", "-CAcreateserial", "-days", "7",
            "-extfile", extension, "-out", cert)
    for private in directory.glob("*.key"):
        private.chmod(0o600)
    return ca, cert, key


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.seen.append((self.path, self.headers.get("Cookie")))
        path = self.path.split("?", 1)[0]
        status, headers = 200, []
        body = b"<!doctype html><title>zerosee lab</title><p>Local fixture</p>"
        if path == "/redirect":
            status, headers = 302, [("Location", "/weak")]
        elif path == "/cross":
            status, headers = 302, [("Location", f"http://localhost:{self.server.server_port}/strong")]
        elif path == "/upgrade":
            status, headers = 302, [("Location", f"https://localhost:{self.server.https_port}/strong")]
        elif path == "/downgrade":
            status, headers = 302, [("Location", f"http://localhost:{self.server.http_port}/weak")]
        elif path == "/loop":
            status, headers = 302, [("Location", "/loop")]
        elif path == "/duplicate-location":
            status, headers = 302, [("Location", "/weak"), ("Location", "/strong")]
        elif path == "/cookie-redirect":
            status, headers = 302, [("Location", "/echo"), ("Set-Cookie", "session=DO_NOT_REPLAY; Path=/")]
        elif path == "/echo":
            body = json.dumps({"cookie_received": bool(self.headers.get("Cookie"))}).encode()
        elif path == "/strong":
            headers = [("Strict-Transport-Security", "max-age=31536000"),
                       ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
                       ("X-Content-Type-Options", "nosniff"),
                       ("Set-Cookie", "__Host-session=LAB_STRONG_SECRET; Secure; HttpOnly; SameSite=Strict; Path=/")]
        elif path == "/large":
            body = b"x" * 100000
        elif path == "/huge-header":
            headers = [("X-Large", "x" * 70000)]
        elif path == "/slow":
            time.sleep(0.5)
        elif path == "/interim":
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nLink: </unused>\r\n\r\n")
        elif path == "/json":
            body = b'{"fixture": true}'
        elif path not in ("/", "/weak"):
            status = 404
        if path in ("/", "/weak"):
            headers += [("Set-Cookie", "session=LAB_SECRET; SameSite=None; Path=/"),
                        ("Set-Cookie", "theme=dark; Path=/"), ("X-Powered-By", "zerosee-lab")]
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if path in ("/json", "/echo") else "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


@contextlib.contextmanager
def running(directory, http_port=0, https_port=0):
    ca, cert, key = certificates(directory)
    servers, threads = [], []
    try:
        plain = Server(("127.0.0.1", http_port), Handler)
        servers.append(plain)
        secure = Server(("127.0.0.1", https_port), Handler)
        servers.append(secure)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        for server in servers:
            server.seen = []
            server.http_port = plain.server_port
            server.https_port = secure.server_port
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        yield plain, secure, ca
    finally:
        for server, thread in zip(servers, threads):
            server.shutdown()
            thread.join(timeout=3)
        for server in servers:
            server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-port", type=int, default=8000)
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--cert-dir", type=Path, default=Path(__file__).parent / ".certs")
    args = parser.parse_args()
    with running(args.cert_dir, args.http_port, args.https_port) as (plain, secure, ca):
        print(f"HTTP:  http://127.0.0.1:{plain.server_port}/weak", flush=True)
        print(f"HTTPS: https://localhost:{secure.server_port}/strong", flush=True)
        print(f"CA: {ca.resolve()} (trust only for this lab via --ca-file)", flush=True)
        print("Ctrl+C stops both servers.", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
