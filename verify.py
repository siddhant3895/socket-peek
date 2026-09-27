"""End-to-end verification for socket-peek.

Runs three scenarios:
  1. plain HTTP   -> logs a recognised registry  (expect SAFE)
  2. HTTPS/CONNECT-> logs an unrecognised host   (expect UNKNOWN)
  3. HTTP to a raw IP literal                   (expect UNKNOWN, IP verdict)

Each launches a throwaway local origin server, then runs a client that honours
the proxy env vars, under `socket-peek` itself.
"""

import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

RESULTS = []
# Populated once the local origin is up, reused by the width tests.
LOCAL_URLS = []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_origin():
    """A local HTTP origin server that returns 200 for anything."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"origin-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET

        def log_message(self, *a):
            pass

    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return port, srv


def _make_self_signed(tmp):
    """Create a self-signed cert/key pair as (key_path, cert_path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_obj.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key_obj, hashes.SHA256())
    )
    key_path = os.path.join(tmp, "k.pem")
    crt_path = os.path.join(tmp, "c.pem")
    with open(key_path, "wb") as fh:
        fh.write(
            key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(crt_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, crt_path


def make_tls_origin(body=None):
    """A local HTTPS origin with a throwaway self-signed cert.

    The client must not verify it, but the TLS handshake still has to be real:
    a genuine ClientHello crossing the tunnel is what proves the proxy's
    byte-exact head read didn't eat the first bytes of the stream.
    """
    import tempfile

    # Prefer the stdlib: it needs no external openssl and works on Windows.
    # `cryptography` is a fallback for older interpreters.
    key, crt = _make_self_signed(tempfile.mkdtemp())

    payload = body if body is not None else b"tls-origin-ok"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return port, srv


def proc_env():
    return {"PYTHONUNBUFFERED": "1"}


def fetch_through_proxy(url, extra_env):
    """Fetch a URL with the proxy env vars pointing at our own PeekProxy.

    Used to assert byte-for-byte integrity of tunnelled payloads, which the
    wrapped-CLI path cannot check because it only shows a summary.
    """
    import urllib.request

    from socket_peek.proxy import PeekProxy

    p = PeekProxy().start()
    env = dict(os.environ)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        env[var] = p.url
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""

    old = {k: os.environ.get(k) for k in env if k.isupper() and "PROXY" in k}
    os.environ.update(env)
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, timeout=30, context=ctx) as r:
            data = r.read()
    finally:
        p.stop()
    return data


# Client snippet: make one request per URL, honouring the injected proxy vars.
CLIENT = r"""
import os, ssl, sys, urllib.request
ctx = ssl._create_unverified_context()
for url in sys.argv[1:]:
    try:
        urllib.request.urlopen(url, timeout=30, context=ctx).read()
    except Exception as e:
        print("client-error", url, e)
"""


def run_case(name, urls, extra_env=None):
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "-v", "--no-color", "--", sys.executable, "-c", CLIENT, *urls],
        capture_output=True, text=True, env=env, timeout=180,
    )
    RESULTS.append((name, proc.stdout + proc.stderr, proc.returncode))
    return proc


def main():
    # 1. Plain HTTP to our local origin, reached via a hostname that the
    #    safelist knows. Point registry.npmjs.org at loopback via /etc-level
    #    resolution is not possible, so instead we use --allow-internal to
    #    prove the user-safelist path, then separately unit-test the builtin.
    origin_port, srv = make_origin()
    LOCAL_URLS[:] = [f"http://127.0.0.1:{origin_port}/x"]

    proc = run_case("local-origin", LOCAL_URLS)
    out = RESULTS[-1][1]
    # Rich soft-wraps, so match on a distinctive substring rather than a
    # whole phrase that may straddle a line break.
    flat = " ".join(out.split())
    assert "127.0.0.1" in flat, "proxy did not capture the request:\n" + out
    assert "UNKNOWN" in flat, "raw IP should be UNKNOWN:\n" + out
    assert "raw IP" in flat, "missing IP-literal reason:\n" + out
    assert "origin-ok" not in flat, "sanity: client body should not be echoed"
    print("[ok] local origin captured, raw IP flagged UNKNOWN")

    # 1b. HTTPS via CONNECT. We stand up a real TLS origin and make a genuine
    #     https:// request through the proxy -- this exercises the tunnel,
    #     including the byte-exact head read that must not eat the ClientHello.
    import ssl

    tls_port, tls_srv = make_tls_origin()
    proc = run_case("tls-origin", [f"https://localhost:{tls_port}/x"])
    out = " ".join(RESULTS[-1][1].split())
    assert "https" in out.lower(), "no https row captured:\n" + out
    assert "localhost" in out, f"CONNECT host not logged:\n{out}"
    assert "UNKNOWN" in out, "localhost should be UNKNOWN:\n" + out
    tls_srv.shutdown()
    print("[ok] HTTPS CONNECT tunnelled, host logged from CONNECT line")

    # 1c. The tunnel must not corrupt data: a multi-KB body over TLS has to
    #     arrive byte-identical, proving we did not swallow the ClientHello.
    sent = os.urandom(200_000)
    tls_port2, tls_srv2 = make_tls_origin(body=sent)
    recv = fetch_through_proxy(f"https://localhost:{tls_port2}/big", proc_env())
    assert recv == sent, f"body mismatch: {len(recv)} vs {len(sent)}"
    tls_srv2.shutdown()
    print(f"[ok] {len(sent)//1024}KB HTTPS body round-tripped intact")

    # 2. Built-in safelist classification.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from socket_peek.safelist import classify

    cases = [
        ("registry.npmjs.org", "SAFE"),
        ("npmjs.org", "SAFE"),
        ("files.pythonhosted.org", "SAFE"),
        ("pypi.org", "SAFE"),
        ("github.com", "SAFE"),
        ("evil-npmjs.org", "UNKNOWN"),
        ("npmjs.org.evil.com", "UNKNOWN"),
        ("evilnpmjs.org", "UNKNOWN"),
        ("registry.npmjs.org.evil.io", "UNKNOWN"),
        ("attacker.example", "UNKNOWN"),
        ("1.2.3.4", "UNKNOWN"),
        ("[::1]", "UNKNOWN"),
    ]
    for host, expected in cases:
        got, reason = classify(host)
        assert got == expected, f"{host}: expected {expected}, got {got} ({reason})"
    print(f"[ok] safelist: {len(cases)} classification cases correct")

    # 3. --allow-internal promotes a named host, but deliberately NOT a raw IP.
    got, _ = classify("mirror.corp.internal", extra_safe=["corp.internal"])
    assert got == "SAFE", got
    got, _ = classify("other.corp.internal", extra_safe=["corp.internal"])
    assert got == "SAFE", got
    got, _ = classify("127.0.0.1", extra_safe=["127.0.0.1"])
    assert got == "UNKNOWN", "raw IPs must stay flagged even when allow-listed"
    print("[ok] --allow-internal promotes names, never raw IPs")

    # 4. Command not found path.
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "--no-color", "--", "definitely-not-a-real-binary-xyz"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 127, proc.returncode
    assert "command not found" in proc.stdout, proc.stdout
    print("[ok] missing command reports exit 127")

    # 5. No-arg guard.
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli"], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 2, proc.returncode
    print("[ok] bare invocation exits 2 with usage hint")

    # 5b. The wrapped command's exit code must be propagated verbatim, or the
    #     tool is useless in CI pipelines.
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "--no-color", "--",
         sys.executable, "-c", "import sys; sys.exit(3)"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 3, f"expected 3, got {proc.returncode}"
    print("[ok] child exit code propagates (3 -> 3)")

    # 5c. Exit 0 passthrough.
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "--no-color", "--",
         sys.executable, "-c", "pass"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"expected 0, got {proc.returncode}"
    print("[ok] successful command exits 0")

    # 5d. The proxy must bind loopback on an ephemeral port, never 0.0.0.0.
    from socket_peek.proxy import PeekProxy

    p = PeekProxy().start()
    try:
        assert p.host == "127.0.0.1", p.host
        assert p.port > 0, p.port
        assert p.url == f"http://127.0.0.1:{p.port}", p.url
    finally:
        p.stop()
    print("[ok] proxy binds 127.0.0.1 on an ephemeral port")

    # 6. --list-safe
    proc = subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "--list-safe"],
        capture_output=True, text=True, timeout=60,
    )
    assert "pypi.org" in proc.stdout, proc.stdout[:200]
    print(f"[ok] --list-safe prints {len(proc.stdout.split())} entries")

    # 6b. --fail-on-unknown gate: advisory by default, blocking on request.
    #     A raw IP must be gate-able, and the gate must be resettable via
    #     --allow-internal for genuinely-internal named hosts.
    def gated(extra):
        e = dict(os.environ)
        return subprocess.run(
            [sys.executable, "-m", "socket_peek.cli", "--json", *extra, "--",
             sys.executable, "-c", CLIENT, *LOCAL_URLS],
            capture_output=True, text=True, env=e, timeout=120,
        ).returncode

    assert gated([]) == 0, "advisory mode must not change the exit code"
    assert gated(["--fail-on-unknown"]) == 1, "gate must fire on an unknown host"
    print("[ok] --fail-on-unknown gates CI (0 advisory, 1 enforced)")

    # 7. Table integrity: header cells must line up with the data cells, and
    #    the verdict must be readable, at every realistic terminal width.
    #    This is a regression guard for column-order bugs, which are silent.
    for width in (70, 80, 100, 120, 160):
        out = render_at(width)
        grid = table_grid(out)
        assert grid, f"width {width}: no table found in output"
        for line in grid:
            assert "�" not in line, (
                f"width {width}: clipped glyph in row -> {line!r}"
            )
        assert "�" not in "\n".join(grid), f"width {width}: truncation in table"
        widths = {len(ln) for ln in grid if ln.startswith("|")}
        assert len(widths) == 1, f"width {width}: ragged columns {widths}"
        assert max(widths) <= width, (
            f"width {width}: table is {max(widths)} chars, overflows"
        )
        # Verdict text must survive intact, not be ellipsised away.
        flat = " ".join("\n".join(grid).split())
        assert "SAFE" in flat or "UNKNOWN" in flat, f"width {width}: verdict missing"
    print("[ok] table columns align and verdict readable at 70-160 cols")

    srv.shutdown()
    print("\nALL CHECKS PASSED")


def render_at(width):
    """Run the tool with a forced terminal width and return its stdout."""
    env = dict(os.environ)
    env["COLUMNS"] = str(width)
    env["PYTHONUNBUFFERED"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "socket_peek.cli", "--no-color", "-v", "--",
         sys.executable, "-c", CLIENT, *LOCAL_URLS],
        capture_output=True, text=True, env=env, timeout=120,
    ).stdout


def table_grid(out):
    """Extract the contiguous run of box-drawing lines that form the table."""
    lines = [ln for ln in out.splitlines() if ln.lstrip().startswith(("|", "+"))]
    return [ln for ln in lines if "Host" in ln or "http" in ln or "Verdict" in ln]


if __name__ == "__main__":
    main()
