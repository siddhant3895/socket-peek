"""Adversarial checks: things a real attacker or a real package would do.

Focuses on the classification boundary and on cases where the tool could
silently under-report.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from socket_peek.proxy import _parse_head, _split_authority  # noqa: E402
from socket_peek.safelist import classify, classify_detail  # noqa: E402

failures = []


def check(cond, label):
    if cond:
        print("[ok] " + label)
    else:
        failures.append(label)
        print("[FAIL] " + label)


# --- suffix-boundary attacks against the safelist ------------------------
ATTACKS = [
    "evil-npmjs.org",
    "evilnpmjs.org",
    "npmjs.org.evil.com",
    "registry.npmjs.org.evil.io",
    "pypi.org.attacker.net",
    "xn--npmjs-4ve.org",
    ".npmjs.org",                      # empty leading label
    "npmjs..org",                      # empty interior label
    "sub.deep.files.pythonhosted.org.attacker.co",
    "github.com.evil.sh",
    "notgithub.com",
    "crates.io.co",
    "registry.npmjs.orgx",
]
for host in ATTACKS:
    verdict, _ = classify(host)
    check(verdict == "UNKNOWN", f"rejects lookalike: {host}")

# --- legitimate subdomains must still be safe ---------------------------
LEGIT = [
    "registry.npmjs.org",
    "files.pythonhosted.org",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "static.crates.io",
    "repo1.maven.org",
    "proxy.golang.org",
]
for host in LEGIT:
    verdict, _ = classify(host)
    check(verdict == "SAFE", f"accepts real subdomain: {host}")

# --- case / trailing-dot normalisation -----------------------------------
# A trailing dot is the DNS root, so `pypi.org.` is the same host and safe.
for variant in ("PYPI.ORG", "PyPi.Org", "pypi.org."):
    verdict, _ = classify(variant)
    check(verdict == "SAFE", f"normalises {variant!r}")

# --- raw IPs always UNKNOWN, even allow-listed ---------------------------
for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "8.8.8.8", "::1"):
    verdict, _ = classify(ip, extra_safe=[ip])
    check(verdict == "UNKNOWN", f"raw IP stays UNKNOWN: {ip}")

# 169.254.169.254 is the cloud metadata endpoint; a package manager hitting
# it is the canonical supply-chain exfil path, so flag it explicitly.
verdict, reason = classify_detail("169.254.169.254")
check(verdict == "UNKNOWN" and "IP" in reason, "flags cloud metadata IP")

# --- user safelist must not over-match ----------------------------------
check(
    classify("a.corp.internal", extra_safe=["corp.internal"])[0] == "SAFE",
    "allow-internal matches subdomain",
)
check(
    classify("corp.internal.evil.com", extra_safe=["corp.internal"])[0] == "UNKNOWN",
    "allow-internal respects dotted boundary",
)
check(
    classify("evilcorp.internal", extra_safe=["corp.internal"])[0] == "UNKNOWN",
    "allow-internal rejects prefix lookalike",
)

# --- authority parsing edge cases ---------------------------------------
check(_split_authority("example.com:443", 443) == ("example.com", 443), "authority host:port")
check(_split_authority("example.com", 443) == ("example.com", 443), "authority default port")
check(_split_authority("[::1]:8080", 443) == ("::1", 8080), "bracketed IPv6 with port")
check(_split_authority("[2606:4700::1]", 443) == ("2606:4700::1", 443), "bracketed IPv6 no port")
check(_split_authority("host:abc", 443) == ("host:abc", 443), "non-numeric port ignored")

# --- CONNECT parsing ----------------------------------------------------
method, target, version, headers = _parse_head(
    b"CONNECT files.pythonhosted.org:443 HTTP/1.1\r\nHost: files.pythonhosted.org:443\r\n\r\n"
)
check(method == "CONNECT" and target == "files.pythonhosted.org:443", "CONNECT line parsed")
check(version == "HTTP/1.1", "HTTP version parsed")

# Header name casing must be normalised, since we look up 'host'.
_, _, _, hdrs = _parse_head(b"GET http://x/ HTTP/1.1\r\nHOST: example.com\r\n\r\n")
check("host" in hdrs and hdrs["host"] == "example.com", "header lookup is case-insensitive")

# --- empty / junk input must not crash ----------------------------------
for junk in ("", "   ", "....", "a" * 500, "-", "%%%", "\x00bad"):
    try:
        classify(junk)
    except Exception as exc:  # noqa: BLE001
        check(False, f"classify({junk!r}) raised {exc!r}")
    else:
        check(True, f"classify({junk!r}) handled")

print()
if failures:
    print(f"{len(failures)} FAILURES:")
    for f in failures:
        print("  - " + f)
    raise SystemExit(1)
print("ALL ADVERSARIAL CHECKS PASSED")
