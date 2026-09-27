"""Check the --json report is valid, parseable, and free of contamination."""

import json
import os
import subprocess
import sys
import threading
import http.server
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify

port, srv = verify.make_origin()
url = f"http://127.0.0.1:{port}/x"

env = dict(os.environ)
env["COLUMNS"] = "120"
proc = subprocess.run(
    [sys.executable, "-m", "socket_peek.cli", "--json", "--",
     sys.executable, "-c", verify.CLIENT, url],
    capture_output=True, text=True, env=env, timeout=120,
)

failures = []
if proc.returncode != 0:
    failures.append(f"exit {proc.returncode}")

try:
    data = json.loads(proc.stdout)
except json.JSONDecodeError as exc:
    print("[FAIL] stdout is not valid JSON:", exc)
    print("stdout was:", repr(proc.stdout[:400]))
    raise SystemExit(1)
print("[ok] stdout parses as strict JSON (no progress text mixed in)")

for key in ("tool", "version", "command", "exit_code", "summary", "hosts"):
    if key not in data:
        failures.append(f"missing key: {key}")
print("[ok] required top-level keys present")

if data["summary"]["unique_hosts"] != len(data["hosts"]):
    failures.append("unique_hosts disagrees with hosts[] length")
if data["summary"]["unknown"] != 1:
    failures.append(f"expected 1 unknown, got {data['summary']['unknown']}")
if not data["hosts"][0]["verdict"] == "UNKNOWN":
    failures.append("raw IP host should be UNKNOWN")
if not data["hosts"][0]["ips"]:
    failures.append("resolved IP missing")
print("[ok] summary is internally consistent")

if "running:" in proc.stdout:
    failures.append("progress line leaked into JSON output")
if "\u2502" in proc.stdout:
    failures.append("box-drawing leaked into JSON output")
print("[ok] no table/spinner contamination")

srv.shutdown()
if failures:
    print("\nFAILURES:")
    for f in failures:
        print("  - " + f)
    raise SystemExit(1)
print("\nJSON REPORT CHECKS PASSED")
