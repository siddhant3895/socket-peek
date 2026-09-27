"""Ctrl-C handling: the report must still print and no orphans must survive."""

import os
import signal
import subprocess
import sys
import time

env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
env["COLUMNS"] = "100"

# Child announces itself, then hangs long enough to be interrupted.
child_code = "import time; print('started', flush=True); time.sleep(60)"

proc = subprocess.Popen(
    [sys.executable, "-m", "socket_peek.cli", "--no-color", "--",
     sys.executable, "-c", child_code],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    # Own process group so the interrupt targets the wrapper, not the shell.
    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
)

first = proc.stdout.readline().strip()
print("child said:", first)

time.sleep(1.0)
start = time.time()
if os.name == "nt":
    proc.send_signal(signal.CTRL_BREAK_EVENT)
else:
    proc.send_signal(signal.SIGINT)

timed_out = False
try:
    out = proc.communicate(timeout=25)[0]
except subprocess.TimeoutExpired:
    proc.kill()
    out = proc.communicate()[0]
    timed_out = True

elapsed = time.time() - start
print("elapsed: %.1fs  rc=%s" % (elapsed, proc.returncode))
print("--- tail ---")
print(out[-800:])

failures = []
if timed_out:
    failures.append("wrapper did not exit within 25s of SIGINT")
if "socket-peek" not in out:
    failures.append("report panel missing after interrupt")
if "duration" not in out:
    failures.append("summary line missing after interrupt")
if proc.returncode == 0:
    failures.append("interrupted run reported success (exit 0)")

print()
if failures:
    print("FAILURES:")
    for f in failures:
        print("  - " + f)
    raise SystemExit(1)

# Clean shutdown matters: a threading traceback on stderr is noise that would
# make real problems hard to spot in CI logs.
noise = [ln for ln in out.splitlines() if "Traceback" in ln or "Exception ignored" in ln]
if noise:
    failures.append(f"traceback on shutdown: {noise[:2]}")

if proc.returncode != 130:
    failures.append(f"expected 130 on interrupt, got {proc.returncode}")
else:
    print("[ok] interrupt exits 130 (128+SIGINT)")

if not noise:
    print("[ok] clean shutdown, no traceback")

if failures:
    print("\nFAILURES:")
    for f in failures:
        print("  - " + f)
    raise SystemExit(1)
print("INTERRUPT HANDLING OK")
