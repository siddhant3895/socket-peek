"""Command-line entry point for socket-peek.

Wraps an arbitrary command in the logging proxy, injects the standard proxy
environment variables into its environment, runs it, then reports every host it
contacted.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Sequence, Tuple

from rich import box as rich_box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .proxy import Event, PeekProxy
from .safelist import SAFE, UNKNOWN, classify, classify_detail, safe_hosts

GREEN = "green"
YELLOW = "yellow"

# Env vars that make a client honour an HTTP proxy. Both cases are set: some
# tools read the lowercase form, some the uppercase, some either.
PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)

# Tools that need a nudge beyond the standard variables. git already honours
# `http_proxy`/`https_proxy` from the environment, so it needs no special case.
EXTRA_PROXY_VARS = {
    "npm": ("npm_config_proxy", "npm_config_https_proxy"),
    "yarn": ("npm_config_proxy", "npm_config_https_proxy"),
    "pnpm": ("npm_config_proxy", "npm_config_https_proxy"),
}


def console_width() -> int:
    """Usable terminal width, defaulting to 100 when it cannot be determined.

    Falls back to a sane width rather than the terminal's reported 0/None so
    the table is still readable when output is piped.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            width = shutil.get_terminal_size(fallback=(100, 24)).columns
            if width and width > 40:
                return width
        except Exception:
            continue
    return 100


def unicode_safe(console: Console) -> bool:
    """True when the output stream can actually encode the glyphs we use.

    Legacy Windows consoles (cp1252) cannot encode the spinner or heavy box
    drawing, and rich will happily try -- producing a UnicodeEncodeError
    mid-report. We probe rather than guess, since the code page is not
    discoverable from Python.
    """
    stream = console.file
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "\u2502\u256d\u2819".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def human_bytes(num: int) -> str:
    """Format a byte count compactly for the report."""
    if num < 1024:
        return f"{num} B"
    for unit in ("KB", "MB", "GB"):
        num /= 1024.0
        if num < 1024:
            return f"{num:.1f} {unit}"
    return f"{num:.1f} TB"


def aggregate(
    events: Sequence[Event], extra_safe: Sequence[str]
) -> "OrderedDict[Tuple[str, int], Dict[str, object]]":
    """Collapse per-connection events into one row per host:port.

    A package install opens dozens of connections to the same registry; one
    summary row per host is what a reviewer actually scans.
    """
    rows: "OrderedDict[Tuple[str, int], Dict[str, object]]" = OrderedDict()
    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.host, event.port)
        if key not in rows:
            verdict, reason = classify(event.host, extra_safe)
            rows[key] = {
                "host": event.host,
                "port": event.port,
                "scheme": event.scheme,
                "ips": set(),
                "conns": 0,
                "methods": set(),
                "statuses": set(),
                "bytes": 0,
                "verdict": verdict,
                "reason": reason,
                "errors": [],
                "first": event.timestamp,
                "last": event.timestamp,
            }
        row = rows[key]
        row["conns"] = int(row["conns"]) + 1
        row["last"] = event.timestamp
        row["bytes"] = int(row["bytes"]) + event.bytes_sent + event.bytes_received
        if event.ip:
            row["ips"].add(event.ip)  # type: ignore[union-attr]
        if event.method:
            row["methods"].add(event.method)  # type: ignore[union-attr]
        if event.status:
            row["statuses"].add(event.status)  # type: ignore[union-attr]
        if event.error:
            row["errors"].append(event.error)  # type: ignore[union-attr]

    # Swap in the long-form reason now that rows are final, so the table can
    # show a compact label while a detail listing can show the explanation.
    for row in rows.values():
        row["reason_long"] = classify_detail(str(row["host"]), extra_safe)[1]
    return rows


def build_table(
    rows: "OrderedDict[Tuple[str, int], Dict[str, object]]",
    verbose: bool,
    line_box=None,
) -> Table:
    """Render the traffic table: known-safe hosts first, then everything else.

    Column set is chosen from the actual terminal width, because the IP and
    Reason columns are the first things worth dropping when space is tight and
    the first things a reviewer wants when it is not.
    """
    table = Table(
        title="Network activity",
        title_style="bold",
        header_style="bold",
        border_style="dim",
        expand=False,
        box=line_box,
        pad_edge=False,
    )
    width = console_width()
    # Budget the columns against the real terminal width. The core row needs
    # ~64 chars; IP + Reason add ~40. Below the threshold we drop them rather
    # than let rich clip the verdict -- a clipped verdict is the one column
    # that must never be unreadable, and the long-form reason is still printed
    # in the detail listing under the table.
    narrow = width < 118

    # --verbose widens the host column, which is where long internal names
    # actually get truncated. Only when there is spare room: rich does not
    # shrink a `min_width` to fit, so asking for 28 in a 70-column terminal
    # would push the verdict off the right edge.
    table.add_column(
        "Host",
        style="bold cyan",
        no_wrap=True,
        min_width=(28 if verbose and not narrow else 12),
        overflow="ellipsis",
    )
    table.add_column("Port", justify="right", no_wrap=True)
    table.add_column("Scheme" if not narrow else "Sch", style="dim", no_wrap=True)
    table.add_column("Reqs", justify="right", no_wrap=True)
    table.add_column(
        "Transferred" if not narrow else "Bytes", justify="right", no_wrap=True
    )
    if not narrow:
        table.add_column("IP", style="dim", overflow="ellipsis", no_wrap=True)
        table.add_column("Reason", style="dim", overflow="ellipsis", no_wrap=True)
    # Declared last and appended last, so a row always lines up with its header.
    # Verdict on the right edge means the eye lands on it after scanning the host.
    table.add_column("Verdict", no_wrap=True)

    # Sort unknown-first so anything suspicious is the first thing read.
    ordered = sorted(
        rows.values(),
        key=lambda r: (r["verdict"] == SAFE, str(r["host"])),
    )

    for row in ordered:
        verdict = str(row["verdict"])
        colour = GREEN if verdict == SAFE else YELLOW
        icon = "SAFE" if verdict == SAFE else "UNKNOWN"

        # Compact label in the table. The long-form reason is printed in the
        # detail listing below, and can be far too long to sit in a column
        # without pushing the verdict off the edge of the terminal.
        reason = str(row["reason"])
        # ASCII ellipsis, not "…": the latter is unencodable on a cp1252
        # console and would raise mid-render.
        if len(reason) > 18:
            reason = reason[:15] + "..."
        cells: List[object] = [
            str(row["host"]),
            str(row["port"]),
            str(row["scheme"]),
            str(row["conns"]),
            human_bytes(int(row["bytes"])),
        ]
        if not narrow:
            ips = row["ips"]
            cells.append(", ".join(sorted(ips)) if ips else "-")  # type: ignore[arg-type]
            cells.append(reason)
        cells.append(Text(icon, style=f"bold {colour}"))
        table.add_row(*cells)

    return table


def build_summary(
    rows: "OrderedDict[Tuple[str, int], Dict[str, object]]",
    events: Sequence[Event],
    command: str,
    exit_code: Optional[int],
    duration: float,
    signalled: bool,
    line_box=None,
) -> Panel:
    """Headline counts plus the command's own result."""
    safe = sum(1 for r in rows.values() if r["verdict"] == SAFE)
    unknown = len(rows) - safe
    total_bytes = sum(int(r["bytes"]) for r in rows.values())

    verdict_line = Text()
    verdict_line.append(f"{safe} known-safe", style=f"bold {GREEN}")
    verdict_line.append("  |  ", style="dim")
    verdict_line.append(f"{unknown} unknown", style=f"bold {YELLOW}")

    body = Group(
        Text(f"$ {command}", style="bold"),
        Text(""),
        Text.assemble(
            ("exit code  ", "dim"),
            (
                "interrupted by signal" if signalled else str(exit_code),
                "yellow" if signalled else "green",
            ),
            ("    duration  ", "dim"),
            (f"{duration:.2f}s", ""),
            ("    connections  ", "dim"),
            (str(len(events)), ""),
            ("    transferred  ", "dim"),
            (human_bytes(total_bytes), ""),
        ),
        Text(""),
        verdict_line,
    )

    border = YELLOW if unknown else GREEN
    return Panel(
        body,
        title="socket-peek",
        border_style=border,
        padding=(1, 2),
        box=line_box,
    )


def build_json(
    rows: "OrderedDict[Tuple[str, int], Dict[str, object]]",
    command: str,
    exit_code: Optional[int],
    duration: float,
    signalled: bool,
) -> str:
    """Machine-readable report for CI gates and diffing across runs."""
    hosts = []
    for row in rows.values():
        hosts.append(
            {
                "host": row["host"],
                "port": row["port"],
                "scheme": row["scheme"],
                "ips": sorted(row["ips"]),  # type: ignore[arg-type]
                "requests": row["conns"],
                "bytes": row["bytes"],
                "verdict": row["verdict"],
                "reason": row["reason_long"],
                "errors": list(row["errors"]),  # type: ignore[arg-type]
                "first_seen": round(float(row["first"]), 3),  # type: ignore[arg-type]
                "last_seen": round(float(row["last"]), 3),  # type: ignore[arg-type]
            }
        )
    report = {
        "tool": "socket-peek",
        "version": __version__,
        "command": command,
        "exit_code": exit_code,
        "signalled": signalled,
        "duration_seconds": round(duration, 3),
        "summary": {
            "unique_hosts": len(rows),
            "safe": sum(1 for r in rows.values() if r["verdict"] == SAFE),
            "unknown": sum(1 for r in rows.values() if r["verdict"] == UNKNOWN),
            "total_bytes": sum(int(r["bytes"]) for r in rows.values()),
        },
        "hosts": hosts,
    }
    return json.dumps(report, indent=2)


def build_legend(console: Console) -> None:
    legend = Text()
    legend.append("VERDICT  ", style="dim bold")
    legend.append("SAFE", style=f"bold {GREEN}")
    legend.append(" = recognised developer registry", style="dim")
    legend.append("   ")
    legend.append("UNKNOWN", style=f"bold {YELLOW}")
    legend.append(" = anything else, including raw IPs", style="dim")
    console.print(legend)


def build_proxy_env(
    proxy_url: str, base_env: Dict[str, str], command: Sequence[str]
) -> Dict[str, str]:
    """Copy the environment and point every proxy variable at our listener.

    `NO_PROXY` is deliberately cleared: a pre-existing `NO_PROXY` containing
    `localhost` is fine, but one containing an internal mirror would silently
    exclude a host from the audit. Use `--keep-no-proxy` to preserve it.
    """
    env = dict(base_env)
    for var in PROXY_VARS:
        env[var] = proxy_url

    exe = os.path.basename(command[0]).lower() if command else ""
    exe = exe.replace(".exe", "")
    for name in EXTRA_PROXY_VARS.get(exe, ()):
        env[name] = proxy_url
    return env


def install_signal_handlers() -> None:
    """Make Ctrl-C and Ctrl-Break raise `KeyboardInterrupt` in our process.

    On Windows, Python installs a default handler for SIGINT but *not* for
    SIGBREAK, and a terminal Ctrl-Break arrives as SIGBREAK. Without this, the
    process is killed outright by the OS and the report -- the entire point of
    the tool -- is never printed.
    """
    for name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, lambda *_a: (_ for _ in ()).throw(KeyboardInterrupt()))
        except (ValueError, OSError, RuntimeError):
            # Not the main thread, or the platform refuses. KeyboardInterrupt
            # from SIGINT still works as a fallback.
            pass


def run_command(
    command: Sequence[str], env: Dict[str, str], console: Console
) -> Tuple[Optional[int], bool, float]:
    """Run the wrapped command, forwarding Ctrl-C to it as well as to us.

    Returns `(exit_code, signalled, duration)`. `exit_code` is None if the
    command was killed by a signal.
    """
    # Put the child in its own process group so a terminal Ctrl-C reaches it
    # directly instead of us having to relay it.
    kwargs: Dict[str, object] = {}
    if hasattr(os, "setsid"):
        kwargs["start_new_session"] = True

    install_signal_handlers()
    start = time.time()
    try:
        process = subprocess.Popen(list(command), env=env, **kwargs)  # type: ignore[arg-type]
    except FileNotFoundError:
        console.print(f"[bold red]error:[/] command not found: {command[0]}")
        return 127, False, time.time() - start
    except OSError as exc:
        console.print(f"[bold red]error:[/] failed to launch: {exc}")
        return 127, False, time.time() - start

    signalled = False
    try:
        process.wait()
    except KeyboardInterrupt:
        signalled = True
        console.print("\n[yellow]interrupted -- terminating child...[/]")
        _terminate(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        duration = time.time() - start

    code = process.returncode
    if signalled:
        # 128 + SIGINT is the conventional shell code for "died on a signal",
        # and it keeps CI from reading an interrupt as success.
        return 130, True, duration
    exit_code = code if code is not None and code >= 0 else None
    return exit_code, signalled, duration


def _terminate(process: subprocess.Popen) -> None:
    """Best-effort graceful shutdown of the child and its group.

    A package manager mid-install often has grandchildren (`git`, `node-gyp`),
    so on Windows we signal the whole process group rather than just the
    direct child, which would otherwise leave those running.
    """
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError, ProcessLookupError):
            try:
                process.terminate()
            except OSError:
                pass
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="socket-peek",
        description=(
            "Run a command behind a logging proxy and audit the network "
            "destinations it contacts."
        ),
        epilog=(
            "examples:\n"
            "  socket-peek -- npm install\n"
            "  socket-peek -v -- pip install -r requirements.txt\n"
            "  socket-peek --allow-internal git clone https://git.corp/repo\n"
            "  socket-peek --list-safe\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"socket-peek {__version__}"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="use full hostnames and IP lists instead of truncating them",
    )
    parser.add_argument(
        "--allow-internal",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="treat DOMAIN (and subdomains) as safe; repeatable",
    )
    parser.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help=(
            "exit non-zero when any unrecognised host was contacted, so a "
            "supply-chain check can gate a build"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report on stdout instead of a table",
    )
    parser.add_argument(
        "--keep-no-proxy",
        action="store_true",
        help="preserve the existing NO_PROXY/no_proxy values",
    )
    parser.add_argument(
        "--list-safe",
        action="store_true",
        help="print the built-in safelist and exit",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour (also honours NO_COLOR)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command to run, after `--`",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    if args.list_safe:
        for host in safe_hosts():
            print(host)
        return 0

    command: List[str] = [c for c in args.command]
    # argparse.REMAINDER keeps the leading `--`; drop it.
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: no command given. Try: socket-peek -- npm install", file=sys.stderr)
        return 2

    console = Console(no_color=args.no_color, soft_wrap=False)
    ascii_only = not unicode_safe(console)
    display = " ".join(command)
    if len(display) > 76:
        display = display[:73] + "..."

    try:
        proxy = PeekProxy().start()
    except OSError as exc:
        console.print(f"[bold red]error:[/] could not start proxy: {exc}")
        return 1

    env = build_proxy_env(proxy.url, dict(os.environ), command)
    if not args.keep_no_proxy:
        env.pop("NO_PROXY", None)
        env.pop("no_proxy", None)

    # A live spinner needs a TTY and an encodable glyph; fall back to a plain
    # line when either is missing so piped/CI output stays clean. With --json
    # we stay silent, because stdout is reserved for the report.
    if args.json:
        exit_code, signalled, duration = run_command(command, env, console)
    elif console.is_terminal and not ascii_only:
        with console.status(f"[dim]running:[/] {display}", spinner="dots"):
            exit_code, signalled, duration = run_command(command, env, console)
    else:
        console.print(f"[dim]running:[/] {display}")
        exit_code, signalled, duration = run_command(command, env, console)

    # The proxy is stopped before we read events so late connections either
    # land in the table or are genuinely dropped, not silently pending. Joined
    # explicitly so no accept thread is still running at interpreter exit,
    # which on Windows surfaces as a threading-shutdown traceback.
    time.sleep(0.2)
    events = proxy.recorder.snapshot()
    proxy.stop(join_threads=True)

    rows = aggregate(events, args.allow_internal)

    unknown = [r for r in rows.values() if r["verdict"] == UNKNOWN]

    if args.json:
        # JSON goes to stdout alone so it can be piped into jq without the
        # table and progress output contaminating it.
        print(build_json(rows, " ".join(command), exit_code, duration, signalled))
        if unknown and args.fail_on_unknown:
            return 1
        return exit_code if exit_code is not None else 0

    line_box = rich_box.ASCII if ascii_only else None

    console.print()
    console.print(
        build_summary(rows, events, display, exit_code, duration, signalled, line_box)
    )
    console.print()
    if rows:
        console.print(build_table(rows, args.verbose, line_box))
    else:
        console.print(
            Panel(
                Text(
                    "No network traffic captured.\n\n"
                    "The command may have used a cached/offline path, or the "
                    "tool may not honour the standard proxy variables.",
                    style="dim",
                ),
                border_style="yellow",
                title="no traffic",
                padding=(1, 2),
                box=line_box,
            )
        )
    console.print()

    if unknown:
        detail = Table(
            box=None, show_header=False, pad_edge=False, expand=True
        )
        detail.add_column("Host", style="yellow", no_wrap=True)
        detail.add_column("Why", style="dim", overflow="fold")
        for row in unknown:
            detail.add_row(str(row["host"]), str(row["reason_long"]))
        console.print(detail)
        console.print(
            Text(
                f"review {len(unknown)} unrecognised destination(s); "
                "re-run with --allow-internal to silence known ones",
                style=f"bold {YELLOW}",
            )
        )
    console.print()
    build_legend(console)
    console.print()
    console.print(
        Text(
            "note: HTTPS hosts are logged from the CONNECT line. "
            "Payloads are never decrypted.",
            style="dim italic",
        )
    )
    if unknown and args.fail_on_unknown:
        console.print(
            Text(
                f"failing: {len(unknown)} unrecognised destination(s) and "
                f"--fail-on-unknown was set",
                style=f"bold {YELLOW}",
            )
        )
        return 1
    if unknown:
        # Findings are advisory by default, so the child's own exit code wins
        # -- a failing `npm install` must stay a failing `npm install` in CI.
        console.print(
            Text(
                "tip: --fail-on-unknown exits non-zero on any unrecognised "
                "host, for CI gating.",
                style="dim",
            )
        )
    return exit_code if exit_code is not None else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
