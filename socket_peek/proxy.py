"""Transparent logging HTTP/HTTPS forward proxy.

Design notes
------------
* **No TLS interception.** For `https://` we only ever see the `CONNECT
  host:port` line, which is in cleartext, then we blind-tunnel the TLS bytes.
  We never install a CA and never see plaintext payloads. That keeps the tool
  safe to run against real traffic, and it is enough to answer the question an
  auditor actually asks: *which hosts did this process talk to?*

* **Byte-exact head reads.** We read the request head manually instead of using
  `socket.makefile`, because buffering would happily over-read past the
  `\\r\\n\\r\\n` boundary and eat the first TLS ClientHello bytes. Whatever we
  over-read is captured and replayed into the tunnel.

* **Thread per connection.** Package managers open many parallel connections;
  a thread-per-connection model with daemon threads keeps this simple and
  avoids a central event loop starving slow sockets.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Tunables -- generous by default so a slow/hung command doesn't look clean
# just because its sockets went quiet.
CONNECT_TIMEOUT = 15.0
IDLE_TIMEOUT = 300.0
MAX_HEAD_BYTES = 64 * 1024
RECV_CHUNK = 64 * 1024
MAX_CONNECTIONS = 512


@dataclass
class Event:
    """One observed outbound connection."""

    timestamp: float
    method: str
    scheme: str
    host: str
    port: int
    ip: Optional[str] = None
    status: Optional[int] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    error: Optional[str] = None

    @property
    def authority(self) -> str:
        """`host:port`, collapsing the default port for readability."""
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"


class Recorder:
    """Thread-safe, append-only store of `Event`s."""

    def __init__(self) -> None:
        self._events: List[Event] = []
        self._lock = threading.Lock()

    def add(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> List[Event]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def _read_head(sock: socket.socket) -> Tuple[bytes, bytes]:
    """Read up to and including the first blank line.

    Returns `(head, leftover)`. `leftover` is anything we over-read past the
    header terminator -- for CONNECT that is usually the start of the TLS
    handshake, and dropping it would break the tunnel.
    """
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEAD_BYTES:
            raise ValueError("request head too large")
        chunk = sock.recv(RECV_CHUNK)
        if not chunk:
            break
        buf += chunk
    if not buf:
        return b"", b""
    head, _, leftover = bytes(buf).partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", leftover


def _parse_head(head: bytes) -> Tuple[str, str, str, Dict[str, str]]:
    """Split a head into `(method, target, version, headers)` (lowercased keys)."""
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ")
    method = parts[0].upper() if len(parts) > 0 else ""
    target = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return method, target, version, headers


def _split_authority(authority: str, default_port: int) -> Tuple[str, int]:
    """Split `host:port`, honouring bracketed IPv6 literals."""
    authority = authority.strip()
    if authority.startswith("["):
        host, _, rest = authority.partition("]")
        host = host[1:]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        # A bare IPv6 literal that lost its brackets has several colons; only
        # treat the trailing segment as a port if it is actually numeric.
        if port.isdigit() and ":" not in host:
            return host, int(port)
    return authority, default_port


def _resolve(host: str, port: int) -> Tuple[Optional[socket.socket], Optional[str]]:
    """Connect to `host:port`, returning `(socket, resolved_ip)`."""
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"
    last_error: Optional[str] = None
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect(sockaddr)
            sock.settimeout(None)
            return sock, sockaddr[0]
        except OSError as exc:
            last_error = str(exc)
            sock.close()
    return None, last_error or "connection failed"


def _pump(
    client: socket.socket,
    upstream: socket.socket,
    client_leftover: bytes = b"",
    upstream_leftover: bytes = b"",
    idle_timeout: float = IDLE_TIMEOUT,
) -> Tuple[int, int]:
    """Blindly relay bytes both ways until both directions close.

    Implements half-close properly: when one side EOFs we `shutdown(SHUT_WR)`
    the other so it learns about the end of stream, then keep pumping the
    reverse direction rather than tearing the connection down early.
    """
    sent = recv = 0

    if client_leftover:
        upstream.sendall(client_leftover)
        sent += len(client_leftover)
    if upstream_leftover:
        client.sendall(upstream_leftover)
        recv += len(upstream_leftover)

    client_open, upstream_open = True, True
    while client_open or upstream_open:
        watch = [s for s, is_open in ((client, client_open), (upstream, upstream_open)) if is_open]
        if not watch:
            break
        try:
            readable, _, errored = select.select(watch, [], watch, idle_timeout)
        except (OSError, ValueError):
            break
        if errored:
            break
        if not readable:
            # Idle window elapsed. Once either direction has already closed we
            # treat the silence as end-of-stream; otherwise keep waiting, since
            # a slow download can legitimately sit quiet between reads.
            if not client_open or not upstream_open:
                break
            continue

        for sock in readable:
            if sock is client:
                dst, src_open, dst_open = upstream, "client", "upstream"
            else:
                dst, src_open, dst_open = client, "upstream", "client"
            try:
                data = sock.recv(RECV_CHUNK)
            except OSError:
                data = b""
            if not data:
                if src_open == "client":
                    client_open = False
                else:
                    upstream_open = False
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                dst.sendall(data)
            except OSError:
                return sent, recv
            if src_open == "client":
                sent += len(data)
            else:
                recv += len(data)
    return sent, recv


class PeekProxy:
    """A threaded HTTP/HTTPS forward proxy that records what it forwards."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.requested_port = port
        self.recorder = Recorder()
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._active = 0
        self._active_lock = threading.Lock()
        self._threads: List[threading.Thread] = []

    # -- lifecycle ------------------------------------------------------
    def start(self) -> "PeekProxy":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.requested_port))
        sock.listen(128)
        sock.settimeout(0.5)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(
            target=self._accept_loop, name="socket-peek-accept", daemon=True
        )
        self._thread.start()
        return self

    def stop(self, join_threads: bool = False) -> None:
        """Stop accepting. With `join_threads`, also drain in-flight handlers."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        if join_threads:
            # Daemon handler threads would otherwise still be running at
            # interpreter shutdown, which prints a confusing traceback.
            for thread in list(self._threads):
                thread.join(timeout=1.0)

    def __enter__(self) -> "PeekProxy":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- accept ---------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._active_lock:
                if self._active >= MAX_CONNECTIONS:
                    conn.close()
                    continue
                self._active += 1
                thread = threading.Thread(
                    target=self._handle_guarded, args=(conn,), daemon=True
                )
                self._threads.append(thread)
            thread.start()

    def _handle_guarded(self, conn: socket.socket) -> None:
        try:
            self._handle(conn)
        except Exception:
            pass
        finally:
            with self._active_lock:
                self._active -= 1
            try:
                conn.close()
            except OSError:
                pass

    # -- request handling ----------------------------------------------
    def _handle(self, client: socket.socket) -> None:
        client.settimeout(CONNECT_TIMEOUT)
        try:
            head, leftover = _read_head(client)
        except (OSError, ValueError):
            return
        if not head:
            return

        try:
            method, target, _version, headers = _parse_head(head)
        except Exception:
            self._error_response(client)
            return

        if method == "CONNECT":
            self._handle_connect(client, target, leftover)
        else:
            self._handle_http(client, method, target, headers, head, leftover)

    def _error_response(self, client: socket.socket) -> None:
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
        except OSError:
            pass

    def _handle_connect(
        self, client: socket.socket, target: str, leftover: bytes
    ) -> None:
        host, port = _split_authority(target, 443)
        if not host:
            self._error_response(client)
            return

        upstream, ip = _resolve(host, port)
        if upstream is None:
            self.recorder.add(
                Event(
                    timestamp=time.time(),
                    method="CONNECT",
                    scheme="https",
                    host=host,
                    port=port,
                    error=ip,
                )
            )
            self._error_response(client)
            return

        try:
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: socket-peek\r\n\r\n"
            )
        except OSError:
            upstream.close()
            return

        try:
            sent, received = _pump(client, upstream, client_leftover=leftover)
        except OSError:
            sent = received = 0
        finally:
            try:
                upstream.close()
            except OSError:
                pass

        self.recorder.add(
            Event(
                timestamp=time.time(),
                method="CONNECT",
                scheme="https",
                host=host,
                port=port,
                ip=ip,
                status=200,
                bytes_sent=sent,
                bytes_received=received,
            )
        )

    def _handle_http(
        self,
        client: socket.socket,
        method: str,
        target: str,
        headers: Dict[str, str],
        head: bytes,
        leftover: bytes,
    ) -> None:
        # Absolute-form is what a client sends to a real proxy; origin-form
        # means it ignored us, in which case the Host header is our only clue.
        if target.lower().startswith("http://"):
            rest = target[7:]
            authority, _, path = rest.partition("/")
            path = "/" + path if path else "/"
            host, port = _split_authority(authority, 80)
        else:
            path = target
            host, port = _split_authority(headers.get("host", ""), 80)
        if not host:
            self._error_response(client)
            return

        upstream, ip = _resolve(host, port)
        if upstream is None:
            self.recorder.add(
                Event(
                    timestamp=time.time(),
                    method=method,
                    scheme="http",
                    host=host,
                    port=port,
                    error=ip,
                )
            )
            self._error_response(client)
            return

        # Rebuild the head as an origin-form request: drop proxy-specific
        # headers and force `Connection: close` so each exchange terminates
        # cleanly instead of leaving us guessing at body boundaries.
        lines = head.decode("latin-1").split("\r\n")
        rebuilt = [f"{method} {path} HTTP/1.1"]
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in ("proxy-connection", "proxy-authorization", "connection"):
                continue
            rebuilt.append(line)
        rebuilt.append(f"Host: {host}")
        rebuilt.append("Connection: close")

        status: Optional[int] = None
        try:
            upstream.sendall("\r\n".join(rebuilt).encode("latin-1") + b"\r\n\r\n")
            if leftover:
                upstream.sendall(leftover)
            # Read the response head so we can log the status code. If parsing
            # it fails we must still forward the bytes we already consumed --
            # discarding them here would strip the status line off the client.
            resp_head, resp_leftover = _read_head(upstream)
            if resp_head:
                try:
                    status = int(_parse_head(resp_head)[1])
                except (ValueError, IndexError):
                    status = None
                client.sendall(resp_head)
            sent, received = _pump(
                client, upstream, client_leftover=b"", upstream_leftover=resp_leftover
            )
        except OSError as exc:
            self.recorder.add(
                Event(
                    timestamp=time.time(),
                    method=method,
                    scheme="http",
                    host=host,
                    port=port,
                    ip=ip,
                    status=status,
                    error=str(exc),
                )
            )
            return
        finally:
            try:
                upstream.close()
            except OSError:
                pass

        self.recorder.add(
            Event(
                timestamp=time.time(),
                method=method,
                scheme="http",
                host=host,
                port=port,
                ip=ip,
                status=status,
                bytes_sent=sent,
                bytes_received=received,
            )
        )
