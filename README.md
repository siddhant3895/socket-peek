# socket-peek --------------

A lightweight, cross-platform supply-chain network auditor. It runs a command
behind a logging proxy and reports every host that command contacted.

```bash
pip install -e .
socket-peek -- npm install
```

## What it does

`socket-peek` starts a local HTTP/HTTPS forward proxy, injects the standard
proxy environment variables into the child process, runs your command, then
prints a table of every destination it hit, sorted so unrecognised hosts come
first.

```
+----------------------------------------------- socket-peek ----------------------------------------------+
|  $ pip install -r requirements.txt                                                                              |
|  exit code  0    duration  8.41s    connections  12    transferred  4.7 MB                                    |
|  3 known-safe  |  1 unknown                                                                                     |
+-----------------------------------------------------------------------------------------------------------------+

                                          Network activity
+-------------------------------------------------------------------------------------------------+
|Host                   | Port | Scheme | Reqs | Transferred | IP              | Reason | Verdict|
|-----------------------+------+--------+------+-------------+-----------------+--------+--------|
|files.pythonhosted.org |  443 | https  |    6 |      3.9 MB | 151.101.0.223   | pypi   | SAFE   |
|pypi.org               |  443 | https  |    5 |    412.1 KB | 151.101.192.223 | pypi   | SAFE  |
|169.254.169.254        |   80 | http   |    1 |          0 B | 169.254.169.254 | raw IP | UNKNOWN|
+-------------------------------------------------------------------------------------------------+
```

## No TLS interception

This is the central design decision, and it is deliberate.

For `https://` the proxy reads only the `CONNECT host:port` line, which is
sent in cleartext, then blind-tunnels the TLS bytes. **No CA is installed and
no payload is ever decrypted.** That keeps the tool safe to run against real
traffic, and it answers the question an audit actually asks: which hosts did
this process talk to?

If you need to see request *contents* inside HTTPS, that requires a trusted
root CA and a TLS-terminating proxy such as mitmproxy. That is a different tool
with a materially larger blast radius.

## Usage

```bash
socket-peek -- npm install
socket-peek -v -- pip install -r requirements.txt
socket-peek --allow-internal git.corp.internal -- git clone https://git.corp/repo
socket-peek --json --fail-on-unknown -- make build     # CI gate
socket-peek --list-safe
```

| Flag | Effect |
|------|--------|
| `-v, --verbose` | Wider host column, full IP lists |
| `--allow-internal DOMAIN` | Treat `DOMAIN` and its subdomains as safe. Repeatable. |
| `--fail-on-unknown` | Exit non-zero if any unrecognised host was contacted |
| `--json` | Machine-readable report on stdout, no table |
| `--keep-no-proxy` | Preserve existing `NO_PROXY` / `no_proxy` |
| `--list-safe` | Print the built-in safelist and exit |
| `--no-color` | Disable ANSI colour |

## Exit codes

The wrapped command's exit code is propagated verbatim, so a failing
`npm install` stays a failing `npm install`. Findings are advisory by default.
Use `--fail-on-unknown` to turn the audit into a gate; it exits `1` when any
unrecognised host was contacted. An interrupt exits `130` (128 + SIGINT).

## Classification

**SAFE** — matches a known developer registry, matched on a dotted boundary so
`evil-npmjs.org` and `npmjs.org.evil.com` are both rejected. Both exact
hostname and subdomain forms are accepted (`files.pythonhosted.org` is
`pythonhosted.org`'s subdomain).

**UNKNOWN** — everything else, including raw IP literals.

A raw IP is always UNKNOWN *even when passed to `--allow-internal`*. You can
silence a name you trust; you cannot silence the absence of a name. A package
manager fetching from a bare IP has already skipped name verification, so that
is the highest-signal finding the tool can produce. This includes
`169.254.169.254`, the cloud metadata endpoint — the canonical supply-chain
exfiltration path.

## Limitations

Worth understanding before relying on this:

- **Only HTTP and HTTPS.** Raw sockets, QUIC/UDP, and DNS-over-TLS do not
  traverse an HTTP proxy and are invisible. A tool that ignores the standard
  proxy variables is likewise not observed — the report will say
  "no traffic captured" rather than quietly reporting a clean run.
- **Host-level, not request-level.** You learn which hosts were contacted, not
  which URLs or what payloads.
- **CDNs share infrastructure.** A host on the safelist may front arbitrary
  tenant content. The safelist reduces noise; it is not an integrity proof.
- **DNS is resolved by us,** so the resolved IP is what was actually connected
  to, not merely what was requested.

## Tests

Four harnesses, run directly:

```bash
python verify.py              # end-to-end: HTTP, HTTPS tunnel, exit codes, table alignment
python test_adversarial.py    # suffix-boundary and lookalike-domain attacks
python test_json.py           # --json output is valid and uncontaminated
python test_interrupt.py      # Ctrl-C / Ctrl-Break handling
```

`verify.py` stands up a real TLS origin and round-trips a 195 KB body
byte-for-byte, which is what proves the tunnel's byte-exact request-head read
is not swallowing the TLS ClientHello. `test_adversarial.py` covers
`evil-npmjs.org`, `npmjs.org.evil.com`, `xn--npmjs-4ve.org` and similar.

`test_json.py` and `test_interrupt.py` need `cryptography` for the throwaway
self-signed cert. The other two are stdlib-only.

## Requirements

Python 3.9+, and `rich` for the report. Everything else is standard library.
