"""Domain classification for supply-chain auditing.

A host is SAFE if it matches a known developer registry (or a CDN/raw-content
host that those registries are known to serve assets from). Everything else is
UNKNOWN, which includes bare IP literals -- a package manager fetching from
`http://34.107.221.82/` has already skipped name verification, so that is
treated as maximally suspicious rather than merely unrecognised.

Matching is deliberately strict: a candidate host matches an entry only if it
equals the entry, or ends with `"." + entry`. That dotted boundary is what stops
`npmjs.org.evil.com` and `evilnpmjs.org` from being waved through as safe.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List, Tuple

# Verdicts, ordered by increasing severity.
SAFE = "SAFE"
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Rule:
    """A single classification rule.

    `host` is either an exact hostname or a suffix that any subdomain inherits.
    `reason` is surfaced in the report so a reviewer can see *why* a host was
    treated as trusted instead of having to trust a bare green icon.
    `short` is a compact label for narrow terminals; the table uses it in
    normal mode and falls back to the full reason under `--verbose`.
    """

    host: str
    reason: str
    short: str = ""


# Known-good developer infrastructure. Grouped by supplier for readability.
_SAFE_RULES: Tuple[Rule, ...] = (
    # --- JavaScript / TypeScript ---------------------------------------
    Rule("npmjs.org", "npm registry", "npm"),
    Rule("npmjs.com", "npm registry", "npm"),
    Rule("yarnpkg.com", "Yarn registry", "yarn"),
    Rule("registry.yarnpkg.com", "Yarn registry mirror", "yarn"),
    Rule("npmjs.org.ua", "npm mirror", "npm"),
    # --- Python ----------------------------------------------------------
    Rule("pypi.org", "PyPI", "pypi"),
    Rule("python.org", "Python Software Foundation", "python.org"),
    Rule("pythonhosted.org", "PyPI file storage", "pypi files"),
    Rule("files.pythonhosted.org", "PyPI file storage", "pypi files"),
    # --- Source control / code hosting ----------------------------------
    Rule("github.com", "GitHub", "github"),
    Rule("githubusercontent.com", "GitHub raw/asset CDN", "github CDN"),
    Rule("codeload.github.com", "GitHub tarball host", "github"),
    Rule("objects.githubusercontent.com", "GitHub release assets", "github CDN"),
    Rule("gitlab.com", "GitLab", "gitlab"),
    Rule("bitbucket.org", "Bitbucket", "bitbucket"),
    # --- Other language ecosystems --------------------------------------
    Rule("rubygems.org", "RubyGems", "rubygems"),
    Rule("crates.io", "crates.io (Rust)", "crates.io"),
    Rule("static.crates.io", "crates.io downloads", "crates.io"),
    Rule("golang.org", "Go project", "go"),
    Rule("go.dev", "Go project", "go"),
    Rule("proxy.golang.org", "Go module proxy", "go proxy"),
    Rule("gopkg.in", "Go package registry", "go"),
    Rule("maven.org", "Maven Central", "maven"),
    Rule("repo1.maven.org", "Maven Central", "maven"),
    Rule("search.maven.org", "Maven search", "maven"),
    Rule("central.sonatype.com", "Sonatype Central", "sonatype"),
    Rule("nuget.org", "NuGet", "nuget"),
    Rule("api.nuget.org", "NuGet API", "nuget"),
    Rule("packagist.org", "Packagist (PHP)", "packagist"),
    Rule("hex.pm", "Hex.pm (Erlang)", "hex"),
    Rule("pub.dev", "pub.dev (Dart)", "pub.dev"),
    Rule("cocoapods.org", "CocoaPods", "cocoapods"),
    Rule("clojars.org", "Clojars", "clojars"),
    # --- OS / container / infra commonly pulled during a build ----------
    Rule("docker.io", "Docker Hub", "docker hub"),
    Rule("docker.com", "Docker", "docker"),
    Rule("ghcr.io", "GitHub Container Registry", "ghcr"),
    Rule("gcr.io", "Google Container Registry", "gcr"),
    Rule("quay.io", "Quay", "quay"),
    Rule("registry.k8s.io", "Kubernetes registry", "k8s"),
    Rule("registry-1.docker.io", "Docker Hub API", "docker hub"),
    Rule("debian.org", "Debian", "debian"),
    Rule("ubuntu.com", "Ubuntu", "ubuntu"),
    Rule("security.ubuntu.com", "Ubuntu security", "ubuntu"),
    Rule("archive.ubuntu.com", "Ubuntu archive", "ubuntu"),
    Rule("security.debian.org", "Debian security", "debian"),
    Rule("packages.microsoft.com", "Microsoft packages", "ms packages"),
    Rule("dl.google.com", "Google downloads", "google"),
    Rule("storage.googleapis.com", "Google Cloud Storage", "gcs"),
    Rule("registry.npmjs.org", "npm API", "npm"),
)


def _normalise(host: str) -> str:
    """Lower-case and strip the trailing root dot (`example.com.` -> `example.com`).

    A trailing dot is the DNS root and names the same host, so it is stripped.
    Empty interior labels are left alone here and rejected by `_valid_hostname`,
    so `.npmjs.org` cannot slip through the suffix check.
    """
    return host.strip().lower().rstrip(".")


def _valid_hostname(host: str) -> bool:
    """Reject anything that is not a syntactically plausible DNS name.

    Guards the suffix match against inputs with empty labels, stray whitespace,
    or characters that could never appear in a hostname resolved from a proxy
    CONNECT line.
    """
    if not host or len(host) > 253:
        return False
    if host.startswith(".") or ".." in host:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")
    return all(ch in allowed for ch in host)


def is_ip_literal(host: str) -> bool:
    """True when `host` is a bare IPv4/IPv6 address rather than a name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _matches(host: str, rule_host: str) -> bool:
    """Exact match, or subdomain match on a dotted boundary."""
    return host == rule_host or host.endswith("." + rule_host)


def classify(host: str, extra_safe: Iterable[str] = ()) -> Tuple[str, str]:
    """Classify a hostname.

    Returns `(verdict, reason)`. `verdict` is `SAFE` or `UNKNOWN`.

    A bare IP address is always UNKNOWN with an explicit reason, regardless of
    the safelist -- there is no name to validate in the first place.
    """
    host = _normalise(host)
    if not host:
        return UNKNOWN, "empty host"

    if is_ip_literal(host):
        # Checked before the user safelist on purpose: a bare IP has no name to
        # validate, which is the entire signal here, so `--allow-internal`
        # deliberately cannot silence it. Promote the *name* if you trust it.
        return UNKNOWN, "raw IP address"

    if not _valid_hostname(host):
        return UNKNOWN, "malformed hostname"

    for extra in extra_safe:
        extra = _normalise(extra)
        if extra and _matches(host, extra):
            return SAFE, f"user safelist ({extra})"

    for rule in _SAFE_RULES:
        if _matches(host, rule.host):
            return SAFE, rule.short or rule.reason

    return UNKNOWN, "unrecognised domain"


def classify_detail(host: str, extra_safe: Iterable[str] = ()) -> Tuple[str, str]:
    """Like `classify`, but always returns the long-form reason.

    The report uses the short form for the table and the long form for the
    per-host detail lines, so a narrow terminal still gets a readable table
    without losing the explanation.
    """
    host = _normalise(host)
    if not host:
        return UNKNOWN, "empty host"
    if is_ip_literal(host):
        return UNKNOWN, "raw IP address (no TLS identity, no name to validate)"
    if not _valid_hostname(host):
        return UNKNOWN, "malformed hostname"

    for extra in extra_safe:
        extra = _normalise(extra)
        if extra and _matches(host, extra):
            return SAFE, f"user safelist ({extra})"

    for rule in _SAFE_RULES:
        if _matches(host, rule.host):
            return SAFE, rule.reason

    return UNKNOWN, "unrecognised domain"


def safe_hosts() -> List[str]:
    """The built-in safelist, for `--list-safe`."""
    return [rule.host for rule in _SAFE_RULES]
