#!/usr/bin/env python3
"""
php2shell_scan.py

Defensive vulnerability inventory scanner for CVE-2026-109618 / CVE-2026-109619
("php2shell"). Connects over SSH to every host in one or more subnets, detects
installed PHP version(s), and reports whether each is affected.

This tool ONLY reads version information (`php -v`, `php-fpm -v`, package
metadata). It does not exploit anything and makes no changes to remote hosts.
Use it only on infrastructure you are authorized to scan.

Requires: paramiko  (pip install -r requirements.txt)

Copyright (c) 2026 Belsis Meletis. All rights reserved.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    sys.exit("paramiko is required. Install it with: pip install -r requirements.txt")


__app_name__ = "php2shell-scan"
__version__ = "1.0"
__author__ = "Belsis Meletis"
__copyright__ = "Copyright (c) 2026 Belsis Meletis. All rights reserved."


def print_banner() -> None:
    """Print the application/copyright banner to stderr at startup."""
    print(f"{__app_name__} {__version__} - PHP php2shell inventory "
          f"(CVE-2026-109618 / CVE-2026-109619)", file=sys.stderr)
    print(__copyright__, file=sys.stderr)
    print("Authorized use only. Read-only; no exploitation is performed.\n", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Affected-version logic (CVE-2026-109618 / CVE-2026-109619)
# Source: Tenable php2shell FAQ + PHP security releases.
# A branch is affected when the detected version is BELOW the fixed release.
# Anything below 8.2 is affected (EOL or source-backport only upstream).
#
# NOTE ON DISTRO BACKPORTS: Debian, Ubuntu, RHEL, etc. backport security fixes
# while KEEPING the upstream version string (e.g. 8.2.7 patched). A pure
# upstream-version comparison cannot see that. This script therefore also
# captures the full distro package version so you can cross-check against your
# vendor advisory. Treat "POTENTIALLY_VULNERABLE" on a distro-packaged PHP as "needs vendor
# confirmation" rather than a certainty.
# --------------------------------------------------------------------------- #
FIXED_VERSIONS = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
# Branches with no clean fixed upstream release: everything < 8.2.
MIN_SAFE_BRANCH = (8, 2)


def classify_version(version: tuple[int, int, int] | None) -> tuple[str, str]:
    """Return (status, detail) for a parsed (major, minor, patch) version."""
    if version is None:
        return "UNKNOWN", "could not parse PHP version"

    major, minor, patch = version
    branch = (major, minor)

    if branch in FIXED_VERSIONS:
        fixed = FIXED_VERSIONS[branch]
        if version < fixed:
            return "POTENTIALLY_VULNERABLE", f"{major}.{minor}.{patch} < {fixed[0]}.{fixed[1]}.{fixed[2]} (fixed)"
        return "NOT_AFFECTED", f"{major}.{minor}.{patch} >= fixed {fixed[0]}.{fixed[1]}.{fixed[2]}"

    if branch < MIN_SAFE_BRANCH:
        if version >= (7, 4, 0):
            return "POTENTIALLY_VULNERABLE", f"{major}.{minor}.{patch} on 7.4-8.1 branch (source backport only upstream)"
        return "POTENTIALLY_VULNERABLE", f"{major}.{minor}.{patch} on EOL branch (<7.4, no upstream fix)"

    # A future branch newer than anything in our table (e.g. 8.6+). Unknown.
    return "UNKNOWN", f"{major}.{minor}.{patch} is newer than the advisory data; verify manually"


# A non-final suffix after X.Y.Z (RC/alpha/beta/dev/snapshot, or Debian's '~'
# prerelease marker). Such a build does NOT contain the fix that its release-
# version number would imply, so it must not be classified from the number alone.
PRERELEASE_RE = re.compile(r"(?:rc|alpha|beta|dev|snapshot|~)", re.IGNORECASE)


def classify_token(match) -> tuple:
    """From a VERSION_RE / WEB_VERSION_RE match, return (version, status, detail).

    A prerelease/non-final build (e.g. 8.3.36RC1) is reported UNKNOWN rather than
    compared to the fixed release, since the number alone would misread it.
    """
    if not match:
        return None, "UNKNOWN", "could not parse PHP version"
    version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    suffix = (match.group(4) or "") if match.re.groups >= 4 else ""
    if suffix and PRERELEASE_RE.search(suffix):
        return version, "UNKNOWN", (f"{version[0]}.{version[1]}.{version[2]}{suffix} is a "
                                    "prerelease/non-final build; classify manually")
    status, detail = classify_version(version)
    return version, status, detail


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    host: str
    reachable: bool = False
    ssh_ok: bool = False
    php_installed: bool = False
    status: str = "UNREACHABLE"          # POTENTIALLY_VULNERABLE / NOT_AFFECTED / UNKNOWN / AUTH_FAILED / UNREACHABLE / ERROR
    web_ok: bool = False
    incomplete: bool = False             # inventory could not be fully established for this host
    versions: list[str] = field(default_factory=list)   # human-readable per-source findings
    detail: str = ""
    error: str = ""


# --------------------------------------------------------------------------- #
# SSH + detection
# --------------------------------------------------------------------------- #
VERSION_RE = re.compile(r"PHP\s+(\d+)\.(\d+)\.(\d+)([^\s)]*)")

# Commands run on the remote host. Purely read-only.
#
# Failures are made VISIBLE rather than swallowed: a genuine package-query error
# emits 'QUERYERR=<tool>', and a PHP binary that is present but cannot report a
# version (broken install, permissions, missing library) emits 'BINERR=<path>'.
# The scanner treats either marker as an incomplete inventory. 'discovery_complete'
# only means the script ran end to end, not that every check succeeded.
DISCOVERY_CMD = r"""
# Query runtime packages, including installations outside the SSH user's PATH.
if command -v dpkg-query >/dev/null 2>&1; then
  raw=$(dpkg-query -W -f='${db:Status-Status}|${Package}|${Version}\n' 'php*' 'libapache2-mod-php*' 2>&1)
  printf '%s\n' "$raw" | awk -F'|' '$1 == "installed" { print "PKG=" $2 " " $3 }'
  # A real failure (db locked/corrupt) prints an error; the benign
  # "no packages found matching" case (nothing installed) does not.
  printf '%s\n' "$raw" | grep -qiE 'error|cannot|locked|unable|corrupt' && printf 'QUERYERR=dpkg-query\n'
fi
if command -v rpm >/dev/null 2>&1; then
  raw=$(rpm -qa --qf 'PKG=%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' 'php*' 'ea-php*' 'plesk-php*' 'mod_php*' 2>&1)
  printf '%s\n' "$raw" | grep '^PKG='
  printf '%s\n' "$raw" | grep -qiE 'error|cannot|corrupt|failed|unable' && printf 'QUERYERR=rpm\n'
fi
for b in php php-cli php-fpm php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 php7.3 php7.2 php7.1 php7.0 php5 php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4; do
  command -v "$b" 2>/dev/null || true
done |
while IFS= read -r p; do
  v=$("$p" -n -v 2>/dev/null | head -n1)
  if [ -n "$v" ]; then printf 'BIN=%s :: %s\n' "$p" "$v"; else printf 'BINERR=%s\n' "$p"; fi
done
for p in /usr/bin/php* /usr/sbin/php*fpm* /usr/local/bin/php* /usr/local/sbin/php*fpm* /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm; do
  [ -x "$p" ] && [ -f "$p" ] || continue
  case "${p##*/}" in php|php[0-9]*|php-cli|php-fpm|php-fpm[0-9]*) ;; *) continue ;; esac
  v=$("$p" -n -v 2>/dev/null | head -n1)
  if [ -n "$v" ]; then printf 'BIN=%s :: %s\n' "$p" "$v"; else printf 'BINERR=%s\n' "$p"; fi
done
printf 'META=discovery_complete\n'
"""



# --------------------------------------------------------------------------- #
# Web-facing probe (HTTP/HTTPS)
# PHP commonly advertises its version in the X-Powered-By or Server response
# header unless expose_php is Off. This probe READS those headers only: a single
# HEAD (falling back to GET) to "/" with no page body downloaded. TLS certs are
# not verified, since internal hosts frequently use self-signed certificates and
# we only need the response headers.
# --------------------------------------------------------------------------- #
WEB_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)([^\s;,)]*)", re.IGNORECASE)
WEB_USER_AGENT = "php2shell-scan/1.0 (version inventory; headers only)"

# Severity ordering shared by the web and SSH paths.
ORDER = {"NOT_AFFECTED": 0, "UNKNOWN": 1, "POTENTIALLY_VULNERABLE": 2}


def parse_web_ports(spec: str) -> list:
    """Parse a --http-ports spec into a list of (scheme, port) tuples.

    Tokens are comma-separated. A bare port infers its scheme (443/8443 -> https,
    otherwise http); 'scheme:port' forces it (e.g. 'https:8443').
    """
    out = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        scheme = None
        if ":" in tok:
            scheme, _, port_s = tok.partition(":")
            scheme = scheme.strip().lower()
        else:
            port_s = tok
        try:
            port = int(port_s)
        except ValueError:
            raise SystemExit(f"invalid web port: {tok!r}")
        if not 1 <= port <= 65535:
            raise SystemExit(f"web port out of range: {tok!r}")
        if scheme not in (None, "http", "https"):
            raise SystemExit(f"invalid scheme (use http/https): {tok!r}")
        if scheme is None:
            scheme = "https" if port in (443, 8443) else "http"
        out.append((scheme, port))
    return out


def probe_web(host: str, ports: list, timeout: float, paths=("/",), deadline=None) -> list:
    """Probe each (scheme, port) for a PHP version banner.

    For each port, request each path in order (HEAD then GET per path) and stop at
    the first path that reveals a PHP version. Returns a list of dicts:
    {scheme, port, reachable, version, banner, http_status, path}.

    `deadline` (a time.monotonic() timestamp, or None) caps the whole probe: once
    it passes, remaining ports/paths/methods are skipped and whatever was already
    collected is returned.
    """
    results = []
    for scheme, port in ports:
        entry = {"scheme": scheme, "port": port, "reachable": False,
                 "version": None, "banner": "", "http_status": None, "path": None}
        last_exc = None
        for path in paths:
            if phase_timeout(timeout, deadline) <= 0:
                break  # deadline reached before this path
            found = None
            # Try HEAD first, then GET. GET is attempted whenever HEAD did not yield
            # a version, including when HEAD returned a real response such as 405
            # Method Not Allowed (not only when HEAD raised an exception).
            for method in ("HEAD", "GET"):
                eff = phase_timeout(timeout, deadline)
                if eff <= 0:
                    break  # per-host deadline reached; stop probing
                conn = None
                try:
                    if scheme == "https":
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = http.client.HTTPSConnection(host, port, timeout=eff, context=ctx)
                    else:
                        conn = http.client.HTTPConnection(host, port, timeout=eff)
                    conn.request(method, path, headers={"User-Agent": WEB_USER_AGENT})
                    resp = conn.getresponse()
                    status = resp.status
                    headers = {k.lower(): v for k, v in resp.getheaders()}
                except Exception as exc:  # noqa: BLE001 - try the next method before giving up
                    last_exc = exc
                    continue
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:  # noqa: BLE001
                            pass

                entry["reachable"] = True
                if entry["http_status"] is None:
                    entry["http_status"] = status
                    entry["path"] = path
                banner = headers.get("x-powered-by") or headers.get("server") or ""
                if banner and not entry["banner"]:
                    entry["banner"] = banner[:200]
                for header in ("x-powered-by", "server"):
                    match = WEB_VERSION_RE.search(headers.get(header, ""))
                    if match:
                        found = tuple(int(x) for x in match.groups()[:3])  # suffix (group 4) stays out of the numeric tuple
                        entry["banner"] = headers.get(header, "")[:200]
                        entry["http_status"] = status
                        entry["path"] = path
                        break
                if found:
                    break  # version in hand; no need to try GET
                # No version via this method; fall through to GET.
            if found:
                entry["version"] = found
                break  # version found on this path; no need to try other paths

        if not entry["reachable"] and last_exc is not None:
            entry["banner"] = f"__unreachable__:{type(last_exc).__name__}"
        results.append(entry)
        if phase_timeout(timeout, deadline) <= 0:
            break  # deadline reached; do not start further ports
    return results


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Per-host deadline helpers
# A deadline is a time.monotonic() timestamp (or None for "no deadline"). Each
# blocking phase (HTTP, SSH connect, discovery) is given a timeout that is the
# smaller of --timeout and the time left before the deadline, so the worker
# returns promptly instead of relying on cancelling a Python future (which does
# not stop the thread already running inside it).
# --------------------------------------------------------------------------- #
def phase_timeout(base: float, deadline: float | None) -> float:
    """Effective timeout for one blocking op. 0.0 means the deadline passed."""
    if deadline is None:
        return base
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0.0
    return max(0.1, min(base, remaining))


# Resolve the base at import time so the module still imports when paramiko is a
# bare stub (e.g. the dependency-free test run); duck typing is all paramiko needs.
_PolicyBase = getattr(paramiko, "MissingHostKeyPolicy", object)


class _AcceptNewPolicy(_PolicyBase):
    """Trust an unknown host key on FIRST contact and persist it, so a later run
    detects a changed key as a mismatch (like OpenSSH accept-new).

    Thread-safe and race-free: the first key seen for a (host, keytype), decided
    under the lock, becomes authoritative. A concurrent client presenting a
    DIFFERENT key for the same host/type is rejected (BadHostKeyException), never
    trusted. The key is appended to the known_hosts file once (not a whole-file
    rewrite, which would race across the concurrent per-host SSH clients).
    """

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._accepted = {}   # (hostname, keytype) -> key object (authoritative)
        self._warned = False

    def missing_host_key(self, client, hostname, key):
        tag = (hostname, key.get_name())
        with self._lock:
            prior = self._accepted.get(tag)
            if prior is not None:
                # A different key for a host/type we already accepted this run:
                # treat exactly like a known_hosts mismatch, do not trust it.
                if prior.get_base64() != key.get_base64():
                    raise paramiko.BadHostKeyException(hostname, key, prior)
                client.get_host_keys().add(hostname, key.get_name(), key)
                return
            # First contact for this host/type: it becomes authoritative, and we
            # trust it in memory only after recording it, still under the lock.
            self._accepted[tag] = key
            client.get_host_keys().add(hostname, key.get_name(), key)
            if self._path:
                self._persist(hostname, key)

    def _persist(self, hostname, key):
        line = f"{hostname} {key.get_name()} {key.get_base64()}\n"
        try:
            parent = os.path.dirname(self._path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            if not self._warned:
                print(f"warning: could not persist accepted host key(s) to "
                      f"{self._path}: {exc}", file=sys.stderr)
                self._warned = True


def _ssh_detect(host: str, args, pkey, res: "HostResult", deadline=None):
    """SSH-based PHP discovery. Mutates res (reachable/ssh_ok/error/php_installed).

    Returns (outcome, findings, detail, pkg_note, discovery_incomplete):
      outcome  : 'OK' | 'NOPHP' | 'AUTH_FAILED' | 'ERROR' | 'UNREACHABLE'
                 | 'HOSTKEY_MISMATCH' | 'TIMEOUT'
      findings : list of (status, label) for each discovered runtime
      detail   : human-readable text
      pkg_note : ' || distro packages: ...' suffix, or ''
      discovery_incomplete : True if some check was suppressed/failed/timed out
    """
    eff = phase_timeout(args.timeout, deadline)
    if eff <= 0:
        return "TIMEOUT", [], "per-host deadline reached before the SSH probe started", "", True
    if not port_open(host, args.port, eff):
        return "UNREACHABLE", [], f"ssh port {args.port} closed/filtered", "", False
    res.reachable = True

    client = paramiko.SSHClient()
    # Load trusted host keys read-only (no concurrent-write races). A custom file
    # takes priority; otherwise the user's ~/.ssh/known_hosts.
    if getattr(args, "known_hosts", None):
        try:
            client.load_system_host_keys(args.known_hosts)
        except OSError:
            pass
    else:
        client.load_system_host_keys()
    # Default: reject unknown servers. --accept-new trusts on first contact and
    # persists the key (via the shared policy) so a later run detects a change.
    if getattr(args, "accept_new", False):
        client.set_missing_host_key_policy(
            getattr(args, "_accept_policy", None) or paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    eff = phase_timeout(args.timeout, deadline)
    if eff <= 0:
        client.close()
        return "TIMEOUT", [], "per-host deadline reached before SSH connect", "", True
    use_agent = getattr(args, "use_agent", False)
    connect_kwargs = dict(
        hostname=host,
        port=args.port,
        username=args.username,
        timeout=eff,
        banner_timeout=eff,
        auth_timeout=eff,
        allow_agent=use_agent,
        look_for_keys=use_agent,
    )
    if pkey is not None:
        connect_kwargs["pkey"] = pkey
    elif args.password:
        connect_kwargs["password"] = args.password

    try:
        client.connect(**connect_kwargs)
        res.ssh_ok = True
    except paramiko.BadHostKeyException as exc:
        # Server key does not match the trusted entry: a different host or a MITM.
        res.error = f"host key mismatch: {exc}"
        client.close()
        return "HOSTKEY_MISMATCH", [], "SSH host key does NOT match known_hosts (different host or possible MITM)", "", False
    except paramiko.AuthenticationException:
        client.close()
        return "AUTH_FAILED", [], "SSH authentication failed", "", False
    except Exception as exc:  # noqa: BLE001 - report any connect failure per host
        res.error = f"{type(exc).__name__}: {exc}"
        client.close()
        hint = "" if getattr(args, "known_hosts", None) or getattr(args, "accept_new", False) else " (host may be absent from known_hosts; see --accept-new / --known-hosts)"
        return "ERROR", [], f"SSH connection error{hint}", "", False

    eff = phase_timeout(args.timeout, deadline)
    if eff <= 0:
        client.close()
        return "TIMEOUT", [], "per-host deadline reached before PHP discovery", "", True

    # Read stdout/stderr INCREMENTALLY so the budget bounds the whole exchange,
    # not just an idle gap: a slow steady stream or a late exit status cannot run
    # past the per-host deadline, and whatever was received before expiry is kept
    # and parsed (so fully-received vulnerable evidence is never discarded). The
    # loop also stops after --timeout of no progress even when no overall deadline
    # is set, so a wedged channel can never hang the worker.
    out_buf, err_buf = bytearray(), bytearray()
    command_status = None
    timed_out = False
    chan = None
    try:
        stdin, stdout, stderr = client.exec_command(DISCOVERY_CMD, timeout=eff)
        chan = stdout.channel
        last_progress = time.monotonic()
        while True:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                timed_out = True
                break
            if now - last_progress >= args.timeout:
                timed_out = True  # no progress within --timeout; give up on this host
                break
            drained = False
            while chan.recv_ready():
                data = chan.recv(65536)
                if not data:
                    break
                out_buf += data
                drained = True
            while chan.recv_stderr_ready():
                data = chan.recv_stderr(65536)
                if not data:
                    break
                err_buf += data
                drained = True
            if drained:
                last_progress = now
            if chan.exit_status_ready():
                command_status = chan.recv_exit_status()
                while chan.recv_ready():          # drain anything buffered at exit
                    data = chan.recv(65536)
                    if not data:
                        break
                    out_buf += data
                while chan.recv_stderr_ready():
                    data = chan.recv_stderr(65536)
                    if not data:
                        break
                    err_buf += data
                break
            if not drained:
                caps = [0.05, args.timeout - (now - last_progress)]
                if deadline is not None:
                    caps.append(deadline - now)
                time.sleep(max(0.0, min(caps)))
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
        return "ERROR", [], "command execution error", "", False
    finally:
        if chan is not None:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
        client.close()

    output = bytes(out_buf).decode("utf-8", "replace")
    command_error = bytes(err_buf).decode("utf-8", "replace")

    bin_lines = [ln for ln in output.splitlines() if ln.startswith("BIN=")]
    pkg_lines = [ln[4:] for ln in output.splitlines() if ln.startswith("PKG=")]
    # Suppressed-error markers: a PHP binary present but unable to report a version,
    # or a package query that genuinely failed. Either means the inventory is partial.
    binerr = sorted({ln[len("BINERR="):] for ln in output.splitlines() if ln.startswith("BINERR=")})
    queryerr = sorted({ln[len("QUERYERR="):] for ln in output.splitlines() if ln.startswith("QUERYERR=")})
    discovery_incomplete = bool(binerr or queryerr) or timed_out
    disc_bits = []
    if binerr:
        shown = ", ".join(binerr[:6]) + ("..." if len(binerr) > 6 else "")
        disc_bits.append(f"{len(binerr)} discovered PHP binary(ies) could not report a version ({shown})")
    if queryerr:
        disc_bits.append(f"package query failed ({', '.join(queryerr)})")
    if timed_out:
        disc_bits.append("discovery timed out before completing (per-host deadline); results are partial")
    disc_note = "; ".join(disc_bits)

    # A genuine command failure (not a timeout) with no completion marker is an
    # ERROR. A timeout is NOT an early return: we fall through and parse whatever
    # output arrived, so fully-received findings survive as POTENTIALLY_VULNERABLE
    # (with incomplete=True) instead of being discarded.
    if not timed_out and (command_status != 0 or "META=discovery_complete" not in output):
        res.error = command_error[:2000]
        return "ERROR", [], "PHP discovery did not complete", "", False

    # Package versions are evidence even when a runtime binary is not executable.
    # ('common' is not a runtime: it ships shared files and, as a bare metapackage,
    # carries no usable version, so it is excluded.)
    runtime_re = re.compile(
        r"(?:^php(?:[0-9.]+)?(?:-(?:cli|fpm|cgi))?$|^libapache2-mod-php(?:[0-9.]+)?$"
        r"|^mod_php[0-9.]*$|^ea-php[0-9]+-php(?:-|$)|^php[0-9]+-php(?:-|$)|^plesk-php[0-9]+(?:-|$))")
    # Debian/Ubuntu *metapackages* carry no version of their own: the name has no
    # embedded version (php, php-cli, php-fpm, php-cgi, php-common, libapache2-mod-php)
    # and the version is a branch marker like '2:8.3+93'. Only these may be dropped
    # when a real versioned package already covers their branch; a concrete runtime
    # package whose version we simply failed to parse (e.g. 'php8.3-fpm vendor-build')
    # must never be dropped, or a patched sibling could clear an unknown FPM binary.
    meta_pkg_re = re.compile(r"^(?:php(?:-(?:cli|fpm|cgi|common))?|libapache2-mod-php)$")
    runtime_packages = []
    parsed_pkgs = []     # (name, full_version, upstream_token)
    unparsed_pkgs = []   # (name, full_version, branch_or_None)
    for pkg in pkg_lines:
        parts = pkg.split(None, 1)
        if len(parts) != 2:
            continue
        name, full_version = parts
        if not runtime_re.search(name):
            continue
        runtime_packages.append(pkg)
        # Upstream portion only: strip the epoch and the distro revision after '-'
        # (so '8.3.36~rc1-1.el9' -> '8.3.36~rc1', '8.3.6-0ubuntu0.24.04.13' -> '8.3.6').
        upstream = re.sub(r"^[0-9]+:", "", full_version).split("-", 1)[0]
        if re.match(r"[0-9]+\.[0-9]+\.[0-9]+", upstream):
            parsed_pkgs.append((name, full_version, upstream))
        else:
            m2 = re.match(r"([0-9]+)\.([0-9]+)", upstream)
            branch = (int(m2.group(1)), int(m2.group(2))) if m2 else None
            if branch is None:
                mn = re.search(r"php-?([0-9])\.?([0-9]+)", name)
                branch = (int(mn.group(1)), int(mn.group(2))) if mn else None
            unparsed_pkgs.append((name, full_version, branch))

    # Build findings from parsed packages and record their branches.
    covered_branches = set()
    for name, full_version, upstream in parsed_pkgs:
        mm = re.match(r"([0-9]+)\.([0-9]+)\.", upstream)
        covered_branches.add((int(mm.group(1)), int(mm.group(2))))
        bin_lines.append(f"BIN=package:{name} :: PHP {upstream} ({full_version})")
    # A runtime package whose version we cannot parse is NOT silently dropped: it
    # surfaces as an UNKNOWN finding so it cannot be cleared by a patched sibling.
    # The ONLY exception is a true Debian metapackage (e.g. 'php-cli 2:8.3+93' next
    # to 'php8.3-cli 8.3.6') whose branch a real versioned package already covers.
    for name, full_version, branch in unparsed_pkgs:
        if branch is not None and branch in covered_branches and meta_pkg_re.match(name):
            continue
        bin_lines.append(f"BIN=package:{name} :: PHP unparsed-version ({full_version})")

    pkg_note = (" || distro packages: " + ", ".join(pkg_lines)) if pkg_lines else ""

    if not bin_lines:
        if runtime_packages or binerr:
            res.php_installed = True
        detail = "No runtime version identified; verify containers, custom paths and permissions manually"
        if pkg_lines:
            detail += "; packages: " + ", ".join(pkg_lines)
        if disc_note:
            detail += "; discovery gaps: " + disc_note
        return "NOPHP", [], detail, pkg_note, discovery_incomplete

    findings = []
    details = []
    seen = set()
    for ln in bin_lines:
        if ln in seen:
            continue
        seen.add(ln)
        version, status, detail = classify_token(VERSION_RE.search(ln))
        label = f"{ln.split('::')[0].strip()} -> {('%d.%d.%d' % version) if version else '?'} [{status}]"
        findings.append((status, label))
        details.append(detail)
    joined = "; ".join(details)
    if disc_note:
        joined += ("; " if joined else "") + "discovery gaps: " + disc_note
    return "OK", findings, joined, pkg_note, discovery_incomplete


def scan_host(host: str, args, pkey) -> HostResult:
    """Inventory one host via the optional web probe and SSH, then merge."""
    res = HostResult(host=host)
    worst = None
    details = []

    # One deadline for the whole host: HTTP + SSH + discovery share the budget.
    deadline_s = getattr(args, "deadline", 0) or 0
    deadline = (time.monotonic() + deadline_s) if deadline_s > 0 else None

    # ---- Web-facing probe (runs regardless of SSH reachability) ----
    web_reachable = False
    if getattr(args, "web", False):
        for pr in probe_web(host, args.http_ports, args.timeout,
                            getattr(args, "http_paths", ["/"]), deadline=deadline):
            if not pr["reachable"]:
                continue
            web_reachable = True
            res.web_ok = True
            tag = f"web:{pr['scheme']}://{host}:{pr['port']}{pr['path'] or ''}"
            if pr["version"] is not None:
                # Re-classify from the banner text so a prerelease suffix (e.g.
                # PHP/8.3.36RC1) is caught rather than read as the fixed release.
                version, status, detail = classify_token(WEB_VERSION_RE.search(pr["banner"]))
                shown = ("%d.%d.%d" % version) if version else "?"
                res.versions.append(f"{tag} -> {shown} [{status}] (banner: {pr['banner']})")
                details.append(f"{pr['scheme']}:{pr['port']} {detail}")
                if worst is None or ORDER[status] > ORDER[worst]:
                    worst = status
            else:
                res.versions.append(f"{tag} -> no PHP version banner (server: {pr['banner'] or 'n/a'}; expose_php may be Off)")

    # ---- SSH probe (shares the per-host deadline with the web probe) ----
    outcome, findings, ssh_detail, pkg_note, discovery_incomplete = _ssh_detect(host, args, pkey, res, deadline)
    for status, label in findings:
        res.versions.append(label)
        if worst is None or ORDER[status] > ORDER[worst]:
            worst = status
    if ssh_detail:
        details.append(ssh_detail)

    # An attempted-but-failed SSH probe means the host was not fully inventoried,
    # even when a web banner gave a verdict. NOPHP (SSH ran but located no runtime)
    # is likewise insufficient corroboration, not a clean bill of health. A
    # discovery gap (a binary that could not report a version, or a failed package
    # query) is also inconclusive even when another runtime reported cleanly.
    ssh_failed = outcome in ("AUTH_FAILED", "ERROR", "UNREACHABLE", "HOSTKEY_MISMATCH", "TIMEOUT")
    ssh_inconclusive = ssh_failed or outcome == "NOPHP" or discovery_incomplete

    # ---- Merge into a final status ----
    if worst is not None:
        res.php_installed = True
        res.incomplete = ssh_inconclusive
        # A clean verdict (e.g. a patched web banner) is unreliable while the SSH
        # host inventory is inconclusive: a vulnerable CLI/FPM may be in a path the
        # probe missed or not exposed over HTTP. Only vulnerable evidence clears
        # the ambiguity; otherwise keep the host UNKNOWN.
        if ssh_inconclusive and worst != "POTENTIALLY_VULNERABLE":
            res.status = "UNKNOWN"
        else:
            res.status = worst
        res.detail = "; ".join(d for d in details if d)
        if ssh_failed:
            res.detail += (f" || INCOMPLETE: SSH probe did not complete ({ssh_detail or outcome}); "
                           "host-side CLI/FPM patch state unverified")
        elif outcome == "NOPHP":
            res.detail += (" || INCOMPLETE: SSH located no PHP runtime though other evidence shows "
                           "PHP present; host inventory insufficient")
        elif discovery_incomplete:
            res.detail += (" || INCOMPLETE: part of SSH discovery failed (a PHP binary could not "
                           "report its version, or a package query failed); some host runtimes unverified")
        res.detail += (" || Scope: discovered host runtimes and advertised web banners only; "
                       "containers, custom paths and running worker patch state require verification")
        res.detail += pkg_note
        return res

    # No PHP version evidence from either source.
    res.incomplete = ssh_inconclusive
    if outcome == "HOSTKEY_MISMATCH":
        res.status = "HOSTKEY_MISMATCH"
    elif outcome == "ERROR":
        res.status = "ERROR"
    elif outcome == "TIMEOUT":
        res.status = "UNKNOWN"
        details.append(ssh_detail or "per-host deadline reached; inventory incomplete")
    elif outcome == "NOPHP":
        res.status = "UNKNOWN"
    elif web_reachable:
        res.status = "UNKNOWN"
        details.append("reachable over HTTP but no PHP version advertised; verify manually")
    elif outcome == "AUTH_FAILED":
        res.status = "AUTH_FAILED"
    else:
        res.status = "UNREACHABLE"
    res.detail = "; ".join(d for d in details if d) or ssh_detail
    res.detail += pkg_note
    return res


# --------------------------------------------------------------------------- #
# Input parsing
# --------------------------------------------------------------------------- #
def expand_targets(csv_path: str) -> list[str]:
    """Read a CSV of subnets/IPs and expand to a flat list of host addresses.

    Accepts: CIDR (10.0.0.0/24), single IP (10.0.0.5), or hostname. A header
    row is auto-skipped if the first cell is not an address/CIDR. Lines
    starting with '#' are ignored.
    """
    targets: list[str] = []
    with open(csv_path, newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            cell = row[0].strip()
            if not cell or cell.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(cell, strict=False)
                if net.num_addresses > 65536:
                    raise SystemExit(f"Target range {cell} exceeds 65,536 addresses; split it explicitly")
                if net.num_addresses == 1:
                    targets.append(str(net.network_address))
                else:
                    targets.extend(str(h) for h in net.hosts())
                continue
            except ValueError:
                pass
            try:
                ipaddress.ip_address(cell)
                targets.append(cell)
                continue
            except ValueError:
                pass
            # Treat as hostname unless it's an obvious header label.
            if cell.lower() in {"subnet", "subnets", "cidr", "host", "hosts", "ip", "network"}:
                continue
            targets.append(cell)

    # De-duplicate, preserve order.
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def load_key(args):
    if not args.key:
        return None
    passphrase = args.key_passphrase
    if passphrase is None and args.ask_key_passphrase:
        passphrase = getpass.getpass("SSH key passphrase: ")
    last_err = None
    for loader in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return loader.from_private_key_file(args.key, password=passphrase)
        except paramiko.PasswordRequiredException:
            sys.exit("SSH key is encrypted; provide --ask-key-passphrase or --key-passphrase.")
        except paramiko.SSHException as exc:
            last_err = exc
            continue
    sys.exit(f"Could not load private key {args.key}: {last_err}")


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
CVES = ["CVE-2026-109618", "CVE-2026-109619"]


def _exit_code(results: list[HostResult]) -> int:
    """2 = any patch candidate; 1 = any incomplete/unresolved; 0 = clean."""
    if any(r.status == "POTENTIALLY_VULNERABLE" for r in results):
        return 2
    if any(r.incomplete or r.status in {"UNKNOWN", "ERROR", "AUTH_FAILED", "UNREACHABLE", "HOSTKEY_MISMATCH"}
           for r in results):
        return 1
    return 0


def write_report(results: list[HostResult], out_path: str | None, fmt: str = "csv") -> None:
    """Write the report as CSV (default) or JSON. Both carry the same fields,
    evidence and host set; the exit code is computed identically from `results`."""
    fh = open(out_path, "w", newline="") if out_path else sys.stdout
    try:
        if fmt == "json":
            payload = {
                "tool": __app_name__,
                "version": __version__,
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "cves": CVES,
                "exit_code": _exit_code(results),
                "summary": {s: sum(1 for r in results if r.status == s)
                            for s in sorted({r.status for r in results})},
                "scanned": len(results),
                "incomplete": sum(1 for r in results if r.incomplete),
                "hosts": [{
                    "host": r.host,
                    "status": r.status,
                    "php_installed": r.php_installed,
                    "versions": list(r.versions),
                    "detail": r.detail,
                    "reachable": r.reachable,
                    "ssh_ok": r.ssh_ok,
                    "web_ok": r.web_ok,
                    "incomplete": r.incomplete,
                    "error": r.error,
                } for r in results],
            }
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            return
        fieldnames = ["host", "status", "php_installed", "versions", "detail",
                      "reachable", "ssh_ok", "web_ok", "incomplete", "error"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "host": r.host,
                "status": r.status,
                "php_installed": r.php_installed,
                "versions": " | ".join(r.versions),
                "detail": r.detail,
                "reachable": r.reachable,
                "ssh_ok": r.ssh_ok,
                "web_ok": r.web_ok,
                "incomplete": r.incomplete,
                "error": r.error,
            })
    finally:
        if out_path:
            fh.close()


def print_summary(results: list[HostResult]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n=== php2shell scan summary ===", file=sys.stderr)
    print(f"scanned hosts : {len(results)}", file=sys.stderr)
    for status in ("POTENTIALLY_VULNERABLE", "HOSTKEY_MISMATCH", "NOT_AFFECTED", "UNKNOWN", "AUTH_FAILED", "UNREACHABLE", "ERROR"):
        if status in counts:
            print(f"{status:<22}: {counts[status]}", file=sys.stderr)
    incomplete = sum(1 for r in results if r.incomplete)
    if incomplete:
        print(f"{'(incomplete inventory)':<22}: {incomplete}", file=sys.stderr)

    affected = [r for r in results if r.status == "POTENTIALLY_VULNERABLE"]
    if affected:
        print("\n!!! POTENTIALLY VULNERABLE HOSTS (CVE-2026-109618 / CVE-2026-109619) !!!", file=sys.stderr)
        for r in affected:
            print(f"  {r.host}  {r.detail}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    print_banner()
    p = argparse.ArgumentParser(
        description="Scan subnets over SSH for PHP versions affected by php2shell "
                    "(CVE-2026-109618 / CVE-2026-109619).",
        epilog=__copyright__,
    )
    p.add_argument("-s", "--subnets", required=True,
                   help="CSV file listing subnets (CIDR), IPs, or hostnames (one per row, first column).")
    p.add_argument("-u", "--username", required=True, help="SSH username.")
    p.add_argument("-p", "--port", type=int, default=22, help="SSH port (default 22).")

    auth = p.add_argument_group("authentication (choose password, key, or agent)")
    auth.add_argument("--password", help="SSH password (insecure on shared hosts; prefer --ask-password).")
    auth.add_argument("--ask-password", action="store_true", help="Prompt for the SSH password.")
    auth.add_argument("-k", "--key", help="Path to an SSH private key.")
    auth.add_argument("--key-passphrase", help="Passphrase for the private key.")
    auth.add_argument("--ask-key-passphrase", action="store_true", help="Prompt for the key passphrase.")
    auth.add_argument("--use-agent", action="store_true",
                      help="Authenticate via the running SSH agent and default keys "
                           "(~/.ssh/id_*), in addition to any --key/--password.")

    ssh = p.add_argument_group("ssh connectivity")
    ssh.add_argument("--known-hosts",
                     help="Path to a known_hosts file to trust (default: ~/.ssh/known_hosts). "
                          "Loaded read-only.")
    ssh.add_argument("--accept-new", action="store_true",
                     help="Trust an unknown host key on first contact (TOFU), like OpenSSH "
                          "StrictHostKeyChecking=accept-new. A key that CHANGED is still rejected. "
                          "Less secure than pre-seeding known_hosts.")

    p.add_argument("-w", "--workers", type=int, default=50, help="Concurrent SSH workers (default 50).")
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="Per-connection timeout seconds (default 8).")
    p.add_argument("--deadline", type=float, default=0.0,
                   help="Overall per-host deadline in seconds, covering the web probe, SSH "
                        "connect and discovery together. When it expires, evidence already "
                        "collected is kept, the host is marked incomplete, and connections are "
                        "closed. 0 (default) means no overall deadline (each phase is still "
                        "bounded by --timeout).")
    p.add_argument("-o", "--output", help="Write the report to this file (default: stdout).")
    p.add_argument("--format", choices=("csv", "json"), default="csv",
                   help="Report format (default: csv). JSON carries the same fields and "
                        "evidence; the exit code is identical.")
    p.add_argument("--quiet", action="store_true", help="Suppress the stderr summary.")

    web = p.add_argument_group("web-facing probe (optional)")
    web.add_argument("--web", action="store_true",
                     help="Also probe HTTP/HTTPS and read the PHP version from the "
                          "X-Powered-By / Server response header.")
    web.add_argument("--http-ports", default="80,443",
                     help="Comma-separated web ports to probe; 'scheme:port' forces the "
                          "scheme (e.g. https:8443). Default: 80,443.")
    web.add_argument("--http-paths", default="/",
                     help="Comma-separated request paths to probe per port, in order, until a "
                          "PHP banner is found (e.g. '/,/index.php,/info.php'). Default: /.")

    args = p.parse_args()
    if args.workers < 1 or args.timeout <= 0 or not 1 <= args.port <= 65535:
        p.error("workers and timeout must be positive; port must be 1..65535")
    if args.deadline < 0:
        p.error("--deadline must be >= 0 (0 disables the overall per-host deadline)")
    args.http_ports = parse_web_ports(args.http_ports)
    args.http_paths = [p2 if p2.startswith("/") else "/" + p2
                       for p2 in (s.strip() for s in args.http_paths.split(",")) if p2]
    if not args.http_paths:
        args.http_paths = ["/"]
    if args.web and not args.http_ports:
        p.error("--web requires at least one valid --http-ports entry")

    # Resolve auth.
    if args.ask_password and not args.password:
        args.password = getpass.getpass("SSH password: ")
    if not args.key and not args.password and not args.use_agent:
        p.error("provide authentication: --key, --password/--ask-password, or --use-agent")

    pkey = load_key(args)

    # One shared accept-new policy persists accepted keys to the same file the
    # clients trust from, so a later run detects a changed key as a mismatch.
    args._accept_policy = None
    if args.accept_new:
        persist_path = args.known_hosts or os.path.expanduser("~/.ssh/known_hosts")
        args._accept_policy = _AcceptNewPolicy(persist_path)

    targets = expand_targets(args.subnets)
    if not targets:
        p.error(f"no targets found in {args.subnets}")

    if not args.quiet:
        print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] "
              f"scanning {len(targets)} host(s) with {args.workers} workers...", file=sys.stderr)

    results: list[HostResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_host, host, args, pkey): host for host in targets}
        done = 0
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append(HostResult(host=host, status="ERROR", error=str(exc)))
            done += 1
            if not args.quiet and done % 25 == 0:
                print(f"  ... {done}/{len(targets)} done", file=sys.stderr)

    # Stable sort: affected first, then by host.
    priority = {"POTENTIALLY_VULNERABLE": 0, "HOSTKEY_MISMATCH": 1, "UNKNOWN": 2, "NOT_AFFECTED": 3,
                "AUTH_FAILED": 4, "UNREACHABLE": 5, "ERROR": 6}
    results.sort(key=lambda r: (priority.get(r.status, 9), r.host))

    write_report(results, args.output, args.format)
    if not args.quiet:
        print_summary(results)

    # Exit code: 2 for patch candidates; 1 for incomplete inventory; 0 otherwise.
    return _exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
