# php2shell-scan

A read-only inventory scanner for the **php2shell** PHP vulnerabilities,
**CVE-2026-109618** and **CVE-2026-109619** (CVSS 9.2).

---

## 1. What this script does

`php2shell-scan` connects to the servers you list — single IPs, hostnames, or
whole subnets from a CSV — finds which PHP runtimes are installed, reads their
versions, and tells you which servers may need patching for php2shell. It is a
**patch-planning inventory tool, not an attack tool**: it only ever *reads*
version information, changes nothing on remote hosts, and performs no
exploitation.

It gathers evidence two complementary ways per host:

- **Over SSH (primary).** It logs in with the credentials you provide and reads
  the PHP version from the CLI/FPM binaries *and* from the installed distro
  packages — including Apache `mod_php`, cPanel `ea-php`, Plesk and Remi layouts.
- **Over HTTP/HTTPS (optional, `--web`).** It reads the PHP version a web server
  advertises in its `X-Powered-By` / `Server` response header.

The two results are **merged per host and the worst verdict wins**, so a clean
web banner can never hide a failed or incomplete SSH check.

Each run prints a short banner and copyright notice before it starts.

### How a version is judged

A discovered runtime is flagged when it is **below the upstream fixed release**
for its branch, or on a branch older than 8.2:

| Branch | Fixed in |
|--------|----------|
| 8.5    | 8.5.12   |
| 8.4    | 8.4.27   |
| 8.3    | 8.3.36   |
| 8.2    | 8.2.35   |
| < 8.2  | always flagged |

Pre-release builds of a fix (e.g. `8.3.36RC1`, Debian `8.3.36~rc1`) are **not**
treated as the final fixed release — they are reported `UNKNOWN` for manual
review. The scanner does not automatically resolve distro **vendor backports**,
so it keeps the full package version in the report for you to verify.

---

## 2. Prerequisites

- **Python 3.10 or newer** on the machine you run the scan *from*.
- **paramiko** (the only third-party dependency) — install it from
  `requirements.txt`.
- **SSH access** to the targets: one username with either a password, a private
  key, or a loaded SSH agent. The same credentials are tried on every host.
- **Trusted SSH host keys.** Each target's key must already be in your
  `~/.ssh/known_hosts` (or a file passed with `--known-hosts`). Unknown keys are
  rejected unless you opt into trust-on-first-use with `--accept-new`; a *changed*
  key is always rejected. See [SSH connectivity](#6-ssh-connectivity).
- **Network reachability** to TCP 22 on the targets (and to 80/443 if you use
  `--web`).
- **Authorization.** Only scan infrastructure you are permitted to scan.

### Install

```sh
python3 -m pip install -r requirements.txt
```

---

## 3. How to run it

**Step 1 — list your targets** in a CSV, one entry per row in the first column.
CIDR ranges, single IPs and hostnames are all accepted; blank lines, `#`
comments and a header row are ignored. A sample is in `subnets.csv`. Ranges
larger than 65,536 addresses are rejected.

```
subnet
10.0.1.0/24
192.168.50.10
web01.internal.example.com
```

**Step 2 — run the scan.**

Key-based auth, writing a CSV report:

```sh
python3 php2shell_scan.py -s subnets.csv -u admin -k ~/.ssh/id_ed25519 -o results.csv
```

Password auth (prompted — never echoed or stored in shell history):

```sh
python3 php2shell_scan.py -s subnets.csv -u admin --ask-password -o results.csv
```

Add the web probe and an encrypted-key passphrase prompt:

```sh
python3 php2shell_scan.py -s subnets.csv -u admin -k ~/.ssh/id_ed25519 \
    --ask-key-passphrase --web -o results.csv
```

> **Tip:** prefer the `--ask-*` prompt forms over `--password` /
> `--key-passphrase`, which would put secrets in your shell history and process
> list.

### Common options

| Option | Purpose |
|---|---|
| `-s, --subnets FILE` | CSV of targets (**required**). |
| `-u, --username NAME` | SSH username (**required**). |
| `-p, --port N` | SSH port (default 22). |
| `-k, --key PATH` | SSH private key. |
| `--ask-password` / `--password` | Password auth (prefer the prompt form). |
| `--ask-key-passphrase` / `--key-passphrase` | Passphrase for an encrypted key. |
| `--use-agent` | Authenticate via the SSH agent and default keys. |
| `--known-hosts FILE` | Trust this known_hosts file instead of `~/.ssh/known_hosts`. |
| `--accept-new` | Trust an unknown host key on first contact (TOFU), and remember it. |
| `--web` | Also probe HTTP/HTTPS for a PHP version banner. |
| `--http-ports LIST` | Web ports, e.g. `80,443,https:8443` (default `80,443`). |
| `--http-paths LIST` | Paths to try per port, e.g. `/,/index.php` (default `/`). |
| `-w, --workers N` | Concurrent hosts (default 50). |
| `-t, --timeout SEC` | Per-connection timeout (default 8). |
| `--deadline SEC` | Overall per-host budget across web + SSH + discovery (default 0 = off). |
| `-o, --output FILE` | Write the report here (default: stdout). |
| `--format {csv,json}` | Report format (default `csv`). |
| `--quiet` | Suppress the stderr progress/summary (the banner still prints). |

### Bounding slow hosts (`--deadline`)

`--timeout` bounds each individual connection; on a large estate a single
unresponsive host can still stack several of those (web ports, then SSH connect,
then discovery). `--deadline SEC` sets one overall budget per host that the web
probe, SSH connect and discovery **share**. Discovery output is read
incrementally with the budget checked throughout, so a slow steady stream or a
late exit status cannot run past it. When the budget expires, the scanner keeps
whatever evidence it already parsed — a fully-received vulnerable finding stays
`POTENTIALLY_VULNERABLE` — marks the host `incomplete`, closes the channel and
connection, and moves on. Even with no deadline set, discovery gives up after
`--timeout` of no progress rather than blocking forever. It is off by default
(`0`); set it a bit above your worst healthy host, e.g. `--deadline 25`.

---

## 4. How to check the results

The scan tells you its outcome in three ways: the **exit code**, the **stderr
summary**, and the **CSV report**.

### Exit code (best for scripts / CI)

```
2   at least one host is POTENTIALLY_VULNERABLE
1   scan incomplete (any UNKNOWN / HOSTKEY_MISMATCH / AUTH_FAILED / UNREACHABLE /
    ERROR, or any host flagged incomplete)
0   every host scanned cleanly and none are affected
```

```sh
python3 php2shell_scan.py -s subnets.csv -u admin -k ~/.ssh/id_ed25519 -o results.csv
echo "exit code: $?"
```

An exit of **2 can still include incomplete hosts**, so always read the full
report too — don't stop at the first vulnerable host.

### On-screen summary

Unless `--quiet` is set, a summary is printed to stderr: how many hosts were
scanned, counts per status, and an explicit list of the
`POTENTIALLY_VULNERABLE` hosts with the versions that triggered them.

### CSV or JSON

Both formats carry the same host set, fields and evidence, and the exit code is
identical. Choose with `--format` (default `csv`). JSON is handy for pipelines:

```sh
python3 php2shell_scan.py -s subnets.csv -u admin -k ~/.ssh/id_ed25519 \
    --format json -o results.json
```

JSON adds a small envelope — `tool`, `version`, `generated`, `cves`,
`exit_code`, a `summary` of status counts, `scanned`, `incomplete`, and a
`hosts` array. Each host object holds the same fields as the CSV columns below,
with `versions` as a native list. A quick triage with `jq`:

```sh
jq -r '.hosts[] | select(.status=="POTENTIALLY_VULNERABLE" or .incomplete) | .host' results.json
```

### The report columns

Columns: `host, status, php_installed, versions, detail, reachable, ssh_ok,
web_ok, incomplete, error`.

- **`status`** — the headline verdict (see table below).
- **`versions`** — every piece of evidence found (each binary, each package,
  each web banner) with its own per-item verdict, so you can see *what* drove the
  result.
- **`detail`** — human-readable reasoning plus the full raw package versions
  (needed to check a vendor backport).
- **`incomplete`** — `True` whenever the host could not be fully inventoried (for
  example a web banner gave a verdict but SSH failed). A `True` here means "treat
  this result as partial," even if the status looks clean.
- **`error`** — the failure reason, when one applies.

| `status` | Meaning | What to do |
|---|---|---|
| `POTENTIALLY_VULNERABLE` | A discovered version is below its branch's fix, or on a branch older than 8.2. | Prioritise for patching. A vendor backport may already fix it — verify against the full version in `detail`. |
| `NOT_AFFECTED` | All **discovered** runtimes meet the fix thresholds. | Low priority. Not a whole-server guarantee — covers what was discovered only. |
| `UNKNOWN` | Not enough evidence (e.g. web reachable but no banner, or an unparseable build). | Investigate; **do not** treat as clean. |
| `HOSTKEY_MISMATCH` | The server's SSH key doesn't match your trusted entry. | Possible wrong host or MITM — investigate before rerunning. |
| `AUTH_FAILED` / `UNREACHABLE` / `ERROR` | Inventory could not complete. | Fix access/connectivity and rerun. |

A quick way to pull just the hosts that need attention:

```sh
# every host that is vulnerable OR could not be fully checked
awk -F, 'NR==1 || $2=="POTENTIALLY_VULNERABLE" || $9=="True"' results.csv
```

---

## 5. Example output

Against two servers running affected PHP (8.2.32 and 8.3.6):

```
172.25.0.2  POTENTIALLY_VULNERABLE  8.2.32 < 8.2.35 (fixed)  ...  ssh_ok=True web_ok=True incomplete=False
172.25.0.3  POTENTIALLY_VULNERABLE  8.3.6  < 8.3.36 (fixed)  ...  ssh_ok=True web_ok=True incomplete=False
exit code: 2
```

---

## 6. SSH connectivity

By default the scanner verifies each server's identity against your
`~/.ssh/known_hosts` and **rejects unknown hosts**, so credentials and results
are never sent to an unverified server.

- `--known-hosts FILE` trusts a specific file (loaded read-only).
- `--accept-new` trusts an unknown key on first contact and **writes it** to the
  trusted file (`--known-hosts`, else `~/.ssh/known_hosts`), like OpenSSH
  `StrictHostKeyChecking=accept-new`. Because the key is persisted, a later run
  detects a *changed* key as `HOSTKEY_MISMATCH`. Convenient for a first scan of a
  fresh subnet; still weaker than pre-seeding, since the very first contact is
  trusted blindly.
- `--use-agent` authenticates through the running SSH agent and default keys, on
  its own or alongside `--key` / `--password`.

On a fresh subnet, prefer pre-seeding trust over `--accept-new`. `ssh-keyscan`
does not expand CIDR, so expand the range, collect keys into a staging file,
review it, and only then trust it:

```sh
# 1. Expand the CIDR to one host per line:
python3 -c "import ipaddress,sys; [print(h) for n in sys.argv[1:] for h in ipaddress.ip_network(n).hosts()]" 10.0.1.0/24 > hosts.txt
# 2. Collect keys into a STAGING file (not yet trusted):
ssh-keyscan -t ed25519,rsa -f hosts.txt > staged_known_hosts 2>/dev/null
# 3. Review staged_known_hosts, then trust it:
cat staged_known_hosts >> ~/.ssh/known_hosts
```

---

## 7. Web-facing probe (`--web`)

PHP advertises its version in the `X-Powered-By` or `Server` header unless
`expose_php` is Off. With `--web`, the scanner sends one HEAD (falling back to
GET) per path, reads **headers only**, downloads no page body, and does not
verify TLS certificates (internal hosts are often self-signed). It probes `/` by
default; pass `--http-paths "/,/index.php,/info.php"` to try PHP endpoints in
order until a banner appears.

```sh
python3 php2shell_scan.py -s subnets.csv -u admin -k ~/.ssh/id_ed25519 --web -o results.csv
python3 php2shell_scan.py -s subnets.csv -u admin --ask-password --web --http-ports "80,443,https:8443"
```

A host reachable over HTTP with **no** PHP banner is reported `UNKNOWN`
(`expose_php` may simply be Off), never assumed safe.

---

## 8. Scope and limitations

Discovery covers common CLI/FPM names and standard distro, cPanel, Plesk and
Remi paths, plus installed runtime package evidence. It does **not** inspect
container contents, arbitrary custom install directories, remote managed
services, or whether already-running workers have loaded the patched binary.
After patching, restart the relevant services through your normal process and
verify the PHP runtime serving each application, including containers. A
`POTENTIALLY_VULNERABLE` result on a distro-packaged PHP should be checked
against your OS or hosting vendor advisory, since a backport may already carry
the fix without changing the upstream version number.

---

## 9. Tests

Fast, dependency-free unit suite (stubs paramiko if it isn't installed):

```sh
python3 -m unittest -v test_inventory
```

A Docker-based integration harness lives in `test/docker/` (two images pinned to
genuinely affected PHP builds, with build-time version assertions).

---

## 10. Official advisories

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

---

## Copyright

Copyright (c) 2026 Belsis Meletis. All rights reserved.

## Disclaimer

This script is provided **as is**, to help Security Administrators who manage
large infrastructures detect vulnerable PHP installations so they can patch
them. It is a read-only inventory aid and is not a guarantee of completeness or
accuracy. Use it only on infrastructure you are authorized to scan, and verify
its findings before acting on them. The author accepts **no responsibility or
liability** for any issue, loss, or damage arising from the use of, or inability
to use, this script.
