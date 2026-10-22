"""Offline regression checks; no SSH connections are made."""
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

# Keep parsing tests usable without installing SSH dependencies.
try:
    import paramiko
except ImportError:
    sys.modules['paramiko'] = types.ModuleType('paramiko')
import php2shell_scan as scanner


class FakeChannel:
    """Minimal paramiko-style channel for offline tests of the incremental reader.

    stall=True serves stdout/stderr once and then never reports exit-ready, so the
    scanner's reader hits its timeout with the data already buffered — reproducing
    'full output received, then a timeout'."""
    def __init__(self, out=b'', err=b'', status=0, stall=False):
        self._out = bytearray(out)
        self._err = bytearray(err)
        self._status = status
        self._stall = stall

    def settimeout(self, t):
        pass

    def recv_ready(self):
        return bool(self._out)

    def recv(self, n):
        d, self._out = bytes(self._out[:n]), self._out[n:]
        return d

    def recv_stderr_ready(self):
        return bool(self._err)

    def recv_stderr(self, n):
        d, self._err = bytes(self._err[:n]), self._err[n:]
        return d

    def exit_status_ready(self):
        if self._stall:
            return False
        return not self._out and not self._err

    def recv_exit_status(self):
        return self._status

    def close(self):
        pass


def _exec_return(output, err=b'', status=0, stall=False):
    """Build an (stdin, stdout, stderr) triple whose stdout.channel is a FakeChannel."""
    out = output.encode() if isinstance(output, str) else output
    errb = err.encode() if isinstance(err, str) else err
    stdout = types.SimpleNamespace(channel=FakeChannel(out, errb, status, stall))
    return None, stdout, types.SimpleNamespace()


class InventoryTests(unittest.TestCase):
    def test_release_boundaries(self):
        for version in scanner.FIXED_VERSIONS.values():
            self.assertEqual(scanner.classify_version(version)[0], 'NOT_AFFECTED')
            previous = (*version[:2], version[2] - 1)
            self.assertEqual(scanner.classify_version(previous)[0], 'POTENTIALLY_VULNERABLE')

    def scan(self, output):
        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, **kwargs): pass
            def exec_command(self, *args, **kwargs): return _exec_return(output)
            def close(self): pass
        with patch.object(scanner.paramiko, 'SSHClient', Client, create=True), patch.object(scanner.paramiko, 'RejectPolicy', lambda: None, create=True), patch.object(scanner, 'port_open', return_value=True):
            return scanner.scan_host('offline-test', types.SimpleNamespace(port=22, timeout=1, username='test', password='unused'), None)

    def test_package_only_is_not_no_php(self):
        result = self.scan('PKG=php8.3-fpm 8.3.6-0ubuntu0.24.04.13\nMETA=discovery_complete\n')
        self.assertTrue(result.php_installed)
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')
        self.assertIn('8.3.6-0ubuntu0.24.04.13', result.detail)

    def test_incomplete_discovery(self):
        self.assertEqual(self.scan('').status, 'ERROR')

    def test_no_evidence_is_unknown(self):
        self.assertEqual(self.scan('META=discovery_complete\n').status, 'UNKNOWN')

    def test_old_fpm_overrides_fixed_cli(self):
        result = self.scan('BIN=/usr/bin/php :: PHP 8.3.36\nBIN=/usr/sbin/php-fpm8.2 :: PHP 8.2.34\nMETA=discovery_complete\n')
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')

    def test_remi_package_recognized(self):
        # Remi SCL-style package (php82-php-fpm) must be recognized as a runtime.
        result = self.scan('PKG=php82-php-fpm 8.2.34-1.el9.remi\nMETA=discovery_complete\n')
        self.assertTrue(result.php_installed)
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')
        self.assertIn('8.2.34', result.detail)

    def test_unparseable_runtime_package_is_unknown_not_cleared(self):
        # A patched CLI plus a runtime package with an unparseable version on a
        # DIFFERENT branch must not be cleared: the unknown package forces UNKNOWN.
        result = self.scan(
            'BIN=/usr/bin/php :: PHP 8.3.40 (cli)\n'
            'PKG=php82-php-fpm 8.2-weird-nonsemver\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertIn('8.2-weird-nonsemver', result.detail)

    def test_metapackage_does_not_force_unknown(self):
        # A Debian metapackage (php-cli 2:8.3+93) whose branch is already covered
        # by a parsed package must NOT drag a patched host to UNKNOWN.
        result = self.scan(
            'BIN=/usr/bin/php :: PHP 8.3.40 (cli)\n'
            'PKG=php8.3-cli 8.3.40-1\nPKG=php-cli 2:8.3+93\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'NOT_AFFECTED')

    def test_unparseable_fpm_not_cleared_by_patched_cli_same_branch(self):
        # A concrete versioned FPM package with an unparseable version must NOT be
        # dropped just because a patched CLI covers its branch; only true Debian
        # metapackages may be dropped that way.
        result = self.scan(
            'PKG=php8.3-cli 8.3.36-1\nPKG=php8.3-fpm vendor-build\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertIn('vendor-build', result.detail)

    def test_mod_php_metapackage_does_not_force_unknown(self):
        # The unversioned Debian mod_php metapackage (libapache2-mod-php 2:8.3+93)
        # carries only a branch marker; when a real versioned package covers 8.3 it
        # must not leak a spurious UNKNOWN finding.
        result = self.scan(
            'PKG=php8.3-cli 8.3.40-1\nPKG=libapache2-mod-php8.3 8.3.40-1\n'
            'PKG=libapache2-mod-php 2:8.3+93\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'NOT_AFFECTED')

    def test_binary_without_version_forces_incomplete_unknown(self):
        # A patched CLI plus a discovered binary that could not report a version
        # must NOT read as NOT_AFFECTED: the host is incomplete and UNKNOWN.
        result = self.scan(
            'BIN=/usr/bin/php :: PHP 8.3.40 (cli)\n'
            'BINERR=/usr/sbin/php-fpm8.2\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertTrue(result.incomplete)

    def test_discovery_gap_preserves_vulnerable_verdict(self):
        # A discovery gap must never downgrade a real vulnerable finding; the host
        # stays POTENTIALLY_VULNERABLE but is flagged incomplete.
        result = self.scan(
            'BIN=/usr/bin/php :: PHP 8.3.40 (cli)\n'
            'BIN=/usr/sbin/php-fpm8.2 :: PHP 8.2.10\n'
            'BINERR=/opt/custom/php\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')
        self.assertTrue(result.incomplete)

    def test_failed_package_query_forces_incomplete_unknown(self):
        # A genuinely failed package query alongside a patched runtime -> UNKNOWN.
        result = self.scan(
            'PKG=php8.3-cli 8.3.40-1\nQUERYERR=dpkg-query\n'
            'META=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertTrue(result.incomplete)

    def test_clean_binary_host_is_not_incomplete(self):
        # No discovery gaps: a patched runtime must read cleanly, not incomplete.
        result = self.scan('BIN=/usr/bin/php :: PHP 8.3.40 (cli)\nMETA=discovery_complete\n')
        self.assertEqual(result.status, 'NOT_AFFECTED')
        self.assertFalse(result.incomplete)

    def test_prerelease_cli_is_unknown(self):
        # 8.3.36RC1 is a prerelease of the fix and must NOT read as fixed 8.3.36.
        result = self.scan('BIN=/usr/bin/php :: PHP 8.3.36RC1 (cli)\nMETA=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertIn('prerelease', result.detail)

    def test_debian_prerelease_package_is_unknown(self):
        # Debian '~rc1' prerelease marker in a package version -> UNKNOWN.
        result = self.scan('PKG=php8.3-fpm 8.3.36~rc1-1\nMETA=discovery_complete\n')
        self.assertEqual(result.status, 'UNKNOWN')

    def scan_web(self, ssh_output, web_version):
        """Run a scan with the web probe returning one banner of web_version."""
        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, **kwargs): pass
            def exec_command(self, *a, **k): return _exec_return(ssh_output)
            def close(self): pass

        def fake_probe(host, ports, timeout, paths=('/',), deadline=None):
            return [{'scheme': 'https', 'port': 443, 'reachable': True,
                     'version': web_version, 'banner': 'PHP/%d.%d.%d' % web_version,
                     'http_status': 200, 'path': '/'}]

        args = types.SimpleNamespace(port=22, timeout=1, username='t', password='x',
                                     web=True, http_ports=[('https', 443)], http_paths=['/'])
        with patch.object(scanner.paramiko, 'SSHClient', Client, create=True), \
             patch.object(scanner.paramiko, 'RejectPolicy', lambda: None, create=True), \
             patch.object(scanner, 'probe_web', fake_probe), \
             patch.object(scanner, 'port_open', return_value=True):
            return scanner.scan_host('offline-test', args, None)

    def test_patched_web_banner_with_ssh_nophp_is_incomplete_unknown(self):
        # SSH finds no runtime, web shows a patched version: NOT a clean NOT_AFFECTED.
        result = self.scan_web('META=discovery_complete\n', (8, 3, 36))
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertTrue(result.incomplete)

    def test_vulnerable_web_banner_with_ssh_nophp_stays_vulnerable(self):
        # Vulnerable evidence takes priority, but the host is still flagged incomplete.
        result = self.scan_web('META=discovery_complete\n', (8, 2, 10))
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')
        self.assertTrue(result.incomplete)

    def test_prerelease_web_banner_is_not_cleared(self):
        # A prerelease banner (PHP/8.3.36RC1) must not be read as the fixed release.
        ssh_output = 'BIN=/usr/bin/php :: PHP 8.3.36RC1 (cli)\nMETA=discovery_complete\n'

        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, **kwargs): pass
            def exec_command(self, *a, **k): return _exec_return(ssh_output)
            def close(self): pass

        def fake_probe(host, ports, timeout, paths=('/',), deadline=None):
            return [{'scheme': 'https', 'port': 443, 'reachable': True,
                     'version': (8, 3, 36), 'banner': 'PHP/8.3.36RC1',
                     'http_status': 200, 'path': '/'}]

        args = types.SimpleNamespace(port=22, timeout=1, username='t', password='x',
                                     web=True, http_ports=[('https', 443)], http_paths=['/'])
        with patch.object(scanner.paramiko, 'SSHClient', Client, create=True), \
             patch.object(scanner.paramiko, 'RejectPolicy', lambda: None, create=True), \
             patch.object(scanner, 'probe_web', fake_probe), \
             patch.object(scanner, 'port_open', return_value=True):
            result = scanner.scan_host('offline-test', args, None)
        self.assertEqual(result.status, 'UNKNOWN')

    def test_web_banner_parsing_does_not_crash_on_suffix(self):
        # Regression: WEB_VERSION_RE captures a 4th (suffix) group. Converting the
        # whole match to int raised ValueError even on a plain 'PHP/8.2.34' (empty
        # suffix), aborting the probe. The real probe_web path must parse the
        # numeric version and keep the suffix out of the tuple.
        class FakeResp:
            def __init__(self, header):
                self.status, self._h = 200, header
            def getheaders(self):
                return [('X-Powered-By', self._h)]

        class FakeConn:
            last_header = 'PHP/8.2.34'
            def __init__(self, *a, **k): pass
            def request(self, *a, **k): pass
            def getresponse(self): return FakeResp(FakeConn.last_header)
            def close(self): pass

        with patch.object(scanner.http.client, 'HTTPConnection', FakeConn):
            FakeConn.last_header = 'PHP/8.2.34'  # stable, empty suffix
            res = scanner.probe_web('h', [('http', 80)], 1, ('/',))
            self.assertEqual(res[0]['version'], (8, 2, 34))
            self.assertTrue(res[0]['reachable'])

            FakeConn.last_header = 'PHP/8.3.36RC1'  # prerelease suffix
            res = scanner.probe_web('h', [('http', 80)], 1, ('/',))
            self.assertEqual(res[0]['version'], (8, 3, 36))

    def test_accept_new_rejects_changed_key(self):
        # The accept-new policy must treat a second, different key for the same
        # host/type as a mismatch, never trust it, even under concurrency.
        if not hasattr(scanner.paramiko, 'BadHostKeyException'):
            scanner.paramiko.BadHostKeyException = type(
                'BadHostKeyException', (Exception,), {})

        class Key:
            def __init__(self, name, b64):
                self._n, self._b = name, b64
            def get_name(self):
                return self._n
            def get_base64(self):
                return self._b

        class HostKeys:
            def __init__(self):
                self.added = []
            def add(self, host, name, key):
                self.added.append((host, name, key.get_base64()))

        class Client:
            def __init__(self):
                self._hk = HostKeys()
            def get_host_keys(self):
                return self._hk

        import tempfile, os
        path = tempfile.mktemp(suffix='_known_hosts')
        try:
            policy = scanner._AcceptNewPolicy(path)
            c1 = Client()
            key1 = Key('ssh-ed25519', 'FIRSTKEYAAAA')
            policy.missing_host_key(c1, '[10.0.0.9]:22', key1)   # first contact
            self.assertIn(('[10.0.0.9]:22', 'ssh-ed25519', 'FIRSTKEYAAAA'), c1._hk.added)
            self.assertIn('FIRSTKEYAAAA', Path(path).read_text())

            # Same key again: accepted, no exception.
            c2 = Client()
            policy.missing_host_key(c2, '[10.0.0.9]:22', Key('ssh-ed25519', 'FIRSTKEYAAAA'))
            self.assertTrue(c2._hk.added)

            # Different key, same host/type: rejected, not trusted.
            c3 = Client()
            with self.assertRaises(scanner.paramiko.BadHostKeyException):
                policy.missing_host_key(c3, '[10.0.0.9]:22', Key('ssh-ed25519', 'SECONDKEYBBBB'))
            self.assertEqual(c3._hk.added, [])
            self.assertNotIn('SECONDKEYBBBB', Path(path).read_text())
        finally:
            if os.path.exists(path):
                os.unlink(path)

    # ---- per-host deadline ----
    def test_phase_timeout_caps_and_expires(self):
        import time
        self.assertEqual(scanner.phase_timeout(8.0, None), 8.0)   # no deadline -> base
        future = time.monotonic() + 100
        self.assertLessEqual(scanner.phase_timeout(8.0, future), 8.0)  # capped by base
        self.assertGreater(scanner.phase_timeout(8.0, future), 0)
        past = time.monotonic() - 1
        self.assertEqual(scanner.phase_timeout(8.0, past), 0.0)   # expired -> 0

    def test_ssh_detect_returns_timeout_when_deadline_passed(self):
        import time
        res = scanner.HostResult(host='h')
        args = types.SimpleNamespace(port=22, timeout=5, username='u', password='p')
        # A deadline already in the past: _ssh_detect must bail out before any
        # network I/O, reporting TIMEOUT and discovery_incomplete=True.
        outcome, findings, detail, pkg_note, incomplete = scanner._ssh_detect(
            'h', args, None, res, deadline=time.monotonic() - 1)
        self.assertEqual(outcome, 'TIMEOUT')
        self.assertEqual(findings, [])
        self.assertTrue(incomplete)

    def test_scan_host_timeout_is_incomplete_unknown_keeps_web_evidence(self):
        # A per-host deadline expiry must keep collected web evidence, mark the
        # host incomplete, and resolve to UNKNOWN (not a clean verdict).
        def fake_probe(host, ports, timeout, paths=('/',), deadline=None):
            return [{'scheme': 'https', 'port': 443, 'reachable': True,
                     'version': None, 'banner': 'Apache', 'http_status': 200, 'path': '/'}]

        def fake_ssh(host, args, pkey, res, deadline=None):
            return 'TIMEOUT', [], 'PHP discovery timed out', '', True

        args = types.SimpleNamespace(port=22, timeout=1, username='u', password='p',
                                     web=True, http_ports=[('https', 443)], http_paths=['/'],
                                     deadline=5)
        with patch.object(scanner, 'probe_web', fake_probe), \
             patch.object(scanner, '_ssh_detect', fake_ssh):
            result = scanner.scan_host('h', args, None)
        self.assertEqual(result.status, 'UNKNOWN')
        self.assertTrue(result.incomplete)
        self.assertTrue(result.web_ok)  # web evidence retained

    def test_timeout_after_full_output_preserves_vulnerable_findings(self):
        # Reviewer repro: stdout fully received (identifies vulnerable PHP), then the
        # exchange stalls past the budget. Parsed findings must survive -> the host
        # stays POTENTIALLY_VULNERABLE with incomplete=True, not an empty UNKNOWN.
        vuln = ('PKG=php8.2-cli 8.2.10-1\nBIN=/usr/bin/php :: PHP 8.2.10 (cli)\n'
                'META=discovery_complete\n')

        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, **kwargs): pass
            def exec_command(self, *a, **k): return _exec_return(vuln, stall=True)
            def close(self): pass

        # Small --timeout so the 'no progress' idle cap fires quickly; no overall
        # deadline needed to exercise the stall path.
        args = types.SimpleNamespace(port=22, timeout=0.2, username='u', password='p')
        with patch.object(scanner.paramiko, 'SSHClient', Client, create=True), \
             patch.object(scanner.paramiko, 'RejectPolicy', lambda: None, create=True), \
             patch.object(scanner, 'port_open', return_value=True):
            result = scanner.scan_host('offline-test', args, None)
        self.assertEqual(result.status, 'POTENTIALLY_VULNERABLE')
        self.assertTrue(result.incomplete)
        self.assertTrue(result.versions)  # findings preserved, not discarded
        self.assertIn('timed out', result.detail)

    # ---- JSON report ----
    def test_json_report_matches_csv_fields_and_exit_code(self):
        results = [
            scanner.HostResult(host='a', status='POTENTIALLY_VULNERABLE', php_installed=True,
                               reachable=True, ssh_ok=True, versions=['BIN=/usr/bin/php -> 8.2.1 [POTENTIALLY_VULNERABLE]'],
                               detail='8.2.1 < 8.2.35'),
            scanner.HostResult(host='b', status='NOT_AFFECTED', php_installed=True,
                               reachable=True, ssh_ok=True, versions=['BIN=/usr/bin/php -> 8.3.40 [NOT_AFFECTED]']),
        ]
        import tempfile, os, json as _json
        path = tempfile.mktemp(suffix='.json')
        try:
            scanner.write_report(results, path, 'json')
            payload = _json.loads(Path(path).read_text())
        finally:
            if os.path.exists(path):
                os.unlink(path)
        self.assertEqual(payload['exit_code'], scanner._exit_code(results))
        self.assertEqual(payload['exit_code'], 2)  # a is vulnerable
        self.assertEqual(payload['scanned'], 2)
        hosts = {h['host']: h for h in payload['hosts']}
        self.assertEqual(set(hosts), {'a', 'b'})
        # Same field set as CSV, versions as a native list.
        for key in ('host', 'status', 'php_installed', 'versions', 'detail',
                    'reachable', 'ssh_ok', 'web_ok', 'incomplete', 'error'):
            self.assertIn(key, hosts['a'])
        self.assertIsInstance(hosts['a']['versions'], list)
        self.assertEqual(hosts['a']['status'], 'POTENTIALLY_VULNERABLE')


if __name__ == '__main__':
    unittest.main()
