"""Real, loopback-only OpenSSL checks for recorded certificate snapshots.

All keys and certificates are disposable and generated for each test class.
The test CA is passed only to child OpenSSL commands; system trust is unchanged.
"""
import base64
from contextlib import contextmanager
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from cgp_cert_manager import bootstrap, core, recovery, resolution
from cgp_cert_manager.transactions import Journal


def openssl(*args):
    return subprocess.run(
        ["openssl", *map(str, args)], input=b"", check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
    ).stdout


def block(value):
    return "[" + base64.b64encode(value).decode("ascii") + "]"


@contextmanager
def tls_listener(certificate, key):
    """Serve a generated chain on an OS-selected, local TCP port."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.1)
    stop = threading.Event()
    failures = []

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not stop.is_set():
                    failures.append("TLS listener failed before shutdown")
                return
            with connection:
                connection.settimeout(3)
                try:
                    with context.wrap_socket(connection, server_side=True) as stream:
                        while stream.recv(4096):
                            pass
                        # Send close_notify so OpenSSL does not mistake EOF for
                        # a truncated TLS connection on OpenSSL 3.x.
                        stream.unwrap().close()
                except (ssl.SSLError, ConnectionError):
                    # Expected when a negative test rejects the certificate.
                    pass
                except Exception as exc:
                    failures.append(type(exc).__name__)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield {"host": "127.0.0.1", "port": listener.getsockname()[1],
               "sni": "example.com"}
    finally:
        stop.set()
        listener.close()
        worker.join(5)
        if worker.is_alive():
            raise AssertionError("Local TLS listener did not stop")
        if failures:
            raise AssertionError("Local TLS listener failed: " + ", ".join(failures))


class RecordedSnapshotTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.path = Path(cls.tmp.name)
        root = cls.path / "root.pem"
        root_key = cls.path / "root.key"
        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", "2", "-subj", "/CN=Snapshot Test Root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", root_key, "-out", root)
        intermediate = cls.path / "intermediate.pem"
        intermediate_key = cls.path / "intermediate.key"
        intermediate_csr = cls.path / "intermediate.csr"
        intermediate_ext = cls.path / "intermediate.ext"
        intermediate_ext.write_text(
            "basicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        )
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", "/CN=Snapshot Test Intermediate",
                "-keyout", intermediate_key, "-out", intermediate_csr)
        openssl("x509", "-req", "-in", intermediate_csr,
                "-CA", root, "-CAkey", root_key, "-set_serial", "2",
                "-days", "2", "-sha256", "-extfile", intermediate_ext,
                "-out", intermediate)
        cls.settings = {}
        for serial, name in enumerate(("old", "new"), start=3):
            key = cls.path / (name + ".key")
            csr = cls.path / (name + ".csr")
            cert = cls.path / (name + ".pem")
            ext = cls.path / (name + ".ext")
            ext.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:example.com,DNS:" + name + ".example.com\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
            )
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                    "-subj", "/CN=example.com", "-keyout", key, "-out", csr)
            openssl("x509", "-req", "-in", csr,
                    "-CA", intermediate, "-CAkey", intermediate_key,
                    "-set_serial", str(serial), "-days", "2", "-sha256",
                    "-extfile", ext, "-out", cert)
            (cls.path / (name + "-fullchain.pem")).write_bytes(
                cert.read_bytes() + intermediate.read_bytes())
            cls.settings[name] = {
                "PrivateSecureKey": block(openssl("pkey", "-in", key, "-outform", "DER")),
                "SecureCertificate": block(openssl("x509", "-in", cert, "-outform", "DER")),
                "CAChain": block(openssl("x509", "-in", intermediate, "-outform", "DER")),
                "CertificateType": "YES",
            }
        (cls.path / "old-with-root.pem").write_bytes(
            (cls.path / "old-fullchain.pem").read_bytes() + root.read_bytes())
        lineage = cls.path / "new-lineage" / "example.com"
        lineage.mkdir(parents=True)
        (lineage / "cert.pem").write_bytes((cls.path / "new.pem").read_bytes())
        (lineage / "privkey.pem").write_bytes((cls.path / "new.key").read_bytes())
        (lineage / "chain.pem").write_bytes(intermediate.read_bytes())

        # Use the long-established `ca` date flags, also available on Ubuntu
        # 24.04's OpenSSL, to avoid dependence on the wall clock or sleep.
        (cls.path / "index").write_text("")
        (cls.path / "serial").write_text("10\n")
        config = cls.path / "ca.cnf"
        config.write_text(
            "[ca]\ndefault_ca=test\n[test]\n"
            f"database={cls.path / 'index'}\nserial={cls.path / 'serial'}\n"
            f"new_certs_dir={cls.path}\ncertificate={intermediate}\n"
            f"private_key={intermediate_key}\n"
            "default_md=sha256\ndefault_days=2\npolicy=policy\n"
            "x509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\n"
            + (cls.path / "old.ext").read_text()
        )
        expired = cls.path / "expired.pem"
        openssl("ca", "-batch", "-notext", "-config", config,
                "-startdate", "20000101000000Z", "-enddate", "20010101000000Z",
                "-in", cls.path / "old.csr", "-out", expired)
        cls.expired = dict(cls.settings["old"], SecureCertificate=block(
            openssl("x509", "-in", expired, "-outform", "DER")))

    def setUp(self):
        run = core.run

        def with_test_trust(*args, **kwargs):
            # All parsing, public-key comparisons, trust checks and TLS probes
            # execute real OpenSSL. Only the child process's trust file changes.
            args = list(args)
            if "-CAfile" in args:
                args[args.index("-CAfile") + 1] = str(self.path / "root.pem")
            return run(*args, **kwargs)

        trust = patch.object(core, "run", side_effect=with_test_trust)
        trust.start()
        self.addCleanup(trust.stop)

    def serve(self, name="old", chain=None):
        return tls_listener(self.path / (chain or (name + "-fullchain.pem")),
                            self.path / (name + ".key"))

    def test_saved_old_chain_ignores_current_certbot_lineage(self):
        with self.serve() as endpoint, \
                patch.object(core, "LIVE", self.path / "new-lineage"), \
                patch.object(core, "expected_chain", side_effect=AssertionError("Mutable lineage read")):
            # A rollback must still work for the old-only name after SANs change.
            recovery.verify_snapshot(self.settings["old"], [dict(endpoint, sni="old.example.com")])

    def test_live_new_certificate_rejects_old_snapshot(self):
        with self.serve("new") as endpoint:
            with self.assertRaisesRegex(core.Error, "TLS certificate/chain mismatch"):
                recovery.verify_snapshot(self.settings["old"], [endpoint])

    def test_valid_chain_with_extra_root_is_not_the_recorded_chain(self):
        with self.serve(chain="old-with-root.pem") as endpoint:
            with self.assertRaisesRegex(core.Error, "TLS certificate/chain mismatch"):
                recovery.verify_snapshot(self.settings["old"], [endpoint])

    def test_missing_presented_intermediate_fails(self):
        with self.serve(chain="old.pem") as endpoint:
            with self.assertRaisesRegex(core.Error, "openssl failed"):
                recovery.verify_snapshot(self.settings["old"], [endpoint])

    def test_hostname_mismatch_fails(self):
        with self.serve() as endpoint:
            with self.assertRaisesRegex(core.Error, "openssl failed"):
                recovery.verify_snapshot(self.settings["old"], [dict(endpoint, sni="new.example.com")])

    def test_mismatched_private_key_fails_before_network(self):
        snapshot = dict(self.settings["old"], PrivateSecureKey=self.settings["new"]["PrivateSecureKey"])
        with patch.object(core, "probe_tls") as probe:
            with self.assertRaisesRegex(core.Error, "Backup key mismatch"):
                recovery.verify_snapshot(snapshot, [{"port": 443, "sni": "example.com"}])
            probe.assert_not_called()

    def test_expired_snapshot_fails_before_network(self):
        with patch.object(core, "probe_tls") as probe:
            with self.assertRaisesRegex(core.Error, "openssl failed"):
                recovery.verify_snapshot(self.expired, [{"port": 443, "sni": "example.com"}])
            probe.assert_not_called()

    def test_bootstrap_readiness_accepts_real_expired_snapshot_without_crypto(self):
        # Establish expiry with the real OpenSSL parser before forbidding all
        # crypto below.  Capture eligibility must not prevent later renewal.
        self.assertLess(core.installed_info(self.expired)["days"], 0)
        cfg = {"communigate": {"url": "http://127.0.0.1:8100/CLI/"}}
        response = "{" + "".join(name + "=" + value + ";"
                                  for name, value in self.expired.items()) + "}"
        with patch.object(core, "cli", return_value=response) as read, \
                patch.object(core, "run", side_effect=AssertionError("Readiness attempted crypto")) as run, \
                patch.object(core, "validate_backup") as validate, \
                patch.object(core, "probe_tls") as probe, \
                patch.object(recovery, "verify_snapshot") as verify:
            inspection = bootstrap.inspect(cfg, "example.com")
            self.assertTrue(inspection.report["deployment_ready"])
            self.assertTrue(inspection.report["explicit_snapshot_complete"])
            self.assertFalse(inspection.report["automatic_bootstrap"])
            self.assertEqual(inspection.settings, self.expired)
            self.assertEqual(bootstrap.require_ready(cfg, "example.com"), self.expired)
            self.assertEqual(read.call_count, 8)
            run.assert_not_called()
            validate.assert_not_called()
            probe.assert_not_called()
            verify.assert_not_called()

    def test_real_expired_previous_requires_explicit_unverified_acceptance(self):
        endpoint = {"port": 443, "sni": "example.com"}
        with self.assertRaisesRegex(core.Error, "openssl failed"):
            recovery.verify_snapshot(self.expired, [endpoint])
        cfg = {"communigate": {"url": "http://127.0.0.1:8100/CLI/"}}
        identity = recovery.server_identity(cfg, "a" * 32)
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(core, "STATE", Path(tmp)), \
                patch.object(core, "current", return_value=self.expired), \
                patch.object(core, "update") as update, \
                patch.object(recovery, "server_identity", return_value=identity), \
                patch.object(recovery, "verify_snapshot", side_effect=AssertionError("Cannot claim TLS proof")):
            journal = Journal(Path(tmp) / "transactions")
            journal.prepare("example.com", self.expired, self.settings["new"], [endpoint], identity)
            token = resolution.preview(cfg, "example.com")["confirmation_token"]
            result = resolution.acknowledge(cfg, "example.com", token,
                                            "Confirmed expired certificate; accept previous settings")
            self.assertEqual(result["result"], "acknowledged_unverified")
            self.assertEqual(result["tls"], "unverified")
            self.assertIsNone(journal.read("example.com"))
            update.assert_not_called()

    def test_untrusted_chain_fails_before_network(self):
        # A valid DER root in place of the issuer cannot validate this leaf.
        snapshot = dict(self.settings["old"], CAChain=block(
            openssl("x509", "-in", self.path / "root.pem", "-outform", "DER")))
        with patch.object(core, "probe_tls") as probe:
            with self.assertRaisesRegex(core.Error, "openssl failed"):
                recovery.verify_snapshot(snapshot, [{"port": 443, "sni": "example.com"}])
            probe.assert_not_called()
