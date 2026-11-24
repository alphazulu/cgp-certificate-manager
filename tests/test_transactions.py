import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cgp_cert_manager import core
from cgp_cert_manager.transactions import Journal, JournalError, classify, durable_json, validate, sync_directory

def settings(value="YQ=="):
    return dict(PrivateSecureKey="["+value+"]", SecureCertificate="[YQ==]", CAChain="[YQ==]", CertificateType="YES")

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.j=Journal(self.root/"transactions")
        self.old=settings()
        self.new=settings("Yg==")

    def prepare(self):
        return self.j.prepare("example.com",self.old,self.new,[{"port":443,"sni":"example.com"}],"server")

    def test_durable_lifecycle(self):
        self.assertIsNone(self.j.read("example.com"))
        self.prepare()
        self.assertEqual(self.j.path("example.com").stat().st_mode & 0o777,0o600)
        self.assertEqual(self.j.directory.stat().st_mode & 0o777,0o700)
        for phase in ("applying","applied","verifying","committed"):
            self.j.transition("example.com",phase)
            self.assertEqual(Journal(self.j.directory).read("example.com")["phase"],phase)
        self.j.finish("example.com")
        self.assertIsNone(self.j.read("example.com"))

    def test_restore_lifecycle(self):
        self.prepare()
        self.j.transition("example.com","restoring")
        self.j.transition("example.com","restored")
        self.j.finish("example.com")

    def test_refuses_unresolved_and_invalid_transition(self):
        self.prepare()
        with self.assertRaises(JournalError): self.prepare()
        with self.assertRaises(JournalError): self.j.transition("example.com","committed")
        with self.assertRaises(JournalError): self.j.finish("example.com")
        with self.assertRaises(JournalError): self.j.transition("other.com","applying")
        with self.assertRaises(JournalError): self.j.finish("other.com")

    def test_classification(self):
        r=self.prepare()
        self.assertEqual(classify(r,self.old),"previous")
        self.assertEqual(classify(r,self.new),"intended")
        self.assertEqual(classify(r,{}),"unknown")

    def test_unsafe_directory(self):
        self.j.directory.mkdir(mode=0o755)
        self.j.directory.chmod(0o755)
        with self.assertRaises(JournalError): self.prepare()

    def test_unsafe_file(self):
        self.prepare()
        self.j.path("example.com").chmod(0o644)
        with self.assertRaises(JournalError): self.j.read("example.com")

    def test_corrupt_file(self):
        self.prepare()
        self.j.path("example.com").write_text("not json")
        with self.assertRaises(JournalError): self.j.read("example.com")

    def test_invalid_record(self):
        r=self.prepare()
        for changes in ({"schema":2},{"domain":"other.com"},{"phase":"bad"},{"previous":{}},{"intended":dict(self.new,CAChain="bad;")},{"endpoints":None},{"config_identity":""}):
            with self.subTest(changes=changes):
                with self.assertRaises(JournalError): validate(dict(r,**changes),"example.com")

    def test_atomic_replace_failure_keeps_previous(self):
        r=self.prepare()
        with patch("cgp_cert_manager.transactions.os.replace",side_effect=OSError()):
            with self.assertRaises(OSError): self.j.transition("example.com","applying")
        self.assertEqual(self.j.read("example.com"),r)
        self.assertEqual(list(self.j.directory.iterdir()),[self.j.path("example.com")])

    def test_directory_sync_failure_propagates(self):
        with patch("cgp_cert_manager.transactions.os.fsync",side_effect=OSError()):
            with self.assertRaises(OSError): sync_directory(self.root)

    def test_symlink_rejected(self):
        self.prepare()
        path=self.j.path("example.com")
        target=self.root/"target"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(OSError): self.j.read("example.com")
