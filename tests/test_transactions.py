import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
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
        with self.assertRaises(JournalError): self.j.transition("example.com", [])

    def test_classification(self):
        r=self.prepare()
        self.assertEqual(classify(r,self.old),"previous")
        self.assertEqual(classify(r,self.new),"intended")
        self.assertEqual(classify(r,{}),"unknown")
        self.assertEqual(classify(dict(r, intended=self.old),self.old),"both")

    def test_reads_and_listing_have_no_write_side_effects(self):
        with patch("cgp_cert_manager.transactions.sync_directory") as sync,patch.object(Path,"mkdir") as mkdir:
            self.assertIsNone(self.j.read("example.com"))
            self.assertEqual(self.j.domains(),[])
            mkdir.assert_not_called()
            sync.assert_not_called()
        self.prepare()
        with patch("cgp_cert_manager.transactions.sync_directory") as sync,patch.object(Path,"mkdir") as mkdir:
            self.assertEqual(self.j.read("example.com")["phase"],"prepared")
            self.assertEqual(self.j.domains(),["example.com"])
            self.assertIsNone(self.j.read("other.com"))
            mkdir.assert_not_called()
            sync.assert_not_called()

    def test_lists_domain_names_without_reading_keys(self):
        self.prepare()
        self.j.path("other.com").write_text("unreadable record")
        (self.j.directory/".txn-abandoned").write_text("temporary")
        self.assertEqual(self.j.domains(),["example.com","other.com"])
        (self.j.directory/"bad_name.json").write_text("invalid")
        with self.assertRaises(core.Error): self.j.domains()

    def test_unsafe_directory(self):
        self.j.directory.mkdir(mode=0o755)
        self.j.directory.chmod(0o755)
        with self.assertRaises(JournalError): self.prepare()
        with self.assertRaises(JournalError): self.j.read("missing.com")

    def test_directory_type_and_owner(self):
        target=self.root/"target"
        target.mkdir(mode=0o700)
        self.j.directory.symlink_to(target,target_is_directory=True)
        with self.assertRaises(JournalError): self.j.read("example.com")
        self.j.directory.unlink()
        self.j.directory.mkdir(mode=0o700)
        with patch("cgp_cert_manager.transactions.os.geteuid",return_value=os.geteuid()+1):
            with self.assertRaises(JournalError): self.prepare()

    def test_unsafe_file(self):
        self.prepare()
        self.j.path("example.com").chmod(0o644)
        with self.assertRaises(JournalError): self.j.read("example.com")
        self.j.path("example.com").chmod(0o600)
        info=self.j.path("example.com").stat()
        for mode,uid in ((info.st_mode,info.st_uid+1),(0o010600,info.st_uid)):
            with self.subTest(mode=mode,uid=uid),patch("cgp_cert_manager.transactions.os.fstat",return_value=SimpleNamespace(st_mode=mode,st_uid=uid)):
                with self.assertRaises(JournalError): self.j.read("example.com")

    def test_corrupt_file(self):
        self.prepare()
        self.j.path("example.com").write_text("not json")
        with self.assertRaises(JournalError): self.j.read("example.com")
        self.j.path("example.com").write_bytes(b"\xff")
        with self.assertRaises(JournalError): self.j.read("example.com")

    def test_invalid_record(self):
        r=self.prepare()
        for changes in ({"schema":1},{"schema":True},{"schema":2.0},{"domain":"other.com"},{"phase":"bad"},{"phase":[]},{"previous":{}},{"previous":None},{"intended":dict(self.new,CAChain="bad;")},{"intended":dict(self.new,PrivateSecureKey=None)},{"endpoints":None},{"previous_endpoints":[]},{"config_identity":""},{"config_identity":None},{"extra":"unexpected"}):
            with self.subTest(changes=changes):
                with self.assertRaises(JournalError): validate(dict(r,**changes),"example.com")
        with self.assertRaises(JournalError): validate(None,"example.com")
        incomplete=dict(r)
        del incomplete["previous_endpoints"]
        with self.assertRaises(JournalError): validate(incomplete,"example.com")

    def test_previous_endpoints_are_recorded_independently(self):
        before=[{"port":993,"sni":"old.example.com","starttls":None}]
        after=[{"port":443,"sni":"new.example.com"}]
        self.j.prepare("example.com",self.old,self.new,after,"server",previous_endpoints=before)
        r=self.j.read("example.com")
        self.assertEqual(r["previous_endpoints"],before)
        self.assertEqual(r["endpoints"],after)

    def test_atomic_replace_failure_keeps_previous(self):
        r=self.prepare()
        with patch("cgp_cert_manager.transactions.os.replace",side_effect=OSError()):
            with self.assertRaises(OSError): self.j.transition("example.com","applying")
        self.assertEqual(self.j.read("example.com"),r)
        self.assertEqual(list(self.j.directory.iterdir()),[self.j.path("example.com")])

    def test_directory_sync_failure_propagates(self):
        with patch("cgp_cert_manager.transactions.os.fsync",side_effect=OSError()):
            with self.assertRaises(OSError): sync_directory(self.root)

    def test_file_sync_failure_preserves_previous_record(self):
        before=self.prepare()
        with patch("cgp_cert_manager.transactions.os.fsync",side_effect=OSError("disk failure")):
            with self.assertRaises(OSError): self.j.transition("example.com","applying")
        self.assertEqual(self.j.read("example.com"),before)
        self.assertEqual(list(self.j.directory.iterdir()),[self.j.path("example.com")])

    def test_directory_sync_failure_leaves_readable_pending_record(self):
        self.prepare()
        with patch("cgp_cert_manager.transactions.sync_directory",side_effect=OSError("disk failure")):
            with self.assertRaises(OSError): self.j.transition("example.com","applying")
        # The caller receives an error, but recovery can inspect the replaced file.
        self.assertEqual(self.j.read("example.com")["phase"],"applying")
        self.assertEqual(list(self.j.directory.iterdir()),[self.j.path("example.com")])

    def test_failed_terminal_unlink_preserves_terminal_record(self):
        self.prepare()
        self.j.transition("example.com","restoring")
        self.j.transition("example.com","restored")
        with patch.object(Path,"unlink",side_effect=OSError("disk failure")):
            with self.assertRaises(OSError): self.j.finish("example.com")
        self.assertEqual(self.j.read("example.com")["phase"],"restored")

    def test_symlink_rejected(self):
        self.prepare()
        path=self.j.path("example.com")
        target=self.root/"target"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(OSError): self.j.read("example.com")

    def test_endpoint_validation(self):
        r=self.prepare()
        for ep in ([],[None],[{"port":443,"sni":"example.com","extra":1}],[{"port":0,"sni":"example.com"}],[{"port":65536,"sni":"example.com"}],[{"port":True,"sni":"example.com"}],[{"port":443,"sni":None}],[{"port":443,"sni":"invalid"}],[{"port":443,"sni":"*.example.com"}],[{"port":443,"sni":"example.com","host":None}],[{"port":443,"sni":"example.com","host":"bad host"}],[{"port":443,"sni":"example.com","starttls":"bad"}]):
            with self.subTest(ep=ep),self.assertRaises(JournalError):
                validate(dict(r,endpoints=ep),"example.com")
