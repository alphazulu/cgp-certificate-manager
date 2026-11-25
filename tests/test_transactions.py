import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cgp_cert_manager import core, storage
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
        with patch("cgp_cert_manager.storage.os.fsync") as sync,patch.object(Path,"mkdir") as mkdir:
            self.assertIsNone(self.j.read("example.com"))
            self.assertEqual(self.j.domains(),[])
            mkdir.assert_not_called()
            sync.assert_not_called()
        self.prepare()
        with patch("cgp_cert_manager.storage.os.fsync") as sync,patch.object(Path,"mkdir") as mkdir:
            self.assertEqual(self.j.read("example.com")["phase"],"prepared")
            self.assertEqual(self.j.domains(),["example.com"])
            self.assertIsNone(self.j.read("other.com"))
            mkdir.assert_not_called()
            sync.assert_not_called()

    def test_lists_domain_names_without_reading_keys(self):
        self.prepare()
        self.j.path("other.com").write_text("unreadable record")
        self.j.path("other.com").chmod(0o600)
        (self.j.directory/".txn-abandoned").write_text("temporary")
        self.assertEqual(self.j.domains(),["example.com","other.com"])
        (self.j.directory/"bad_name.json").write_text("invalid")
        (self.j.directory/"bad_name.json").chmod(0o600)
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
        fstat=os.fstat
        for mode,uid in ((info.st_mode,info.st_uid+1),(0o010600,info.st_uid)):
            def changed(fd):
                actual=fstat(fd)
                if not stat.S_ISREG(actual.st_mode): return actual
                fields=list(actual)
                fields[stat.ST_MODE]=mode
                fields[stat.ST_UID]=uid
                return os.stat_result(fields)
            with self.subTest(mode=mode,uid=uid),patch("cgp_cert_manager.transactions.os.fstat",side_effect=changed):
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
        fsync=os.fsync
        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode): raise OSError("disk failure")
            fsync(fd)
        with patch("cgp_cert_manager.transactions.os.fsync",side_effect=fail_file):
            with self.assertRaises(OSError): self.j.transition("example.com","applying")
        self.assertEqual(self.j.read("example.com"),before)
        self.assertEqual(list(self.j.directory.iterdir()),[self.j.path("example.com")])

    def test_directory_sync_failure_leaves_readable_pending_record(self):
        self.prepare()
        fsync=os.fsync
        directory=self.j.directory.stat()
        def fail_directory(fd):
            opened=os.fstat(fd)
            if (opened.st_dev,opened.st_ino)==(directory.st_dev,directory.st_ino): raise OSError("disk failure")
            fsync(fd)
        with patch("cgp_cert_manager.storage.os.fsync",side_effect=fail_directory):
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
        with self.assertRaises(JournalError): self.j.read("example.com")

    def test_missing_state_reads_are_side_effect_free(self):
        journal=Journal(self.root/"missing"/"transactions")
        with patch("cgp_cert_manager.storage.os.fsync") as sync:
            self.assertIsNone(journal.read("example.com"))
            self.assertEqual(journal.domains(),[])
        sync.assert_not_called()
        self.assertFalse((self.root/"missing").exists())

    def test_unsafe_state_rejected_before_creating_transactions(self):
        self.root.chmod(0o755)
        for operation in (self.prepare,self.j.domains,lambda:self.j.read("example.com")):
            with self.subTest(operation=operation),self.assertRaises(JournalError): operation()
        self.assertFalse(self.j.directory.exists())

    def test_state_symlink_rejected_even_without_transaction_directory(self):
        real=self.root/"real"
        real.mkdir(mode=0o700)
        link=self.root/"state"
        link.symlink_to(real,target_is_directory=True)
        journal=Journal(link/"transactions")
        for operation in (journal.domains,lambda:journal.read("example.com"),journal.ensure_directory):
            with self.subTest(operation=operation),self.assertRaises(JournalError): operation()
        self.assertFalse((real/"transactions").exists())

    def test_hardlinked_record_rejected_by_read_and_listing(self):
        self.prepare()
        linked=self.root/"extra-link"
        os.link(self.j.path("example.com"),linked)
        evidence=linked.read_bytes()
        for operation in (self.j.domains,lambda:self.j.read("example.com")):
            with self.subTest(operation=operation),self.assertRaises(JournalError): operation()
        self.assertEqual(linked.read_bytes(),evidence)

    def test_hardlinked_terminal_record_cannot_be_removed(self):
        self.prepare()
        self.j.transition("example.com","restoring")
        self.j.transition("example.com","restored")
        linked=self.root/"extra-link"
        os.link(self.j.path("example.com"),linked)
        evidence=linked.read_bytes()
        with self.assertRaises(JournalError): self.j.finish("example.com")
        self.assertEqual(self.j.path("example.com").read_bytes(),evidence)
        self.assertEqual(linked.read_bytes(),evidence)

    def test_ancestor_symlink_cannot_hide_existing_pending_record(self):
        container=self.root/"container"
        state=container/"state"
        storage.ensure_private_directory(state)
        journal=Journal(state/"transactions")
        journal.prepare("example.com",self.old,self.new,[{"port":443,"sni":"example.com"}],"server")
        link=self.root/"alias"
        link.symlink_to(container,target_is_directory=True)
        alias=Journal(link/"state"/"transactions")
        for operation in (alias.domains,lambda:alias.read("example.com")):
            with self.subTest(operation=operation),self.assertRaises(JournalError): operation()
        self.assertEqual(journal.read("example.com")["phase"],"prepared")

    def test_endpoint_validation(self):
        r=self.prepare()
        for ep in ([],[None],[{"port":443,"sni":"example.com","extra":1}],[{"port":0,"sni":"example.com"}],[{"port":65536,"sni":"example.com"}],[{"port":True,"sni":"example.com"}],[{"port":443,"sni":None}],[{"port":443,"sni":"invalid"}],[{"port":443,"sni":"*.example.com"}],[{"port":443,"sni":"example.com","host":None}],[{"port":443,"sni":"example.com","host":"bad host"}],[{"port":443,"sni":"example.com","starttls":"bad"}]):
            with self.subTest(ep=ep),self.assertRaises(JournalError):
                validate(dict(r,endpoints=ep),"example.com")
