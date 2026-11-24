import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from cgp_cert_manager import core, recovery
from cgp_cert_manager.transactions import Journal, JournalError

def settings(key):
    return {"PrivateSecureKey":key, "SecureCertificate":"[YQ==]",
            "CAChain":"[YQ==]", "CertificateType":"YES"}

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.j=Journal(Path(self.tmp.name)/"transactions")
        self.name="example.com"
        self.cfg={"communigate":{"url":"http://127.0.0.1:8100/CLI/"}}
        self.old=settings("[YQ==]")
        self.new=settings("[Yg==]")
        self.ep=[{"port":443,"sni":self.name}]
        self.identity=recovery.server_identity(self.cfg,"machine")
        self.verify=Mock()
        self.j.prepare(self.name,self.old,self.new,self.ep,self.identity)

    def advance(self,phase):
        for p in ("applying","applied","verifying","committed"):
            self.j.transition(self.name,p)
            if p==phase: break

    def run_recovery(self):
        return recovery.recover(self.j,self.name,self.cfg,self.identity,self.verify)

    def test_identity(self):
        self.assertNotEqual(self.identity,recovery.server_identity(self.cfg,"other"))
        with self.assertRaises(JournalError):
            recovery.recover(self.j,self.name,self.cfg,"wrong",self.verify)

    def test_none(self):
        self.j.transition(self.name,"restoring")
        self.j.transition(self.name,"restored")
        self.j.finish(self.name)
        self.assertEqual(self.run_recovery(),"none")

    def test_previous(self):
        with patch.object(core,"current",return_value=self.old),patch.object(core,"update") as update:
            self.assertEqual(self.run_recovery(),"restored")
            update.assert_not_called()
        self.verify.assert_called_once_with(self.old,self.ep)
        self.assertIsNone(self.j.read(self.name))

    def test_unknown(self):
        with patch.object(core,"current",return_value={}),patch.object(core,"update") as update:
            with self.assertRaises(JournalError): self.run_recovery()
            update.assert_not_called()
        self.assertIsNotNone(self.j.read(self.name))

    def test_prepared_intended_refused(self):
        with patch.object(core,"current",return_value=self.new),patch.object(core,"update") as update:
            with self.assertRaises(JournalError): self.run_recovery()
            update.assert_not_called()

    def test_resume_intended(self):
        for phase in ("applying","applied","verifying"):
            with self.subTest(phase=phase):
                if self.j.read(self.name) is None:
                    self.j.prepare(self.name,self.old,self.new,self.ep,self.identity)
                self.advance(phase)
                with patch.object(core,"current",return_value=self.new),patch.object(core,"update") as update:
                    self.assertEqual(self.run_recovery(),"committed")
                    update.assert_not_called()
                self.assertIsNone(self.j.read(self.name))

    def test_failed_intended_restores_previous(self):
        self.advance("applying")
        self.verify.side_effect=[core.Error("TLS failure"),None]
        with patch.object(core,"current",side_effect=[self.new,self.new,self.old]),patch.object(core,"update") as update:
            self.assertEqual(self.run_recovery(),"restored")
            update.assert_called_once_with(self.cfg,self.name,self.old)

    def test_resume_restoring(self):
        self.j.transition(self.name,"restoring")
        with patch.object(core,"current",side_effect=[self.new,self.new,self.old]),patch.object(core,"update") as update:
            self.assertEqual(self.run_recovery(),"restored")
            update.assert_called_once_with(self.cfg,self.name,self.old)

    def test_changed_during_verification(self):
        self.advance("applying")
        self.verify.side_effect=core.Error("TLS failure")
        with patch.object(core,"current",side_effect=[self.new,{}]),patch.object(core,"update") as update:
            with self.assertRaisesRegex(JournalError,"changed before"): self.run_recovery()
            update.assert_not_called()
        self.assertEqual(self.j.read(self.name)["phase"],"verifying")

    def test_restore_readback_failure(self):
        self.j.transition(self.name,"restoring")
        with patch.object(core,"current",return_value=self.new),patch.object(core,"update"):
            with self.assertRaisesRegex(JournalError,"readback"): self.run_recovery()
        self.assertEqual(self.j.read(self.name)["phase"],"restoring")

    def test_restore_tls_failure(self):
        self.verify.side_effect=core.Error("TLS failed")
        with patch.object(core,"current",return_value=self.old):
            with self.assertRaises(core.Error): self.run_recovery()
        self.assertEqual(self.j.read(self.name)["phase"],"restoring")

    def test_completed_cleanup(self):
        self.advance("committed")
        with patch.object(core,"current",return_value=self.old):
            with self.assertRaisesRegex(JournalError,"after transaction"): self.run_recovery()
        with patch.object(core,"current",return_value=self.new):
            self.assertEqual(self.run_recovery(),"committed")
        self.j.prepare(self.name,self.old,self.new,self.ep,self.identity)
        self.j.transition(self.name,"restoring")
        self.j.transition(self.name,"restored")
        with patch.object(core,"current",return_value=self.old):
            self.assertEqual(self.run_recovery(),"restored")

class SnapshotTests(unittest.TestCase):
    def test_der(self):
        short=b"\x30\x01a"
        long=b"\x30\x81\x80"+b"a"*128
        self.assertEqual(recovery.der_certificates(short+long),[short,long])
        for invalid in (b"",b"x",b"\x31\x01a",b"\x30\x80",b"\x30\x82\x01",b"\x30\x00",b"\x30\x05a"):
            with self.subTest(invalid=invalid),self.assertRaises(JournalError):
                recovery.der_certificates(invalid)

    def test_datablock(self):
        self.assertEqual(recovery.datablock("[YQ==]"),b"a")
        for invalid in ("bad","[!!!]"):
            with self.assertRaises(JournalError): recovery.datablock(invalid)

    def test_snapshot(self):
        leaf=b"leaf"
        ca=b"\x30\x01a"
        f=settings("[YQ==]")
        f["SecureCertificate"]="["+base64.b64encode(leaf).decode()+"]"
        f["CAChain"]="["+base64.b64encode(ca).decode()+"]"
        endpoint={"port":443,"sni":"example.com"}
        with patch.object(core,"validate_backup") as validate,patch.object(core,"probe_tls") as probe:
            recovery.verify_snapshot(f,[endpoint])
            validate.assert_called_once_with(f)
            probe.assert_called_once_with(endpoint,[hashlib.sha256(x).hexdigest() for x in (leaf,ca)])
            with self.assertRaises(JournalError): recovery.verify_snapshot(f,[])
            with self.assertRaises(JournalError): recovery.verify_snapshot(dict(f,SecureCertificate="[]"),[endpoint])
