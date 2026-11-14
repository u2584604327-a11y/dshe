#!/usr/bin/env python3
"""P293: 28 source-only AXML original-member restoration adversarial fixtures."""
import contextlib,io,sys,tempfile,unittest,warnings,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=["host_candidate/p293_manifest_parity",
             "host_candidate/p249_dual_diff",
             "host_candidate/p246_exception_semantics"]
import p293_manifest_parity as m

def axml(body=b"ORIGINAL_AXML_VALID_MOCK"):
    return m.AXML_HEAD+(8+len(body)).to_bytes(4,"little")+body
def plain():return b'<?xml version="1.0" encoding="utf-8"?>\n<manifest package="x"/>'
def zipwrite(path,blob,twice=False,missing=False):
    with warnings.catch_warnings():
      warnings.simplefilter("ignore",UserWarning)
      with zipfile.ZipFile(path,"w") as z:
        if missing:z.writestr("classes.dex",b"DATA")
        else:
          z.writestr(m.MEMBER,blob)
          if twice:z.writestr(m.MEMBER,blob)

@contextlib.contextmanager
def fixture(base=None,candidate=None,duplicated=False,base_duplicated=False):
    with tempfile.TemporaryDirectory() as folder:
        directory=Path(folder)
        bp=directory/"baseline.apk"
        cp=directory/"candidate.apk"
        stage=directory/"staged"/m.MEMBER
        signed=directory/"signed.apk"
        zipwrite(bp,axml() if base is None else base,base_duplicated)
        zipwrite(cp,plain() if candidate is None else candidate,duplicated)
        signed.write_bytes(b"PINNED_TEST_ONLY")
        with patch.object(m,"BASE",bp),patch.object(m,"CANDIDATE",cp),\
             patch.object(m,"SIGNED",signed),patch.object(m,"STAGED",stage),\
             patch.object(m,"seal",return_value=None):
            yield (directory,bp,cp,stage)

class Tests(unittest.TestCase):
 def test_01_axml_header_valid(self):
    self.assertEqual(m.kind(axml()),"BINARY_AXML")
 def test_02_xml_declaration_valid(self):
    self.assertEqual(m.kind(plain()),"PLAINTEXT_XML")
 def test_03_plain_manifest_tag_valid(self):
    self.assertEqual(m.kind(b'<manifest package="test"/>'),"PLAINTEXT_XML")
 def test_04_plain_manifest_bare_valid(self):
    self.assertEqual(m.kind(b'<manifest>text</manifest>'),"PLAINTEXT_XML")
 def test_05_utf8_bom_allowed(self):
    self.assertEqual(m.kind(b"\xef\xbb\xbf"+plain()),"PLAINTEXT_XML")
 def test_06_binary_header_with_wrong_size_is_unknown(self):
    b=axml()
    self.assertEqual(m.kind(b[:4]+(len(b)+1).to_bytes(4,"little")+b[8:]),"UNKNOWN")
 def test_07_wrong_axml_header_unknown(self):
    self.assertEqual(m.kind(b"\x01\x00\x08\x00"+axml()[4:]),"UNKNOWN")
 def test_08_short_header_unknown(self):
    self.assertEqual(m.kind(m.AXML_HEAD),"UNKNOWN")
 def test_09_unknown_utf8_unknown(self):
    self.assertEqual(m.kind(b"some text"),"UNKNOWN")
 def test_10_xml_embedded_nul_unknown(self):
    self.assertEqual(m.kind(plain()+b"\x00"),"UNKNOWN")
 def test_11_xml_unicode_invalid_unknown(self):
    self.assertEqual(m.kind(b"\xff\xfe\x00\x00"),"UNKNOWN")
 def test_12_overlong_unknown(self):
    self.assertEqual(m.kind(b"X"*(m.LIMIT+1)),"UNKNOWN")
 def test_13_zero_length_unknown(self):
    self.assertEqual(m.kind(b""),"UNKNOWN")
 def test_14_non_bytes_unknown(self):
    self.assertEqual(m.kind(None),"UNKNOWN")
 def test_15_binary_base_plain_candidate_allowed_to_stage(self):
    self.assertEqual(m.classify(axml(),plain()),"COPY_BASELINE_BINARY_ONLY")
 def test_16_plain_base_deny(self):
    self.assertEqual(m.classify(plain(),plain()),"DENY_BASE_NOT_BINARY")
 def test_17_candidate_already_binary_deny(self):
    self.assertEqual(m.classify(axml(),axml()),"DENY_CANDIDATE_NOT_PLAINTEXT")
 def test_18_candidate_unknown_deny(self):
    self.assertEqual(m.classify(axml(),b"INVALID"),"DENY_CANDIDATE_NOT_PLAINTEXT")
 def test_19_verified_unique_zip(self):
    with fixture() as (_,bp,cp,_):
        self.assertEqual(m.verified_member(bp),axml())
        self.assertEqual(m.verified_member(cp),plain())
 def test_20_stage_byte_exact_from_baseline(self):
    with fixture() as (_,bp,cp,stage):
        o=io.StringIO()
        with contextlib.redirect_stdout(o):m.stage()
        self.assertEqual(stage.read_bytes(),m.verified_member(bp))
        self.assertIn("P293_STAGE_FROM_VALIDATED_BASE=BYTE_EXACT",o.getvalue())
 def test_21_stage_second_attempt_denied(self):
    with fixture() as (_,bp,cp,stage):
        m.stage()
        with self.assertRaises(ValueError):m.stage()
 def test_22_repack_can_verify_after_exact_member_copy(self):
    with fixture() as (_,bp,cp,stage):
        m.stage()
        zipwrite(cp,stage.read_bytes())
        out=io.StringIO()
        with contextlib.redirect_stdout(out):m.verify()
        self.assertIn("P293_FINAL_MANIFEST_MEMBER=BYTE_EXACT_BASELINE",out.getvalue())
 def test_23_unrestored_plaintext_denied_by_verify(self):
    with fixture():
        with self.assertRaises(ValueError):m.verify()
 def test_24_different_but_valid_axml_denied(self):
    with fixture(candidate=axml(b"DIFFERENT_VALID_BINARY")):
        with self.assertRaises(ValueError):m.verify()
 def test_25_duplicate_candidate_member_denied(self):
    with fixture(duplicated=True):
        with self.assertRaises(ValueError):m.stage()
 def test_26_duplicate_baseline_member_denied(self):
    with fixture(base_duplicated=True):
        with self.assertRaises(ValueError):m.stage()
 def test_27_missing_manifest_member_denied(self):
    with fixture() as (_,bp,cp,_):
        zipwrite(cp,b"?",missing=True)
        with self.assertRaises(ValueError):m.stage()
 def test_28_source_only_no_real_claim(self):
    old=sys.argv;sys.argv=["p293"]
    try:
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(m.main(),0)
        self.assertIn("P293_REAL_MANIFEST=NOT_ATTESTED",out.getvalue())
        self.assertIn("P293_NO_RELEASE=YES",out.getvalue())
    finally:
        sys.argv=old

if __name__=="__main__":unittest.main()
