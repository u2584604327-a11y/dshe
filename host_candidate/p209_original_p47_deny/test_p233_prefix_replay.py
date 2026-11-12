#!/usr/bin/env python3
"""P233 synthetic positive/negative exact-size replay tests (8)."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from p233_prefix_replay import audit, EXPECTED

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory(prefix="p233-test-")
        cls.root = Path(cls.tmp.name)
        cls.a = cls.root / "first.trace"
        cls.b = cls.root / "second.trace"
        cls.a.write_bytes(b"Z" * EXPECTED)
        cls.b.write_bytes(b"Z" * EXPECTED)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_exact_identical(self):
        self.assertEqual(audit(self.a, self.b), "PASS")

    def test_mutated_second(self):
        p = self.root / "mutated.trace"
        with p.open("wb") as f:
            f.write(b"X")
            f.write(b"Z" * (EXPECTED-1))
        self.assertEqual(audit(self.a, p), "DIFFERENT")

    def test_short_second(self):
        p = self.root / "short.trace"
        p.write_bytes(b"A" * 8)
        self.assertEqual(audit(self.a, p), "SIZE_MISMATCH")

    def test_oversize_second(self):
        p = self.root / "large.trace"
        with p.open("wb") as f:
            f.write(b"Y" * (EXPECTED+1))
        self.assertEqual(audit(self.a, p), "SIZE_MISMATCH")

    def test_missing_file(self):
        self.assertEqual(audit(self.a, self.root / "missing.trace"), "INVALID_INPUT")

    def test_same_path(self):
        self.assertEqual(audit(self.a, self.a), "INVALID_INPUT")

    def test_symlink(self):
        p = self.root / "linked.trace"
        p.symlink_to(self.b)
        self.assertEqual(audit(self.a, p), "INVALID_INPUT")

    def test_directory(self):
        self.assertEqual(audit(self.a, self.root), "INVALID_INPUT")

if __name__ == "__main__":
    unittest.main(verbosity=2)
