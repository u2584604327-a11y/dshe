#!/usr/bin/env python3
"""P233/P234 synthetic replay and privacy-preserving length-band tests (16)."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from p233_prefix_replay import audit, EXPECTED, length_band, file_length_band

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

    def test_p234_exact_and_empty_bands(self):
        self.assertEqual(length_band(EXPECTED), "EXACT_7M")
        self.assertEqual(length_band(0), "EMPTY")

    def test_p234_small_short_band_edges(self):
        self.assertEqual(length_band(EXPECTED-1), "SHORT_1_TO_64")
        self.assertEqual(length_band(EXPECTED-64), "SHORT_1_TO_64")

    def test_p234_mid_short_band_edges(self):
        self.assertEqual(length_band(EXPECTED-65), "SHORT_65_TO_4096")
        self.assertEqual(length_band(EXPECTED-4096), "SHORT_65_TO_4096")

    def test_p234_large_short_bands(self):
        self.assertEqual(length_band(EXPECTED-4097), "SHORT_4097_TO_65536")
        self.assertEqual(length_band(EXPECTED-65537), "SHORT_OVER_65536")

    def test_p234_small_over_band_edges(self):
        self.assertEqual(length_band(EXPECTED+1), "OVER_1_TO_64")
        self.assertEqual(length_band(EXPECTED+64), "OVER_1_TO_64")

    def test_p234_mid_over_band_edges(self):
        self.assertEqual(length_band(EXPECTED+65), "OVER_65_TO_4096")
        self.assertEqual(length_band(EXPECTED+4096), "OVER_65_TO_4096")

    def test_p234_large_over_bands(self):
        self.assertEqual(length_band(EXPECTED+4097), "OVER_4097_TO_65536")
        self.assertEqual(length_band(EXPECTED+65537), "OVER_OVER_65536")

    def test_p234_actual_file_and_unknown(self):
        self.assertEqual(file_length_band(self.a), "EXACT_7M")
        self.assertEqual(file_length_band(self.root / "not-here.trace"), "UNSAFE_OR_MISSING")
        self.assertEqual(length_band(-1), "UNKNOWN")

    def test_directory(self):
        self.assertEqual(audit(self.a, self.root), "INVALID_INPUT")

if __name__ == "__main__":
    unittest.main(verbosity=2)
