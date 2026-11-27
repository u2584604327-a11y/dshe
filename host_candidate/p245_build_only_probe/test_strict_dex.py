"""Exercise the strict comparisons against mutations of the actual P245 DEX."""

import hashlib
import struct
import sys
import unittest
import zipfile
import zlib

from loguru import logger

from strict_dex import (
    DexView, Deny, HELPER, LOG_METHOD, NEW_METHOD, SIGNED_GETTER, START,
    compare_code, index, verify_helper,
)


def load_primary(apk):
    with zipfile.ZipFile(apk) as archive:
        return DexView(archive.read("classes.dex"))


class RealDexMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = baseline
        cls.candidate = candidate
        cls.original_methods = index(cls.base.dex)
        cls.patched_methods = index(cls.candidate.dex)

    def mutate(self, method, offset, value):
        data = bytearray(self.candidate.data)
        start = method.get_code().get_off() + 16 + offset
        data[start:start + len(value)] = value
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
        patched = DexView(bytes(data))
        return patched, index(patched.dex)

    def test_rejects_wrong_coroutine_receiver(self):
        start = self.patched_methods[START]
        (pc, call), = [(pc, raw) for pc, raw in self.candidate.rows(start).items()
                       if self.candidate.instruction(raw)[1] == NEW_METHOD]
        receiver = int.from_bytes(call[4:], "little")
        patched, methods = self.mutate(start, pc + 4, struct.pack("<H", receiver + 1))
        with self.assertRaisesRegex(Deny, "START_HELPER_CALL"):
            compare_code(self.original_methods[START], methods[START], self.base, patched, True)

    def test_rejects_wrong_log_method_id_even_with_same_registers(self):
        helper = self.patched_methods[HELPER]
        calls = {self.candidate.instruction(raw)[1]: (pc, raw[2:4])
                 for pc, raw in self.candidate.rows(helper).items() if raw[0] == 0x71}
        patched, methods = self.mutate(helper, calls[LOG_METHOD][0] + 2, calls[SIGNED_GETTER][1])
        with self.assertRaisesRegex(Deny, "HELPER_LOG"):
            verify_helper(methods[HELPER], self.base, patched)

    def test_rejects_try_range_that_excludes_log(self):
        helper = self.patched_methods[HELPER]
        code_units = helper.get_code().get_insns_size()
        first_try = 2 * (code_units + code_units % 2)
        log_pc, = [pc for pc, raw in self.candidate.rows(helper).items()
                   if self.candidate.instruction(raw)[1] == LOG_METHOD]
        patched, methods = self.mutate(helper, first_try + 4, struct.pack("<H", log_pc // 2))
        with self.assertRaisesRegex(Deny, "HELPER_EXCEPTION_TABLE"):
            verify_helper(methods[HELPER], self.base, patched)

    def test_rejects_changed_switch_payload_in_unrelated_method(self):
        for key, method in self.patched_methods.items():
            if key in (START, HELPER) or method.get_code() is None:
                continue
            for pc, raw in self.candidate.rows(method).items():
                if raw[:2] == b"\0\1":
                    patched, methods = self.mutate(method, pc + 4, bytes((raw[4] ^ 1,)))
                    with self.assertRaisesRegex(Deny, "UNAPPROVED_INSTRUCTION_CHANGE"):
                        compare_code(self.original_methods[key], methods[key], self.base, patched, False)
                    return
        self.fail("No original packed-switch payload")


if __name__ == "__main__":
    logger.remove()
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_strict_dex.py BASE_APK CANDIDATE_APK")
    baseline, candidate = map(load_primary, sys.argv[1:])
    unittest.main(argv=[sys.argv[0]])
