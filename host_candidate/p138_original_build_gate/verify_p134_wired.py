#!/usr/bin/env python3
"""P138: evidence that the *actual original DSH test APK builder* compiles and
verifies the P134 genuine ARM64 kernel guard. Source-only, no signing or APK.
"""
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[2]
builder = (ROOT / "host_candidate/p43_original_service/build_embedded_emulator_apk.sh").read_text()
p50 = (ROOT / "host_candidate/p50_original_arm64_node/android/com/dsh/android/p50/P50OriginalNodeFixedChild.java").read_text()
guard = (ROOT / "host_candidate/p134_real_arm64_gate/src/com/dsh/android/p134/P134RealArm64Gate.java").read_text()
source = "host_candidate/p134_real_arm64_gate/src/com/dsh/android/p134/P134RealArm64Gate.java"
descriptor = "'Lcom/dsh/android/p134/P134RealArm64Gate;'"
assert builder.count(source) == 1, "P138_GUARD_NOT_UNIQUELY_IN_ORIGINAL_BUILDER"
assert builder.count(descriptor) == 1, "P138_GUARD_NOT_UNIQUELY_IN_DEX_ASSERTION"
javac_start = builder.index("javac --release 8 -cp")
javac_end = builder.index("\njar cf ", javac_start)
javac = builder[javac_start:javac_end]
assert source in javac and "P50OriginalNodeFixedChild.java" in javac
dex_start = builder.index("for expected in ('Lcom/dsh/android/p43/P43IsolatedWorker;'")
dex_end = builder.index("\nprint(\"P43_ORIGINAL_ASSETS", dex_start)
assert descriptor in builder[dex_start:dex_end]
assert builder.index(descriptor) > builder.index("classes=DEX(derived.read('classes3.dex'))")
assert "P134RealArm64Gate.allow(" in p50
assert p50.index("P134RealArm64Gate.allow(") < p50.index("new ProcessBuilder(")
assert "Os.uname().machine" in p50
assert 'Process.isIsolated()' in p50
assert '"aarch64".equals(actualKernelMachine)' in guard
assert '"arm64-v8a".equals(processAbis[0])' in guard
assert (ROOT / source).is_file()
print("P138_ORIGINAL_BUILDER_P134_SOURCE_INCLUDED=PASS")
print("P138_ORIGINAL_DEX_CLASSES3_P134_ASSERTION=PASS")
print("P138_P50_GENUINE_ARM64_GATE_PRE_EXEC=PASS")
print("P138_ORIGINAL_SIGNED_APK_MODIFICATION=NONE")
print("P138_PRODUCTION_NODE=NOT_EXECUTED")
print("P138_FORMAL_V139=BLOCKED")
