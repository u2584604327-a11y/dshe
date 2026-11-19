#!/usr/bin/env python3
"""P307: local deterministic synthetic fixture distinctness, not release evidence."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXPRESSION = "for(int i=0;i<data.length;i++)data[i]=(byte)((i*31+7+(i>>>8)*17+(i>>>12)*53)&255);"
JAVA = (
    ROOT / "probe/src/main/java/com/dsh/p302probe/ProbeActivity.java",
    ROOT / "probe/src/main/java/com/dsh/p302probe/IsolatedPipeService.java",
)
for f in JAVA:
    s = f.read_text(encoding="utf-8")
    assert s.count(EXPRESSION) == 1, "P307_SOURCE_ALGORITHM_MISMATCH"

payload = bytes(
    (i * 31 + 7 + (i >> 8) * 17 + (i >> 12) * 53) & 255
    for i in range(65_536)
)
assert len(payload) == 65_536
blocks = [payload[i:i + 4096] for i in range(0, len(payload), 4096)]
assert len(blocks) == 16
assert len({block[0] for block in blocks}) == 16
assert len(set(blocks)) == 16
for i in range(16):
    assert blocks[i][0] == (7 + 69 * i) & 255
assert b"".join([blocks[1], blocks[0], *blocks[2:]]) != payload
assert b"".join([blocks[0], blocks[0], *blocks[2:]]) != payload
assert payload[:-1] != payload
print("P307_DISTINCT_16_BLOCK_FIXTURE=PASS")
print("P307_SWAPPED_DUPLICATE_TRUNCATED_OFFLINE_NEGATIVES=PASS")
