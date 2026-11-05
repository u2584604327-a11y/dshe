# P204 — original v138 onCreate PC430 branch structure

P203 verified a static direct call from original MainActivity.onCreate PC430 to MainActivity.bootEngine. P204 inspects the surrounding normal control-flow graph in the exact signed original v138 APK, SHA256 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5.

The inspector requires the single original onCreate(Bundle) method, the exact PC430 bootEngine call, valid instruction lengths and valid DEX branch targets. It maps if/goto/return normal edges and reports bounded conditional branch PC, opcode, successor reachability and preceding opcode names. Branch relative offsets are converted from DEX code units to byte PCs. Switch and exception edges are marked unmodeled. The report contains no original bytecode operands or string literals.

A reachable static call does not prove the Android process executed that branch, nor establish a particular Boolean condition. P200 genuine Android35 onCreate and onResume observation had an original coroutine stack-shape NOT_OBSERVED result, which is not proof PC430 was skipped. P204 therefore always reports actual execution NOT_OBSERVED and real coroutine authority NOT_ATTESTED.

P204 is read-only original binary analysis with 25 synthetic regression checks. It does not enable original Node or change the three P47 DENY launch bridges, isolated process policy or permission checks. The CI test APK has an unrelated signer and is never installed on the user's phone. Future physical ARM64 testing needs a separate consenting side-by-side build and signing checks.

No merge, release, data overwrite or external fingerprinting tests. Preserve original DSHAPP MIT attribution and independent-fork notices. Formal v139 remains STRUCTURAL_BLOCKED.
