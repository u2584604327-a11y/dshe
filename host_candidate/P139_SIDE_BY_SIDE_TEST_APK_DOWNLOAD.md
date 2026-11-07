# P139 P51 side-by-side ARM64 isolated Node diagnostic APK

This is **not** DSH v139 or an upgrade to com.dsh.android.
Only use the one-day artifact generated at the exact PR #80 HEAD after
the P139 source/original ELF/manifest/DEX/signer gates pass.
Android 34+ ARM64 only. The test APK package is
`com.dsh.p51.isolatedprobe`, distinct from original `com.dsh.android`.
Only a launcher diagnostic Activity and non-exported isolated Service are
declared, with no requested Android permissions. It uses an ephemeral signer.
Install as an additional app and open **P51 Isolated Node Test**;
wait for on-screen PASS/BLOCKED indicators and copy that text into the chat.
The APK carries exact SHA-locked original Node but only a fixed synthetic
test; no user scripts, browser automation, login, network or production tools.
DO NOT uninstall or overwrite `com.dsh.android`; do not treat this artifact
as proof of original EngineManager production startup.
Artifacts expire after one day and contain the APK plus SHA256SUMS.txt.
Neither original APK nor signer is preserved in CI after artifact upload.
Formal v139 remains BLOCKED, sensitive native tools DENY_ALL.
