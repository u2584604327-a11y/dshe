# Production bridge precursor: original signed-v138 three spawn sites

This read-only test compares the **actual pinned v138 APK DEX** against the three distinct upstream Kotlin EngineManager launch modes. P35 previously pinned only the main start coroutine. P142 intentionally intercepts the three sites in upstream *source*; neither establishes complete signed-v138 runtime equivalence.

The parser refuses a non-matching original APK SHA, missing/duplicate/unclassified EngineManager ProcessBuilder.start calls, or drift from the already established main DEX code offset 3163260 / PC 3912. Its transient report contains **only** typed callsite offsets and no source/strings/argv/env/authentication tokens.

The existing baseline release is downloaded into a disposable runner directory and deleted before exit, never installed, patched, signed or uploaded. The parser selftest covers missing, duplicate, forged mode and drift cases. A red result must be investigated rather than weakening these gates.

**Not proved by a static PASS:** Kotlin-v138 full equivalence; complete Node CLI imports, Android isolated UID, real Binder sending UID, per-request native authorization, Process stream and epoch behavior, or real HTTP token Ready. These remain STOP conditions. P47/P142 fail-closed launch, P109 DENY_ALL, GS capture OFF, and formal v139 BLOCKED are unchanged.
