# P153 — exact original installed Node ELF metadata versus emulator ABI

P152 determined this isolated Android35 x86_64 original-v138-derived package
lacks an architecture-specific x86_64 Termux bootstrap asset and that the
original Node is not usable after install. P153 reads the **fixed original
private** files/termux/usr/bin/node using read-only, capped ELF I/O and
categorizes ELF class, e_machine, architecture match with the runtime
Build.SUPPORTED_ABIS[0] and the PT_INTERP category. No raw interpreter
path, file bytes, profile data, process argv, cwd, environment, credential
or private path enters logs/Binder. The parser reads at most 64 ELF header
bytes, 128 program headers of at most 128 bytes each, and 256 interpreter
bytes, with file-size cap, syntax/offset validation and symlink denial.
Java8 synthetic positives/negatives validate AARCH64 vs x86_64, corrupt
headers, invalid interpreter bounds and redaction.

At P151's 5/20/40-second sample points, the same emulated app reads the
original Node file but **never launches it or calls --version**. The
original Termux startup behavior is unchanged. A mismatch is structural
ELF evidence, not a proof that restoring compatibility or enabling host
ProcessBuilder would work; shared-library closure, OS loader restrictions,
original Process façade, Node/JS session and token Ready remain UNPROVEN.
P47/P142 no host fallback, P109 sensitive tools DENY_ALL, P143 exact asset
FD/full TAR, no releases, no signing, no phone changes. Formal v139 BLOCKED.
