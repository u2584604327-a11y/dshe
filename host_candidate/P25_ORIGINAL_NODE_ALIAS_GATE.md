# P25 immutable v138 ARM64 Node + 10 dynamic library alias staging

## Purpose and evidence source

P24 Android35 x86_64 live emulation PASS:
https://github.com/u2584604327-a11y/dshe/actions/runs/40856304638

In P24 a real DT_NEEDED libp24version.so.3 executable failed without
LD_PRELOAD and succeeded with LD_PRELOAD of installer-extracted libp24version.so,
whose embedded DT_SONAME remained libp24version.so.3. The executed native
child getuid matched its isolatedProcess UID.

That is single-synthetic-library evidence only, not proof about original Node.

## New P25 exact-input static verifier

- Download exact original v138 signed APK only to disposable CI runner; verify
  APK, asset ZIPs, original Node binary hashes and 16KiB PT_LOAD alignments.
- Run already verified P21 recursive DT_NEEDED source intake for actual original
  AArch64 Node and 10 dependent ELF libraries, using their original bytes.
- Read ELF DT_SONAME and DT_NEEDED for all 10; require each library SONAME to
  equal the original recorded dependency name, reject missing SONAME or
  out-of-closure deps. Explicitly detect cycles among versioned dependencies.
- Create 10 collision-free Android installer-extractable lib*.so filenames.
  Six version-suffixed libraries acquire deterministic alias filenames, but
  their bytes, ELF DT_SONAME and DT_NEEDED remain completely unchanged.
- Generate dependency-before-dependent preload ordering for six aliased
  versioned libraries; do NOT claim it is sufficient to boot original Node.
- Put original unmodified Node ELF plus 10 immutable library aliases in a
  16KiB-aligned, unsigned, transient APK for package structure validation.
- Never place original APK, Node or libraries into Git repo, PR artifacts,
  public releases, production or user's phone. Delete staging files after CI.

## Non-negotiable unsupported claims

No real original AArch64 Node isolatedProcess execve or Android ARM64 linker
result; no guarantee that preloading six libraries resolves all original
Termux/RunPath issues; no full DSH native host integration, real permissions
broker or JS engine confinement. No authentic simulated iPhone or Windows UID.

## Future real ARM64 gate

Test this source-only candidate in a disposable, authorized ARM64 Android
environment (emulator with verified ABI/OS compatibility or user-owned debug
device) against exact SHA-256 original Node and libraries:
- One-to-one original binary hash identity and all ELF DT_NEEDED;
- android:isolatedProcess=true plus Binder framework caller UID/one-shot approval;
- Only --version, no arbitrary scripts, network, user files or production tools;
- No LD_PRELOAD fallback to writable executable/data paths, no root/ptrace;
- Positive native linker version output and native child UID;
- Real Node direct filesystem, loopback/outbound denial by OS;
- Only after all gates: integrate DSH Node/JS/attachments/browser/plugins and
  run full regressions with original signer preserved out of GitHub.

P25_ORIGINAL_ARM64_ALIAS_STATIC=CI_PENDING
P25_ANDROID_ARM64_MULTI_LIBRARY_EXECVE=NOT_TESTED
P25_ORIGINAL_DSH_NATIVE_HOST_MIGRATION=NO
P25_RELEASE=BLOCKED
