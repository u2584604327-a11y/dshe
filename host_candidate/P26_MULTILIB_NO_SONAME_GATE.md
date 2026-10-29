# P26 multi-SONAME preload + original SQLite missing-SONAME analogue

Date: 2026-10-29. Disposable x86_64 test-only code.

## Why this is needed

P24 verified real Android35 x86_64 isolatedProcess LD_PRELOAD works
for ONE synthetic versioned DT_NEEDED library:
https://github.com/u2584604327-a11y/dshe/actions/runs/40856304638

P25 static inspect of the EXACT original signed v138 AArch64 Node found
TEN actual dependent ELF libraries, SIX versioned SONAMEs and ONE original
libsqlite3.so with missing DT_SONAME. All were packaged under installer
compatible .so filenames without changing bytes and with 16KiB alignment:
https://github.com/u2584604327-a11y/dshe/actions/runs/40857414215

P24 one-library PASS cannot prove actual multi-library preload or
Bionic filename fallback when SONAME is missing.

## P26 synthetic three-library real OS test

NDK builds native x86_64:
- file libp26core.so, ELF DT_SONAME libp26core.so.1;
- file libp26top.so, ELF DT_SONAME libp26top.so.2,
  DT_NEEDED libp26core.so.1;
- file libp26sqlite.so, intentionally no DT_SONAME;
- file libp26exec.so, DT_NEEDED libp26top.so.2 and libp26sqlite.so.

All are installer-extractable .so filenames, never writable-home executables.
The actual native program calls BOTH the top transitive library and the
no-SONAME sqlite-like library and prints only its actual getuid() on success.

A real Android35 isolatedProcess worker:
- runs the exact same libp26exec.so without LD_PRELOAD (must fail with
  missing top.so.2 dependency, FAIL if native executes without it);
- runs with the exact package-managed immutable core.so then top.so
  filenames listed in LD_PRELOAD, colon separated;
- requires native output matching the worker isolated Process.myUid(),
  exit 0, and success of both transitive and missing-SONAME dependencies;
- host verifies actual Binder Message.sendingUid isolation.
- no Android permissions, network, user files, root, Shizuku, ADB in app,
  arbitrary command, real original Node execution, or production signer.

## Limits

It is a controlled analogue, NOT original ARM64 Node or original SQLite.
No ARM64 OS linker/SELinux verification, six-library simultaneous preload,
Termux RUNPATH, actual Node --version, direct Node egress, or full DSH
host integration. Never claim a strict VM or device identity spoof.

P26_ANDROID35_NATIVE_THREE_LIBRARY_LOAD=CI_PENDING
P26_ORIGINAL_ARM64_NODE_EXECUTED=NO
P26_PRODUCTION_DSH_MIGRATED=NO
P26_RELEASE=BLOCKED
