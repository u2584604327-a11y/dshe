# DSH P23 installed APK ZIP loader forensic controls

Date: 2026-10-29. This is independent disposable Android35 x86_64 code; no original ARM64 Node executable.

## Baseline
- P18 actual bound isolatedProcess service and capability broker tested on Android35: PASS.
- P20 host INTERNET positive control vs isolated worker local socket and host-private file denial: PASS.
- P21 original v138 ARM64 Node+10 transitive libraries, 16 KiB ELF and APK ZIP static staging: PASS, **no Node execution**.
- P22 actual Android35 x86_64 execve with versioned DT_NEEDED .so.3: exit 1 CANNOT LINK EXECUTABLE.
- P22 native Bionic dlopen to APK!/lib/x86_64/libp22version.so.3: test returned -21 (dlerror classified "not found").
- Java System.load of the same ZIP path: UnsatisfiedLinkError.
- P22 PR #6 remains Draft, release blocked.

## Actual P23 change

Test case deliberately controls **the same ELF bytes under three archive names**:
1. assets/p23control.so
2. assets/p23control.so.3
3. lib/x86_64/libp22version.so.3

All three must retain byte-identical SHA256, be STORED (no ZIP compression)
and align their ZIP data offsets to 16 KiB. A fixed-purpose JNI bridge
libp23bridge.so, which is installer-extractable, calls native Bionic dlopen
on each path. It cannot accept arbitrary file paths, user URLs, external
network, shell, secrets or DSH tool commands.

The Android35 disposable APK has no Android permissions and contains one
non-exported isolatedProcess service. The worker:
- uses platform ApplicationInfo.sourceDir to resolve its own installed APK;
- checks that the APK is a readable ordinary file;
- opens the actual APK with Java ZipFile inside isolated UID;
- opens each of the three STORED entries and verifies bounded bytes and
  matching SHA256, without printing/exfiltrating paths, content or private data;
- separately loads installed JNI bridge;
- invokes three direct native dlopen fixed-path tests and returns three
  individual codes;
- trusted host checks Binder framework Message.sendingUid is an isolated UID,
  plus the reported UID matches.

P23 CI **only passes characterization gates** when archive access, entry
identity, JNI bridge, actual Binder UID and real executed native variants
have all returned. Individual dlopen FAIL remains explicitly BLOCKED and does
not become a loader PASS.

### Why both success and failures matter
If installed APK and all ZIP entry contents are readable, but dlopen still
reports "not found", that rules out APK entry loss and simple worker filesystem
denial for the measured test package, but does not settle linker namespaces,
ZIP path syntax, Bionic restrictions or dependencies. In particular, the
original v138 ARM64 Node may behave differently.

## Stop conditions

No production APK, original signing key, real phone install, credential
access, root, Shizuku, ADB privileges inside app or production internet
requests. If exact installed controls cannot be observed, FAIL/UNKNOWN.

P23_INSTALLED_APK_POSITIVE_CONTROL=CI_PENDING
P23_BIONIC_ASSET_PLAIN=CI_PENDING
P23_BIONIC_ASSET_VERSIONED=CI_PENDING
P23_BIONIC_NATIVE_VERSIONED=CI_PENDING
P23_ACTUAL_DSH_ARM64_NODE_BOOT=NOT_TESTED
P23_PRODUCTION_RUNTIME_INTEGRATION=NO
P23_RELEASE=BLOCKED
