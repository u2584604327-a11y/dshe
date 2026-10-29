# P29 actual original ARM64 Node subprocess OS boundary check (owner-initiated)

## P28 owner-reported prerequisite
Owner's separate P28 Android API36 arm64-v8a local test reported exact
original v138 Node v26.4.0 --version and ten original library hashes PASS.
The host observed Binder isolated UID but the actual Node child UID and
Node-origin filesystem/network restrictions remained NOT_TESTED.

## P29 independent standalone test APK
- Owner-approved **private Draft Release only**, never public.
- Package com.dsh.p29.nodeprobe, Android API34+, ARM64 only.
- No Android permissions, non-exported isolatedProcess service.
- User must explicitly tap one Start button to initiate.
- Host creates exactly one 32-byte random canary in this P29 app's own
  private files directory (not real user data) and sends ONLY its pathname
  to same-package UID-authenticated isolated Service. File removed when
  result arrives or Activity is destroyed.
- Worker verifies original SHA-256 Node and ten exact native ELF libraries
  plus six P25 installer-compatible aliases before exec.
- Real exact original Node executes fixed embedded **--eval** JavaScript,
  no arbitrary JS, input files, arbitrary command, URL, arguments or shells.
- Node calls actual process.getuid() and uses native node:fs/node:net APIs:
  1) reading the host-only test canary (must EACCES/EPERM);
  2) connecting TCP 127.0.0.1:9 (must EACCES/EPERM);
  3) connecting TCP documentation-only 198.51.100.1:443 (must EACCES/EPERM).
  Network only initiates connect, no application payload, no user data.
- The worker compares Node's native getuid() against its real
  Process.myUid; host separately checks framework Binder sendingUid.
- Only exact explicit DENIED_EACCES / DENIED_EPERM classify PASS.
  TIMEOUT, ECONNREFUSED, ENOENT, arbitrary errors, unexpected output,
  unexpected Node UID or Node nonzero exit => BLOCKED/FAIL.
- Node runtime output is constrained to a bounded synthetic JSON status;
  no user secrets, file content, absolute file paths or full error traces
  included in the UI or uploaded to any server.
- A PASS would establish this fixed Node child under this Android API36
  configuration and tested network endpoints/canary. It would NOT prove
  sandbox coverage for all Node APIs, subprocess/FFI capabilities,
  WebView browser bridges, host DSH tool brokers, arbitrary JS, device
  virtualization or production security.

## CI packaging
Use the exact v138 APK input SHA and P21/P25 derived original ELF SHA lock.
All original ARM64 native entries remain uncompressed, page aligned and
byte-identical; throwaway signing key and no-permission APK checked.
Use private Draft Release and 3 assets only; no Actions Artifact quotas.
After P29 Draft successfully exists, delete the already owner-tested P28
private Draft Release with strict tag + draft check (owner authorized
cleanup). Do not delete P21/P25 original release baseline or any source.

## Status before real P29 phone run
P28_OWNER_REPORTED_ORIGINAL_NODE_API36_VERSION=PASS_v26.4.0
P29_BUILD=CI_PENDING
P29_PRIVATE_DRAFT_RELEASE=CI_PENDING
P29_REAL_NODE_GETUID_IN_OS_ISOLATE=NOT_TESTED
P29_REAL_NODE_HOST_PRIVATE_CANARY_DENIAL=NOT_TESTED
P29_REAL_NODE_LOCAL_AND_TESTNET_TCP_DENIAL=NOT_TESTED
P29_FULL_DSH_NATIVE_HOST_INTEGRATION=NO
P29_DSH_V139_PRODUCTION_RELEASE=BLOCKED
