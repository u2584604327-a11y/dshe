# P27 actual ARM64 Android executor admission gate

Date: 2026-10-29. P27 does not implement or execute original Node.

## Evidence from official upstream documentation

- GitHub standard ubuntu-24.04-arm runner is available in private repositories
  from 2026-01-29, billed against standard Actions allotment.
  https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/
- Google's Android emulator Linux ARM64 HOST build is not normally distributed
  via public sdkmanager (Linux host artifact is x86-64). Source-build for
  Linux AArch64 hosts is separately documented.
  https://developer.android.com/studio/releases/emulator
- Android emulator ARM64 guest images and Android ARM64 host support are
  separate from GitHub arm64 Linux runner support. Linux host CPU identity
  and KVM are NOT proof of Android isolated UID.
  https://developer.android.com/studio/run/emulator-acceleration

## Scope and honest gate semantics

1. A genuine ubuntu-24.04-arm GitHub Actions job reads actual Linux host
   architecture, KVM accessibility and API version, and any preinstalled
   native ARM64 Android emulator (if present). No downloads.
2. It ALWAYS lists actual Android guest boot, Android UID, original Node
   execve/identity, and Node OS egress denial as NOT_TESTED.
3. CI may pass host discovery while actual Android guest execution is BLOCKED.
4. No original APK extraction, signer, emulator image download, production
   change, device install, root, ADB privileges, artifacts or secret access.
5. Runner bounded at seven minutes.

## Real ARM64 Android guest admission gate for next phase

Only an observed genuine Android ARM64 guest or explicitly authorized
user-owned test phone is sufficient:
- Verify Android API level, native ABI from actual ADB and worker UID,
  never HTTP user-agent or hardware fingerprint assumptions.
- Build disposable Android35 test APK with original pinned v138 ARM64 Node,
  ten hash-identical ARM64 libs and P25 alias/preload plan.
- In isolatedProcess, bind with framework UID, execute only exact Node
  --version; prove child UID and actual OS/SELinux linker result.
- Probe blocked private canary and loopback/network from actual Node
  subprocess, not Java-only stand-ins.
- Never execute arbitrary JS, permit broad network access, root, Shizuku,
  writable-home native executable copies or profile spoofing.
- If no bootable guest, fail closed as BLOCKED_ARM64_GUEST_UNAVAILABLE.

## Status

P18_OS_BINDER_ISOLATED_UID=PASS_STANDALONE_ANDROID35_X86_64
P20_OS_ISOLATED_WORKER_EGRESS_DENIAL=PASS_STANDALONE_ANDROID35_X86_64
P24_ONE_SYNTHETIC_SONAME_PRELOAD=PASS_ANDROID35_X86_64
P25_EXACT_ORIGINAL_V138_NODE_AND_TEN_ELF_STATIC_ALIAS=PASS_STATIC
P26_MULTILIB_AND_NO_SONAME_PRELOAD=PASS_ANDROID35_X86_64
P27_GITHUB_ARM64_HOST=CI_PENDING
P27_ANDROID_ARM64_GUEST=NOT_TESTED
P27_V138_ORIGINAL_NODE_ISOLATED_ANDROID_BOOT=NOT_TESTED
P27_DSH_PRODUCTION_RUNTIME_MIGRATED=NO
P27_RELEASE=BLOCKED
