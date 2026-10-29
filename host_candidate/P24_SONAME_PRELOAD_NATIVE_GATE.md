# P24 original SONAME vs installer .so filename — real Android35 isolated UID

Date: 2026-10-29. Disposable x86_64 Android experiment ONLY, not a real DSH or original ARM64 Node execution.

## Exact premise grounded in P23
P23 controls proved Bionic dlopen of assets/p23control.so works, while byte-identical version-suffixed .so.3 ZIP entries return native -21 (not found). Thus original ARM64 Node and its versioned DT_NEEDED cannot be declared installable via the P21 ZIP search workaround.

Android NDK official guidance: app PackageManager extracts lib/<abi>/lib<name>.so and Bionic distinguishes DT_NEEDED SONAME from file path. Source docs:
https://developer.android.com/ndk/guides/abis
https://android.googlesource.com/platform/bionic/+/HEAD/android-changes-for-ndk-developers.md

## P24 native positive/negative control
- Real Android NDK x86_64 ELF shared library is physically named libp24version.so and installs under package-managed immutable nativeLibraryDir.
- Its ELF DT_SONAME is exactly libp24version.so.3, which does NOT match its package filename.
- Actual PIE native test binary libp24exec.so has DT_NEEDED libp24version.so.3. The ELF SONAME and DT_NEEDED are verified by readelf in CI.
- A no-permission, non-exported Android isolatedProcess worker executes the exact same binary twice, only with fixed --version argument:
  1. Baseline: LD_LIBRARY_PATH=package nativeLibraryDir, no LD_PRELOAD. Expect linker error containing versioned SONAME.
  2. Control: same path+binary+arguments with LD_PRELOAD set to the exact immutable libp24version.so extracted by PackageManager.
- Real native binary prints its OS getuid() only on success. Worker verifies output equals the isolated service Process.myUid(). Parent verifies Message.sendingUid is framework isolated UID and matches worker.
- Tests have no internet, arbitrary exec, original Node bytes, private secrets, app-private executables, diagnostic upload or target websites. Ephemeral test signer only, destroyed in CI.

## What this can prove (if successful)
Android35 linker can in that isolated UID satisfy a versioned DT_NEEDED from an already-preloaded library with matching internal ELF SONAME, even though its package filename ends in plain .so.

## What this cannot prove
- The original Node AArch64 executable or its 10-library transitive dependency graph can boot under actual ARM64 Android.
- Several libraries preloaded together preserve correct original init/order and symbol binding.
- The linker is safely restricted to correct app installer-managed libraries across OS versions/16KB devices.
- DSH Node is integrated into isolated UID, plugin/JS egress is denied, or authenticated device simulation exists.
- LD_PRELOAD is appropriate for production architecture; missing proof must remain BLOCKED.

## Hard gates
P24_NO_PRELOAD_FAILS_BECAUSE_VERSIONED_DEPENDENCY_MISSING=CI_PENDING
P24_PRELOAD_MATCHING_SONAME_EXECS_AND_UID_MATCHES=CI_PENDING
P24_ACTUAL_ORIGINAL_ARM64_NODE_ISOLATED=NOT_TESTED
P24_PRODUCTION_DSH_MIGRATION=NO
P24_RELEASE=BLOCKED
