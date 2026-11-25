Original module execution boundary
==================================

This implementation executes the unmodified v138 `dsh` entry's exported
`runCli()` with fixed `--dump-default-config --profile web` arguments. It does
not authorize EngineManager, HTTP, user profiles, native addons or production
P47. The default-config command is not a READY check.

`P50ModuleStream` reuses the canonical P77 TAR parser and emits bounded member
records. It emits the completion marker only after the original 30,411-member,
262,498,938-byte tree matches the pinned digest. The Node bootstrap independently
checks every record, path, type, length, content digest, member count, native
addon count, tree digest and EOF before importing any original module. Native
addons remain denied. The immutable tree includes the full original dependency
closure, rather than substituting a fixed BOOT/READY program.

The original command initializes a web profile even for a default-config dump.
Only fresh in-memory `/dsh-home/profiles/web` state is writable, bounded to 64
files and 2 MiB. Original resources cannot be changed. This state is discarded
with the child; it neither reads nor persists account data. Unsupported file
descriptor APIs are denied. This narrow filesystem/resolver adapter has been
validated for default-config only and is not approved for general engine use.

Local reproducible check (JDK 17 and a host Node 26.4.0 required):

    python host_candidate/p50_original_arm64_node/verify_original_modules.py \
      --apk /path/to/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk \
      --host-node /path/to/node

The check validates the APK digest, uses a real OS pipe, and compares the
44,560-byte output against an independent run of the original entry with Node's
ordinary filesystem and resolver. Only the two resource/home root paths in the
reference output are normalized. The result is byte-identical, SHA256
`87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5`.
Truncation, traversal, oversized lengths, version drift, trailing bytes and
changed content must reject before any config output. These host checks do not
prove Android ARM64 execution.

P139's disposable build pins and patches only the existing probe Activity,
worker and build script. The normal worker does not accept this mode. The APK
keeps the established permissionless `com.dsh.p51.isolatedprobe` test identity
and a separate temporary certificate. It cannot upgrade `com.dsh.android`.
The original Node and native dependency provenance checks remain required.

The phone route checks real Binder sender UID, session, ordered child-start
acknowledgment, owner epoch and one-use receipt before obtaining P37. It streams
resources through P37 stdin, verifies stdout/stderr/EOF and authenticated exit,
and cancels on Binder death or deadline. The child checks a real ARM64 kernel
before exec and pins the bootstrap asset. No raw configuration is displayed.
The phone result remains pending until the APK actually runs on ARM64 Android.
