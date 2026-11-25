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
validated for the two fixed fresh-profile config modes only and is not approved for general engine use.

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
worker, build script and typed-denial patcher. The normal worker does not accept this mode. The APK
keeps the established permissionless `com.dsh.p51.isolatedprobe` test identity
and a separate temporary certificate. It cannot upgrade `com.dsh.android`.
The original Node and native dependency provenance checks remain required.

The phone route checks real Binder sender UID, session, ordered child-start
acknowledgment, owner epoch and one-use receipt before obtaining P37. It streams
resources through P37 stdin, verifies stdout/stderr/EOF and authenticated exit,
and cancels on Binder death or deadline. The child checks a real ARM64 kernel
before exec and pins the bootstrap asset. No raw configuration is displayed.
The user-reported 7686479 default-config success is recorded below. The new
original-method handoff still requires a separate phone result.

November 25 input/exit repair
----------------------------

The vivo report for 2c88fcc authenticated CHILD_STARTED and consumed its receipt,
then failed with the previous combined AUTHENTICATED_CHILD_REJECTED status. That
status did not distinguish a valid supervisor FAIL from a protocol rejection and
discarded useful exit diagnostics. It is not a production-module PASS.

The exact pinned 2c88fcc bootstrap independently reproduces exit 125 / EAGAIN on
an empty, open, nonblocking stdin. The repaired receiver retries EAGAIN,
EWOULDBLOCK and EINTR with bounded waiting; all tree verification stays required.
P139 fetches that immutable baseline and repeats this before/after comparison.
The same 69 original modules and byte-identical config must load with delayed
nonblocking chunks. Mutated resources still reject before config output.

Child stdin closure now propagates upstream closure without killing a still-live
child. A real JVM subprocess test requires its later stderr and actual exit 7;
a failed transport read must still cancel it. The config sender closes stdin on
transfer failure and waits for the authenticated error/exit within its deadline.
Authenticated supervisor FAIL now reports only a fixed phase and (after exit)
its numeric status; invalid UID/session/order still closes everything. These
changes fix reproduced defects, but the cause of the reported vivo failure is
not conclusively attributed until the repaired ARM64 route runs on the device.

Reliable pipe ownership repair after the bd4d76e phone result
-----------------------------------------------------------

The user reports VERIFIED_COMPLETE at the resource sender, then supervisor
DRAIN_PIPES failure and child exit 143. This is a failure, not module execution
proof. P68 had closed each sender-side reliable-PFD copy immediately after
Messenger.send. P302 already documented why that can turn EOF into peer DEAD:
closing a duplicate also participates in the shared completion-status socket.
It can consume the peer's OK and leave the actual receiver with no status.
The symmetric writer-copy close can report OK before the real writer finishes,
masking that writer's eventual error.

Sender copies now use the documented Parcelable RETURN_VALUE transfer close:
a temporary Parcel receives a copy, the sender closes without publishing a
completion status, then the temporary copy is recycled. The real Binder receiver
already owns its delivered copy. No detachFd, raw-descriptor close, disabled
checkError or plain-pipe substitution is used. A failed local transfer release
revokes the process. Stdin/stdout/stderr status is owned by their actual stream
endpoints; real errors and peer loss remain failures.

The existing P184 Android35 job runs an actual ART Parcel/PFD fixture as UID2000:
reproduce full-payload/false-cancellation with the old close, require clean EOF
with transfer close, reproduce the old writer-copy error masking, and require
writer-error and silent-peer-loss rejection after repair. It uses the actual
P68 stdin forwarder. This is an Android FD lifecycle test, not a Binder identity
or ARM64 Node attestation. P184's separate real Binder identity/receipt test is
retained. The P302/P306 synthetic stream workflows are not rerun.

AOSP API36 implementation reviewed: ParcelFileDescriptor.writeToParcel uses
Status.SILENCE for PARCELABLE_WRITE_RETURN_VALUE; checkError continues to throw
on non-OK statuses. Source:
https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/os/ParcelFileDescriptor.java


The next disposable P51 build invokes the actual original private
`EngineManager.runDumpConfig()` in a fresh test-owned Context. It stages only the
verified original Node and CLI entry for the original file guards, then hands
its typed P47 config call the exact authenticated P37 Process. The original
reader threads, 30-second wait and DumpResult run unchanged. A receipt is burned
once and the handoff checks the original frame, exact thread, all argv/env/cwd
values and PIPE modes. Missing, stale, replayed or changed requests cannot start
a host process. The two other EngineManager launch seams remain DENY.

The original production P47 Java source still rejects every launch. The CI-only
config delegation is explicit in `patch_config_gate.py`; it cannot initialize
or authorize the installed DSH singleton. The temporary files belong to a new
P51 cache directory and only that invocation's fixed files and empty directories
are cleaned. Existing user profiles are not brokered or represented as empty.
`fresh-config` really selects original `--profile web --dump-config`, independently
compared with the original CLI using Node's normal resolver. This is a bounded
fresh-profile integration, not parity for user configuration or main startup.

User-reported vivo result for commit
768647992573d74fd3254520423b123b5059f12b: original default-config CLI executed
69 original modules and returned 44,560 bytes with SHA256
87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5.
This is a user report from the independent P51 test app, not an independently
observed production EngineManager/HTTP READY result. The new original-method
handoff still needs its own ARM64 device result. No formal v139 is available.
