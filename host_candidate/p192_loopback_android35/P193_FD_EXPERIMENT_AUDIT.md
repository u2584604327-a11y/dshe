# P193-FD isolated Android 35 disposable experiment — controlled rollback

## Existing verified safe path (unchanged)

Original P193 original-derived Android 35 run
https://github.com/u2584604327-a11y/dshe/actions/runs/42397122631
was SUCCESS with fixed-category markers:

- `P193_ANDROID35_HOST_LOOPBACK_AND_REAL_UID_BINDER=PASS`
- `P193_ANDROID35_WRONG_SESSION_AND_REPLAY=PASS`
- `P193_ANDROID35_ISOLATED_TCP=NOT_USED`
- `P193_ANDROID35_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED`
- `P193_V139=STRUCTURAL_BLOCKED`

P192 original isolated UID 127.0.0.1 bind still returned
`P187B_BLOCKED_P187_ISOLATED_BIND_127001=BIND_EACCES`.
Do not weaken isolatedProcess, SELinux, or fall back to host ProcessBuilder.

## Distinct P193-FD experiment, not a release success

On the same sole Draft PR #80, commits `0e60bd2f`, `cbee7ae2`
and `9bbe5c22` added a **standalone synthetic** Android35 QEMU
application, not part of the original v138 DSH APK. It used no Android
permissions, non-exported isolatedProcess Service, genuine Messenger
framework sender UID, and host-created reliable pipe FD. The expected
negative missing-FD stage was checked, then the worker attempted to read
the synthetic 14-byte fixture through a Binder-transferred descriptor.

- Run https://github.com/u2584604327-a11y/dshe/actions/runs/42397121855:
  `P193_BOUNDARY_OR_DENIAL=DENY` (initial output insufficient).
- Run https://github.com/u2584604327-a11y/dshe/actions/runs/42397437772:
  `P193_DIAG_P193_DENY_HOST=DENY`.
- Run https://github.com/u2584604327-a11y/dshe/actions/runs/42397799151:
  `P193_DIAG_P193_DENY_RETURN_READ=DENY` (host received the
  worker's allowlisted `DENY_FD_READ` response). Static scope and
  Android APK build passed, real FD **read did not**.

The cause of the failed worker read is NOT yet determined. Do not
assert SELinux, pipe ownership, process lifecycle, or faulty OS Binder
without independent error-class evidence. Do not downgrade this failure,
add network permissions, claim isolated Node can consume the FD, or
copy real account data. No user phone, real DSH user profile, original
signed APK, cookies or authentication data were touched.

The experiment was reverted from the sole branch after the final
bounded denial diagnosis. The separate mainline P193 proof remains
the active validated architectural direction. The only retained change
from the experiment is this audit note. There is no P193-FD production
feature to release.

## Remaining stop gates

Real original ARM64 Node runtime + authenticated Binder transport,
complete JS/module/FD workspace, original EngineManager process
ownership, P184 receipt, token-bearing HTTP READY, P209 coroutine
path, actual browser process/OS-user slot mapping and no-data-loss
migration are all NOT ATTESTED. Work-profile DPC policies and genuine
AVF/pVM are also NOT ATTESTED. Keep v139 release STRUCTURAL_BLOCKED.
