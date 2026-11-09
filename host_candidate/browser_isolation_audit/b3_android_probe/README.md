# B3 Android35 real Binder transaction probe (test-only)

Two disposable debug APKs: `com.dsh.b3probe` (host with two non-exported
slot services) and `com.dsh.b3attacker` (separate Linux UID). Both have
zero permissions, no INTERNET, no WebView, no DSH asset, no logins and no
real user files. The host exposes only a **synthetic test** Binder service
so the other APK can verify a rejected actual cross-UID transaction.

The actual host Binder `onTransact` calls
`Binder.getCallingUidOrThrow()` before parsing anything; caller-controlled
PID/UID fields are neither read nor trusted. `getCallingPid` is used
solely to demonstrate two distinct live slot-process calls, not as an
authorization key. Host-issued opaque `IBinder` capabilities are delivered
only by explicit non-exported slot Service bindings, associated *in the
host* with B3 Java gate leases. An unrecognized capability fails closed.
Host monotonic `SystemClock.elapsedRealtime()` supplies expiry; Parcel
byte arrays are sized by the receiver, not the sender's declared length.
The host gate accepts only synthetic read/status actions, one in-flight
operation, sequence-matched one-time results. Tests cover wrong-slot
claims, stale epoch, skips/replays, denied operations, oversized inputs
and results, revoked old pending results, lease renewal, expiry and
unknown capabilities. A second APK with an actual different Linux UID
binds the synthetic exported service and must receive UID_DENIED even
though it provides the expected interface token and a forged-looking
request.

Scope: The two authorized slots still have the **same application UID**.
The issued Binder object is only a cooperative intra-app capability; an
already compromised same-UID process cannot be considered an OS-isolated
adversary. This does NOT prove real BrowserBridge routing, v138/v139
behavior, cookie/IndexedDB safety, work profile, independent Android user,
AVF or protected VM. Run exclusively in a fresh Android35 CI emulator.
Do not install on the owner's phone, build a release, or wire real browsers.

Stop if any exact CI marker is absent. No real profile accounts are
created, read, modified or deleted. AI/OmniGate and GS capture deferred.

### Defensive intra-UID sender continuity check

The probe additionally transfers a valid A capability into the *B* process
while A's result ticket is pending, and transfers the valid B capability
into A for the next request. Both must be denied based on the observed
Binder transaction PID after the first accepted command. A legitimate
later response is accepted once, demonstrating failed theft did not consume
its ticket. The probe's bound PID is diagnostic continuity for a cooperative
same-UID deployment, **not** an authentication principal or a mitigation
against a compromised app process. Process death or service disconnect
revokes the lease; a new process needs a new host-issued session. Production
multi-user/work-profile isolation and data migration remain NOT_ATTESTED.

### B3 synthetic Binder file-descriptor negative gate

The **disposable** live slot process now forwards a *real* kernel pipe FD,
with a fixed synthetic one-byte request, through synchronous Binder. The host
must return `FD_DENIED` before parsing or accepting the request. The Android35
runner requires `B3_ANDROID35_SYNTHETIC_FD_TRANSFER_ALL_STATES_DENIED=PASS`
after attempts under a valid lease, wrong-slot claim, revoked lease, stale
epoch, and expired lease. The regular no-FD request/reply and one-use ticket
must remain functional; the slot closes its temporary received FD.

This is an explicit **no-FD transport** contract, not an FD revocation
implementation. Closing the sender's descriptor does **not** revoke a copy
already transferred to another process. Never put real browser, account,
cookie, file or other sensitive FDs into this test. No production Binder,
BrowserBridge, IPC exports or app permissions are changed.
