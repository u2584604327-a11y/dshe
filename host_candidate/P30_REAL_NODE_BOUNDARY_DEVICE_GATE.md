# P30 confirmed P29 test harness defect and owner API36 results

## Exact reported original Node evidence
Android API36 arm64-v8a, Node process.getuid()=99050, native Node exit=0.
Node TCP connect 127.0.0.1:9 and RFC5737 TEST-NET-2
198.51.100.1:443 both DENIED_EACCES in real device report.
Node app-private canary read returned OTHER_ENOENT.
P29 host UI reported WORKER_BINDER_ISOLATED_UID=FAIL even though
the Java Worker built and ran the original Node.

## Precisely identified P29 defect
P29Worker.java writes:
result.putInt("isolatedUid",Process.myUid())
but P29Activity.java reads:
b.getInt("workerUid",-1)
The reliable Android framework Messenger sendingUid is separately checked.
The inconsistent key alone is sufficient to force host identity check FAIL,
which masks true allHashes and uidMatch statuses in UI. This is a
DEFINITE test instrumentation error; it does not prove OS UID isolation failed.
Do not remove framework authenticated sender check or trust Worker-reported
UID as a substitute.

## P30 actual fix
- Entirely separate com.dsh.p30.nodeprobe package; never updates existing
  P29/P28 or user's production DSH.
- Worker reports exact workerUid key expected by UI. Host checks
  Process.isIsolatedUid(actual Messenger sendingUid), != own UID, equals
  worker-provided Worker UID, and Worker reports Process.isIsolated().
- Worker runs original hash-pinned Node + ten original libraries with fixed
  --eval program, only safe file and fixed TEST-NET/loopback TCP probes;
  original Node returns real getuid and OS errors, not Java-only mocks.
- Host generates P30-only random 32-byte private test canary and stores
  original SHA-256 digest in process memory. Before entering isolated Worker,
  host reopens and SHA-verifies canary. On receiving IPC result, host again
  reopens and SHA-verifies the unchanged host-only file BEFORE deleting it.
- If Node file result is ENOENT while host canary remains byte-identical,
  report a PARTIAL_PASS for "not visible while host still had canary" only,
  explicitly NOT EACCES/EPERM ACL-denial PASS. If host liveness fails,
  classify BLOCKED.
- File true EACCES/EPERM plus Node UID equals isolated Service, authentic
  Binder sender, exact original ELF SHA and BOTH TCP EACCES/EPERM are needed
  for strict PASS. All unknown results, ENOENT without positive host
  control, ECONNREFUSED/TIMEOUT, Node uid mismatches => fail closed.
- No personal user files touched, no automatic network diagnostic payload,
  no auto upload, no original signer or production DSH.
- Private Draft Release only, owner's existing consent; old completed P29
  private Draft delete only AFTER P30 Draft created and assets rechecked.

## Provenance and remaining gates
P29 original device report is owner-copied text, not signed hardware
attestation. Android isolated_app AID ranges 99000..99999 make Node 99050
compatible with genuine isolated UID, but strict proof remains P30's
Binder Message.sendingUid / Worker / Child three-way comparison.

P30_BUILD=CI_PENDING
P30_PRIVATE_DRAFT=CI_PENDING
P30_ANDROID_API36_REAL_NODE_CHILD_UID_MATCH=NOT_TESTED
P30_NODE_TCP_EACCES_REPRODUCED=NOT_TESTED
P30_CANARY_HOST_POSITIVE_CONTROL=NOT_TESTED
P30_DSH_V139_FULL_HOST_ISOLATION=NOT_PROVEN
P30_DSH_V139_RELEASE=BLOCKED
