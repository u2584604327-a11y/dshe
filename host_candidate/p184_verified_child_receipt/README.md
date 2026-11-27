# P184: trusted P68 child-start receipt to P75 exact Process

Scope: sole u2584604327-a11y/dshe Draft PR #80 and existing dsh/p96-original-engine-stream-owner-narrow-20261030 branch. Current phase is Java8 negative/compatibility tests and Android source compilation. No signed APK, on-device install, Node execution or production engine READY is claimed.

Problem: previous P75 authenticatedChildStarted(session,remote,uid,verifier) accepts caller-provided claims even though P68 already receives the real Android framework Message.sendingUid. It is therefore not an independent native attestation.

Implementation:
- P184ChildStartReceipt is a Java8 final type with package-private constructor in com.dsh.android.p68. Only trusted P68-package code can mint it in ordinary source boundaries. It binds exact P37 object identity, isolated UID, host session, owner epoch, live issuer predicate and <=12 sec age. First consumption attempt burns it; revoke on disconnect/transport loss; clean rapid REMOTE_EXIT accepted but transport/identity/buffer failures denied.
- P68 receipt issuance is opt-in via trusted native host epoch constructor. Default existing P68 constructors issue no receipt. A receipt exists only after the framework sender UID, host session and ordered P53 CHILD_STARTED are independently accepted by P67. No worker Bundle UID, HELLO, or webpage message may grant it. P68 rejects/disconnects revoke outstanding receipts.
- P75 receives a new explicit armForVerifiedChildReceipt(hostSession,ownerEpoch) mode and authenticatedChildStartedWithReceipt(receipt,remote). In this opt-in mode the legacy UID/BooleanVerifier API returns false; only the exact issuer receipt can satisfy P75. The previous fixed /system/bin/id -u test adapter remains separate and is NOT approved for production Node. P47 forbids host ProcessBuilder fallback.
- Existing P75 JVM regressions and new P184 Java8 replay, wrong session, exact Process, owner epoch, pre-EXIT, transport failure, interrupted/cancel, concurrency and legacy-bypass tests must pass. Compile actual Android P68 + P67 + P53 + P37 + P75 with API35 jar. Android platform Binder receipt E2E requires a separate real two-UID emulator test; it is NOT proven by JVM or Android stub compilation.

Future single blocker: run actual P43/P48 isolated fixed child over real Android35 Messenger and show P68 receipt minted only from framework Message.sendingUid, then delivered once to P75 with exact Process and owner epoch. Only after that should original ARM64 Node + FD JS workspace + authentic HTTP token READY be researched. Until all production gates pass, DSH v139 is STRUCTURAL_BLOCKED.

No new privileges, keys, accounts, cookies, login challenges, website anti-bot workarounds, signing or APK distribution. Original DSHAPP MIT credit, concept-only Shelter/gVisor/AVF and OmniGate behavioral reference must remain accurately documented; see REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md in repository root.
