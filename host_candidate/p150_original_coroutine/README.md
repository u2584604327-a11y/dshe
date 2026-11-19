# P150 — original EngineManager main-coroutine prelaunch stack observation

The exact signed-v138 main DEX P40 bridge -> P47 fail-closed hook now records
a bounded, nonsecret shape of the live Java call stack. The required
signature has P47.startOrDeny before P40ProcessBridge.start before
EngineManager$start$2.invokeSuspend; it is recorded only in a private
atomic counter. The P43 synthetic ProcessBuilder MUST enter the other counter
instead. In the Android35 same-package temporary APK, original MainActivity
is started, then P43 receives a passive read-out after its isolated Binder
HELLO. The result explicitly distinguishes OBSERVED from NOT_OBSERVED.
No fabricated success if the original startup cannot get past Termux
bootstrap/preflight on x86_64; neither branch authorizes Node execution.

This is Java stack SHAPE evidence only, not identity/authentication, cannot
certify an independent live EngineManager command source, P37 Process
lifecycle, Node module dependency graph or token URL Ready. Same-UID
malicious code could imitate stack frames. P47 host ProcessBuilder.start
remains DENIED and P109 sensitive native tool execution remains DENY_ALL.
No user phone/data, sign/release, or network usage.
