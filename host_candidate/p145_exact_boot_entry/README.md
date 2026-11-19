# P145 exact original CLI source and package, no execution
The pinned public upstream EngineManager original Kotlin source
(pht88888888/DSHAPP@4dddb12fd076d052e788a16638a658b7a447b669)
forms its CLI pathname from node_modules/@deepseek-ai/dsh/lib/bin.js.
P144 already passes two arbitrary source leases, not necessarily related
to that real CLI. This independent P145 gate selects ONLY the fixed CLI
file and its sibling node_modules/@deepseek-ai/dsh/package.json in the
real original-v138 APK archive. A full P77 original 30,411-file root hash,
Binder UID/session and an unlinked read-only FD are required. Missing or
oversized entries, an unverified archive, a replay, or wrong session fail
closed. These bytes are never sent back through Binder or executed.
The exact CLI shape originates in pinned upstream source and the source
resource in original-v138 APK; equality of the modified v138 runtime's
DEX command path with upstream is not established by this test.
No require/import closure, real argv/env/cwd mapping, Node native loader,
actual HTTP server or P37 original EngineManager Process binding is proved.
P47 host fallback, P109 native sensitive tools and v139 release remain DENIED.
No user's installed package, data, signer, or network touched.
