# P146 bounded original CLI direct-import hint audit
Original exact bin.js bytes are only inspected after P145 authenticated one-shot
lease, P77 complete 30,411-member pinned TAR root, and same-package Android
isolated UID validation. Conservative regex identifies at most 96 *literal*
relative import/from/require hints and verifies whether simple extension/index
candidates are present within the immutable dsh-package tree, returning ONLY
internal counts. Canonical archive names and JS bytes never leave isolated UID.
Unit negatives reject path traversal out of package scope, malformed UTF-8,
null index and hint-budget overflow.

This is NOT a JavaScript parser; comments/dynamic imports/Node builtin modules,
conditional exports, .node modules, transitive package imports and all actual
module resolution are NOT proven. A PASS reports classification only, even if
zero literal hints are detected. No production JS executed; no generic host
filesystem/network, no EngineManager/P37 process handoff or HTTP token READY.
P47 denies host fallback, P109 sensitive tools remain DENY_ALL, v139 BLOCKED.
