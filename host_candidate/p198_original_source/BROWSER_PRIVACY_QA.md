# Browser privacy QA references (manual and opt-in)

This is a deferred DSH v139 compatibility test plan, not an implemented feature or a promise of passing any website's security checks.

The original CreepJS project is maintained at https://github.com/abrahamjuliot/creepjs and directs users to https://abrahamjuliot.github.io/creepjs/ . The unrelated creepjs.org domain must not be presented as that original project's official deployment.

Reference pages:
- https://browserleaks.com/ — browser API support, WebGL, Canvas, WebRTC and privacy leaks.
- https://abrahamjuliot.github.io/creepjs/ — JS feature consistency and browser privacy protection.
- https://iphey.com/ — IP, DNS, timezone and browser environment visibility.
- https://browserscan.net/ — a supplementary browser capability check.
- https://coveryourtracks.eff.org/ — tracking protection and sample-based fingerprint uniqueness.
- https://amiunique.org/ — sample-based browser attribute frequencies.

Acceptance requirements:
1. Visit only after the user explicitly selects a page in the ordinary browser tab, aware of third-party fingerprint and IP collection.
2. Compare actual supported WebView APIs and privacy disclosures against an unmodified browser baseline on the same device. Preserve genuine device characteristics.
3. Do not capture or persist raw fingerprint identifiers, public IP addresses, private browsing data, or site session credentials in DSH diagnostics. Use short redacted categories only.
4. A site score is an observation rather than a certification of trustworthiness, account access or hardware identity.
5. CI uses local synthetic pages only. These external websites are not queried automatically during builds or application startup.
6. Human security challenges and site rules remain under the user's direct control.

P198 is restricted to signed original v138 DEX caller provenance. P47 remains a deny-only production gate; native sensitive tools and screenshot capture remain disabled. Original DSHAPP credits and independent modification notices are retained.
