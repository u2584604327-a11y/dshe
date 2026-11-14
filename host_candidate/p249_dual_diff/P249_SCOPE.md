# P249 dual-channel source-only audit

P248 CI #43222357607 was FAILURE. The P246 first mismatch was OTHER_PRIMARY / CODE_SIZE, while unchanged P245 verification denied ORIGINAL_EXCEPTION_SEMANTICS; these are not yet proven to be the same method.

P249 separately finds the first original code-item size mismatch and first *exception-specific* catch table mismatch, using strict P247 decode for both sides and stable sorted method order. Sanitized output contains only enum groups and discrepancy classes, never real method names/offsets/strings. These diagnostic results cannot override unchanged P245 full parity or attest ART/runtime behavior.

Any future real signed-original/base/candidate invocation requires original size and SHA256 seal. Source-only CI never reads/builds an APK; 68 synthetic tests enforce negative cases. No original app, P47, P181/P182/P109, P209 or branch guards changed. v139=STRUCTURAL_BLOCKED.
