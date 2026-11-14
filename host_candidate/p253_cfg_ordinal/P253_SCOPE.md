# P253 original method CFG ordinal contract — source only

P252 [CI #43243101054](https://github.com/u2584604327-a11y/dshe/actions/runs/43243101054) was terminal FAILURE: the *first* original code-size difference and first TYPED_TARGET exception-address difference were proven to be in the SAME_METHOD, and the exception handler ordinal mapping was observed as ORDINALS_MATCH_ONLY. This is not equivalent to P245 full parity.

## Limits

The P253 scanner checks only the first original code-size differing method, with the exact original method set independently verified through P251/P249. It requires P246 gap-free byte/code-unit decoding, then compares instruction **count**, opcode sequence, instruction widths, explicit conditional/jump ordinal targets and conditional fallthrough, and P251 exception protected-region/handler ordinal mappings. Branch offsets are relative to the branch instruction, measured in DEX 16-bit code units. Targets inside instructions or out of bounds are denied. Switch/fill-array payloads are deliberately unsupported: fail closed, not ignored. All outputs are sanitized fixed categories; no actual method names, operands, offsets, data strings or raw DEX retained.

This classifier does **not** establish ordinary operands, hidden control-flow, switch case graph, ART acceptance, process ownership, P209 PC3912→P47, or legal relocation. An ORDINALS_MATCH_ONLY result is a necessary-only structural observation. The original P245 complete structural/handler validation remains immutable and DENY. v139 remains STRUCTURAL_BLOCKED. No build, patch, signing, installation, emulator, user account access or release in P253.

145 synthetic source-only fixtures: P245 15, P246 30, P247 12, P249 26, P251 32, P253 30.
