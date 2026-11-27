P255 independent explicit if/goto signature review

P254 CI #43343254835 was terminal FAILURE. Its first size method has OPCODE_CHANGED; P253 labeled NORMAL_BRANCH_ORDINALS=ORDINALS_DIFFER automatically for an opcode sequence change. This does not independently prove any actual jump target changed.

P255 retains frozen P253 intact and independently checks concrete if/goto source instruction ordinal, opcode form, destination ordinal and conditional fallthrough. Outputs EXPLICIT_IF_GOTO_SIGNATURE as a fixed category and P253_BRANCH_LABEL_CONFLATED YES or NO. It does not certify complete normal CFG, operands, switch payload, ART verifier, legal relocation, or child ownership. Unchanged P245 full-original static gate is still denied, as are independent P47/P192/B3/B4 runtime release blockers.

167 source-only tests (145 earlier plus 22 new), immutable hash seals for P47, builder, P245/P246/P249/P251/P253, no APK assembly/install, emulator, account access or artifact publication. v139=STRUCTURAL_BLOCKED.
