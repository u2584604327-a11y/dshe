# P251 source-only first method identity and exception-ordinal diagnostic

P250 same-SHA CI #43226732446: first code-size and first exception handler target differences both occur within coarse class OTHER_PRIMARY, but that does not prove the original methods are identical. Original P245 full exception gate remains DENY.

This P251 component compares the first private method keys in memory, emitting only SAME_METHOD, DIFFERENT_METHOD or NOT_APPLICABLE. For TYPED_TARGET differences it independently converts validated DEX code-unit exception destinations and try protected ranges into **instruction ordinal** positions. ORDINALS_MATCH_ONLY is merely a structural observation, NOT proof of legal code relocation, ordinary CFG/reachable edges, branch operand parity, ART verification or process ownership. Both P249-derived mismatch gates remain DENY and the unmodified P245 release blocker remains authoritative.

CI runs 115 synthetic/source-only fixtures including 32 new P251 cases. Original signed v138 is SHA pinned by the optional real-input CLI before reading inputs. No APK rebuild, emulator, user data, source alteration or release. v139=STRUCTURAL_BLOCKED.
