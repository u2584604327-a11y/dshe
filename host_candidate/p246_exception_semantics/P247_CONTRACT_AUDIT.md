# P247 exception-table classifier hardening (source-only)

- DEX `code_item.insns_size` is measured in 16-bit code units.
- Androguard `get_instructions_idx()` and `Instruction.get_length()` are in **bytes**. Reconstructed instruction widths must cover exactly `2 * insns_size` with no gaps or overlap.
- DEX `try_item.start_addr`, `insn_count`, and catch handler target addresses are in **16-bit code units**; `try_item.handler_off` is in **bytes** from the beginning of the `encoded_catch_handler_list`.
- All handler definitions must be referenced by at least one try item for a *complete-table* attestation. Any unreferenced entry fails closed rather than being silently omitted.
- The classifier still resolves each typed catch against its **own** DEX pool and compares ordered semantic results; pool index/absolute file offsets are not equated to semantics.
- P246 existing 30 fixtures + P247 12 adversarial fixtures. They cover synthetic inputs **only**. The original P245 candidate APK was destroyed by CI; the genuine first method-level semantic difference remains `NOT_ATTESTED`.
- No original APK/DEX modifications, smali, apktool, adb, Android emulator, P47 change, or user accounts. `v139=STRUCTURAL_BLOCKED`.

Normative definition: https://source.android.com/docs/core/runtime/dex-format
