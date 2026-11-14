package com.dsh.android.p134;

/** P134 fail-closed preflight for the exact-v138 original Node candidate.
 * Merely advertising arm64-v8a through Native Bridge is not sufficient.
 * The caller MUST obtain machine from android.system.Os.uname().machine
 * inside the actual Android isolated service; caller data is not trusted.
 * PASS grants no executable, Binder, file, network or release authority.
 */
public final class P134RealArm64Gate {
  private P134RealArm64Gate() {}

  public static boolean allow(boolean isIsolated, int api,
      String[] processAbis, String actualKernelMachine) {
    return isIsolated
        && api >= 34
        && "aarch64".equals(actualKernelMachine)
        && processAbis != null
        && processAbis.length > 0
        && "arm64-v8a".equals(processAbis[0]);
  }
}
