package com.dsh.android.p134;

public final class P134RealArm64GateTest {
  private static int checked;
  private static void check(String name, boolean expected, boolean actual) {
    checked++;
    if (expected != actual) throw new AssertionError(name + " expected=" + expected);
  }
  public static void main(String[] args) {
    String[] real = {"arm64-v8a", "armeabi-v7a"};
    String[] bridge = {"x86_64", "arm64-v8a", "x86"};
    check("real-arm64-service",true,P134RealArm64Gate.allow(true,35,real,"aarch64"));
    check("arm64-api34-service",true,P134RealArm64Gate.allow(true,34,real,"aarch64"));
    check("x86-nativebridge-advertises-arm64",false,
        P134RealArm64Gate.allow(true,35,bridge,"x86_64"));
    check("bridge-with-arm64-first-and-x86-kernel",false,
        P134RealArm64Gate.allow(true,35,real,"x86_64"));
    check("isolated-false",false,P134RealArm64Gate.allow(false,35,real,"aarch64"));
    check("old-android",false,P134RealArm64Gate.allow(true,33,real,"aarch64"));
    check("api-zero",false,P134RealArm64Gate.allow(true,0,real,"aarch64"));
    check("unknown-kernel",false,P134RealArm64Gate.allow(true,35,real,null));
    check("empty-kernel",false,P134RealArm64Gate.allow(true,35,real,""));
    check("armv7-kernel",false,P134RealArm64Gate.allow(true,35,real,"armv7l"));
    check("null-abi",false,P134RealArm64Gate.allow(true,35,null,"aarch64"));
    check("empty-abi",false,P134RealArm64Gate.allow(true,35,new String[0],"aarch64"));
    check("x86-primary-abi-even-with-arm64-kernel",false,
        P134RealArm64Gate.allow(true,35,bridge,"aarch64"));
    check("32bit-primary-abi",false,P134RealArm64Gate.allow(true,35,
        new String[]{"armeabi-v7a","arm64-v8a"},"aarch64"));
    check("arch-string-case-mismatch",false,P134RealArm64Gate.allow(true,35,real,"AARCH64"));
    check("arm64-kernel-abi-whitespace",false,P134RealArm64Gate.allow(true,35,
        new String[]{"arm64-v8a "},"aarch64"));
    System.out.println("P134_REAL_ARM64_KERNEL_AND_ISOLATED_GUARD=PASS");
    System.out.println("P134_FAIL_CLOSED_JVM_CASES="+checked);
    System.out.println("P134_X86_TRANSLATED_ARM64_REJECTED=PASS");
    System.out.println("P134_REAL_ORIGINAL_NODE_EXECUTION=NOT_TESTED");
    System.out.println("P134_PRODUCTION_ISOLATED_UID=NOT_TESTED");
    System.out.println("P134_P109_NATIVE_TOOLS=DENY_ALL");
    System.out.println("P134_FORMAL_V139=BLOCKED");
  }
}
