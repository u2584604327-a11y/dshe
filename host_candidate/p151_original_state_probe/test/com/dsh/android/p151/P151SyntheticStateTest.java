package com.dsh.android.p151;
public final class P151SyntheticStateTest {
  private static void ok(boolean test){if(!test)throw new AssertionError("P151_STATE_CLASSIFIER_BAD");}
  public static void main(String[] ignore) {
    final String prefix="com.dsh.android.EngineManager$State$";
    for(String n:new String[]{"Idle","Extracting","Starting","Ready","Failed","Dead"})
      ok(!"UNRECOGNIZED_STATE".equals(P151OriginalEngineStateSampler.classifyName(prefix+n)));
    ok("UNRECOGNIZED_STATE".equals(P151OriginalEngineStateSampler.classifyName(
       "com.evil.EngineManager$State$Ready")));
    ok("UNRECOGNIZED_STATE".equals(P151OriginalEngineStateSampler.classifyName(null)));
    ok("FAILED_TERMUX_NODE_SETUP".equals(P151OriginalEngineStateSampler.classifyFailure(
       "Termux 环境未就绪，无法启动引擎。prefix=/PRIVATE/DO_NOT_PRINT")));
    ok("FAILED_NODE_BINARY_MISSING".equals(P151OriginalEngineStateSampler.classifyFailure(
       "找不到 Node 可执行文件: /PRIVATE/DO_NOT_PRINT")));
    ok("FAILED_ENTRY_MISSING".equals(P151OriginalEngineStateSampler.classifyFailure(
       "找不到引擎入口: /PRIVATE/DO_NOT_PRINT")));
    ok("FAILED_PROCESS_START".equals(P151OriginalEngineStateSampler.classifyFailure(
       "引擎进程启动失败: PRODUCTION_SECRET_DO_NOT_PRINT")));
    ok("FAILED_EXTRACTION".equals(P151OriginalEngineStateSampler.classifyFailure(
       "引擎解包失败: user file path")));
    ok("FAILED_OTHER_REDACTED".equals(P151OriginalEngineStateSampler.classifyFailure(
       "unrecognized sensitive value")));
    ok(!P151OriginalEngineStateSampler.classifyFailure(
       "Termux 环境未就绪，无法启动引擎。prefix=/PRIVATE/DO_NOT_PRINT").contains("PRIVATE"));
    // Standalone test JVM doesn't contain original EngineManager; sampling
    // must stay fail-closed and never initialize an engine.
    P151OriginalEngineStateSampler.Sample sample=P151OriginalEngineStateSampler.sample();
    ok("UNREADABLE".equals(sample.state) && sample.safeLine().indexOf('/')<0);
    System.out.println("P151_CATEGORICAL_FAILURE_REDACTION_NEGATIVES=PASS");
    System.out.println("P151_JVM_NO_REAL_ENGINE_SINGLETON_EXPECTED=YES");
  }
}
