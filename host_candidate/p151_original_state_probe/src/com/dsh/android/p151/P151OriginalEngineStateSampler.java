package com.dsh.android.p151;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Read-only live original EngineManager state from its existing singleton.
 * Does NOT call Companion.get(), ensureExtracted(), start() or spawn a process.
 * Never publishes message text, URL, private paths or exception details.
 */
public final class P151OriginalEngineStateSampler {
  private static final String ENGINE="com.dsh.android.EngineManager";
  private static final String STATE=ENGINE+"$State$";
  private P151OriginalEngineStateSampler(){}

  public static String classifyName(String name) {
    if(name==null || !name.startsWith(STATE))return "UNRECOGNIZED_STATE";
    String suffix=name.substring(STATE.length());
    switch(suffix){
      case "Idle":return "IDLE";
      case "Extracting":return "EXTRACTING";
      case "Starting":return "STARTING";
      case "Ready":return "READY";
      case "Failed":return "FAILED";
      case "Dead":return "DEAD";
      default:return "UNRECOGNIZED_STATE";
    }
  }
  /** Only a fixed allowlisted category escapes, not the original message. */
  public static String classifyFailure(String message) {
    if(message==null)return "FAILED_MESSAGE_UNAVAILABLE";
    if(message.startsWith("Termux 环境未就绪"))return "FAILED_TERMUX_NODE_SETUP";
    if(message.startsWith("找不到 Node 可执行文件"))return "FAILED_NODE_BINARY_MISSING";
    if(message.startsWith("找不到引擎入口"))return "FAILED_ENTRY_MISSING";
    if(message.startsWith("引擎进程启动失败"))return "FAILED_PROCESS_START";
    if(message.startsWith("引擎解包失败"))return "FAILED_EXTRACTION";
    return "FAILED_OTHER_REDACTED";
  }
  public static final class Sample {
    public final String state;
    public final String cause;
    private Sample(String state,String cause){
      this.state=state;this.cause=cause;
    }
    public String safeLine(){return state+"_"+cause;}
  }
  public static Sample sample() {
    try {
      Class<?> engine=Class.forName(ENGINE);
      // The original Kotlin private singleton is observed, never created.
      Field f=engine.getDeclaredField("instance");
      if(!Modifier.isStatic(f.getModifiers()))return new Sample("UNREADABLE","SINGLETON_NOT_STATIC");
      f.setAccessible(true);
      Object instance=f.get(null);
      if(instance==null)return new Sample("MISSING","SINGLETON_NOT_INITIALIZED");
      Method getter=engine.getMethod("getState");
      Object flow=getter.invoke(instance);
      if(flow==null)return new Sample("UNREADABLE","STATE_FLOW_NULL");
      // Call the public StateFlow interface, not private implementations.
      Class<?> stateFlow=Class.forName("kotlinx.coroutines.flow.StateFlow");
      Method getValue=stateFlow.getMethod("getValue");
      Object value=getValue.invoke(flow);
      if(value==null)return new Sample("UNREADABLE","STATE_VALUE_NULL");
      String state=classifyName(value.getClass().getName());
      if(!"FAILED".equals(state))return new Sample(state,"NO_FAILURE_TEXT_READ");
      // Read the original message only in-process and immediately reduce
      // to a categorical value. Never log/stringify it or an exception.
      Method message=value.getClass().getMethod("getMessage");
      Object raw=message.invoke(value);
      return new Sample("FAILED",classifyFailure(raw instanceof String?(String)raw:null));
    }catch(Throwable denied){
      return new Sample("UNREADABLE","REFLECTION_ORIGINAL_STATE_UNAVAILABLE");
    }
  }
}
