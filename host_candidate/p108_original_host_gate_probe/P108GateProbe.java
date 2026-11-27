import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;

/** JVM behavior probe for the actual compiled Kotlin original-host P108 gate. */
public final class P108GateProbe {
  private static Method find(Class<?> c, String prefix, int count) {
    Method[] found=Arrays.stream(c.getDeclaredMethods())
      .filter(m->m.getName().startsWith(prefix)&&m.getParameterCount()==count)
      .toArray(Method[]::new);
    if(found.length!=1)throw new AssertionError("P108_AMBIGUOUS_METHOD_"+prefix);
    found[0].setAccessible(true);
    return found[0];
  }
  private static void require(boolean condition,String label){
    if(!condition)throw new AssertionError("P108_"+label);
  }
  public static void main(String[] ignored)throws Exception{
    Class<?> type=Class.forName("com.dsh.android.P108OriginalOwnerEpochGate");
    Constructor<?> ctor=type.getDeclaredConstructor();
    ctor.setAccessible(true);
    Object gate=ctor.newInstance();
    Method state=find(type,"observeEngineState",1);
    Method epoch=find(type,"currentEpochForNativeDiagnostics",0);
    Method authorize=find(type,"authorizeOriginalToolCall",3);
    Method destroy=find(type,"onActivityDestroyed",0);
    require(((Long)epoch.invoke(gate))==0L,"INITIAL_EPOCH_NOT_ZERO");
    for(Object[] claim:new Object[][]{
      {null,null,0L},{"forged-session","forged-call",0L},
      {"original-session","pending-call",1L}
    }){
      require(Boolean.FALSE.equals(authorize.invoke(gate,claim)),"UNVERIFIED_CALL_ACCEPTED");
    }
    state.invoke(gate,true);
    require(((Long)epoch.invoke(gate))==1L,"READY_NOT_EPOCH_1");
    require(Boolean.FALSE.equals(authorize.invoke(gate,"sess","call",1L)),
      "READY_GENERATION_AUTHORIZES_NODE_CLAIM");
    state.invoke(gate,true);
    require(((Long)epoch.invoke(gate))==1L,"READY_DUPLICATE_ROTATES_EPOCH");
    state.invoke(gate,false);
    require(((Long)epoch.invoke(gate))==2L,"DEAD_DID_NOT_REVOKE_GENERATION");
    state.invoke(gate,true);
    require(((Long)epoch.invoke(gate))==3L,"ENGINE_RESTART_MISSING_FRESH_EPOCH");
    require(Boolean.FALSE.equals(authorize.invoke(gate,"sess","call",3L)),
      "ENGINE_RESTART_PERMITTED_UNVERIFIED_CALL");
    destroy.invoke(gate);
    require(((Long)epoch.invoke(gate))==4L,"ACTIVITY_DESTROY_NOT_REVOKED");
    state.invoke(gate,true);
    require(((Long)epoch.invoke(gate))==4L,"ACTIVITY_DESTROY_REACTIVATED");
    require(Boolean.FALSE.equals(authorize.invoke(gate,"sess","call",4L)),
      "DESTROYED_ACTIVITY_ACCEPTED_CLAIM");
    System.out.println("P108_COMPILED_KOTLIN_EPOCH_TRANSITIONS=PASS");
    System.out.println("P108_COMPILED_KOTLIN_UNVERIFIED_TOOL_CALL_DENY=PASS");
    System.out.println("P108_COMPILED_KOTLIN_DESTROY_IRREVOCABLE=PASS");
    System.out.println("P108_ORIGINAL_TOOLRUNTIME_PRODUCTION=NOT_WIRED");
  }
}
