package com.dsh.android.p68;
import com.dsh.android.EngineManager;import com.dsh.android.p50.P50OriginalEngineConfig;
import com.dsh.p37.P37RemoteProcess;import java.io.*;import java.lang.reflect.*;import java.util.concurrent.atomic.*;
public class ConfigHandoffTest {
 static String S=new String(new char[64]).replace('\0','a');static int count;
 static void yes(boolean b){count++;if(!b)throw new AssertionError("check="+count);}
 static ProcessBuilder pb(){return new ProcessBuilder("/private/node","/private/bin.js","--profile","web","--dump-config").directory(new File("/workspace"));}
 static P37RemoteProcess process(AtomicInteger killed){return new P37RemoteProcess(99044,S,u->u==99044,new P37RemoteProcess.RemoteControl(){public void requestGracefulStop(){}public void requestForceStop(){killed.incrementAndGet();}});}
 static P50OriginalEngineConfig config(EngineManager owner,ProcessBuilder expected)throws Exception{
  Constructor<?> c=P50OriginalEngineConfig.class.getDeclaredConstructors()[0];c.setAccessible(true);
  return (P50OriginalEngineConfig)c.newInstance(owner,EngineManager.class.getMethod("runDumpConfig"),expected,S);
 }
 static void deny(P50OriginalEngineConfig c,P37RemoteProcess p,P184ChildStartReceipt r)throws Exception{
  try{c.invoke(p,r,9);throw new AssertionError("accepted");}catch(SecurityException|IOException|InvocationTargetException expected){count++;}
 }
 public static void main(String[] args)throws Exception{
  for(String mode:new String[]{"valid","thread","replay","argv","env","cwd","redirect","transport","receipt","raw-call","double"}){
   AtomicInteger killed=new AtomicInteger();P37RemoteProcess p=process(killed);ProcessBuilder b=pb();EngineManager owner=new EngineManager(b);
   P50OriginalEngineConfig c=config(owner,b);P184ChildStartReceipt r=new P184ChildStartReceipt(p,99044,S,9,()->true);
   if(mode.equals("argv"))owner.builder=pb().command("/system/bin/sh","-c","id");
   if(mode.equals("env")){owner.builder=pb();owner.builder.environment().put("NODE_OPTIONS","--import /private/evil");}
   if(mode.equals("cwd"))owner.builder=pb().directory(new File("/"));
   if(mode.equals("redirect"))owner.builder=pb().redirectErrorStream(true);
   if(mode.equals("transport"))p.onTransportLost();
   if(mode.equals("receipt"))r.revoke();
   if(mode.equals("thread"))owner.wrongThread=true;
   if(mode.equals("double"))owner.second=true;
   if(mode.equals("raw-call")){try{P50OriginalEngineConfig.claim(b);throw new AssertionError();}catch(IOException expected){count++;}}
   else if(mode.equals("valid")||mode.equals("thread")||mode.equals("replay")){
    yes(c.invoke(p,r,9)!=null);yes(owner.got==p);yes(r.isConsumed());
    if(mode.equals("replay")){deny(c,p,r);yes(killed.get()==1);}
   }else{deny(c,p,r);yes(r.isConsumed());yes(killed.get()==1||mode.equals("transport"));}
   try{P50OriginalEngineConfig.claim(b);throw new AssertionError("leaked lease");}catch(IOException expected){count++;}
  }
  System.out.println("ORIGINAL_CONFIG_HANDOFF_JVM_NEGATIVES=PASS checks="+count);
  System.out.println("ORIGINAL_CONFIG_REAL_ART_AND_BINDER=NOT_ATTESTED_BY_JVM");
 }
}