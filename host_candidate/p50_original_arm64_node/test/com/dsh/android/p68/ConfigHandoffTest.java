package com.dsh.android.p68;
import com.dsh.android.EngineManager;import com.dsh.android.p50.P50OriginalEngineConfig;
import com.dsh.p37.P37RemoteProcess;import java.io.*;import java.lang.reflect.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public class ConfigHandoffTest {
 static String S=new String(new char[64]).replace('\0','a');static int count;
 static void yes(boolean b){count++;if(!b)throw new AssertionError("check="+count);}
 static ProcessBuilder pb(){return new ProcessBuilder("/private/node","/private/bin.js","--profile","web","--dump-config").directory(new File("/workspace"));}
 static P37RemoteProcess process(AtomicInteger killed){return new P37RemoteProcess(99044,S,u->u==99044,new P37RemoteProcess.RemoteControl(){public void requestGracefulStop(){}public void requestForceStop(){killed.incrementAndGet();}});}
 static P50OriginalEngineConfig config(EngineManager owner,ProcessBuilder expected)throws Exception{
  Constructor<?> c=P50OriginalEngineConfig.class.getDeclaredConstructors()[0];c.setAccessible(true);
  return (P50OriginalEngineConfig)c.newInstance(owner,EngineManager.class.getMethod("runDumpConfig"),expected,S,9L,null);
 }
 static void deny(P50OriginalEngineConfig c,P37RemoteProcess p,P184ChildStartReceipt r)throws Exception{
  try{c.invoke(p,r);throw new AssertionError("accepted");}catch(SecurityException|IOException|InvocationTargetException expected){count++;}
 }
 static void oneOwnerDuringClose()throws Exception{
  AtomicInteger ownedKills=new AtomicInteger(),foreignKills=new AtomicInteger();
  P37RemoteProcess owned=process(ownedKills),foreign=process(foreignKills);
  EngineManager owner=new EngineManager(pb());
  owner.claimed=new CountDownLatch(1);owner.finish=new CountDownLatch(1);
  P50OriginalEngineConfig config=config(owner,pb());
  P184ChildStartReceipt first=new P184ChildStartReceipt(owned,99044,S,9,()->true);
  P184ChildStartReceipt next=new P184ChildStartReceipt(foreign,99044,S,9,()->true);
  AtomicReference<Throwable> result=new AtomicReference<>();
  Thread thread=new Thread(()->{try{config.invoke(owned,first);}catch(Throwable fault){result.set(fault);}});
  thread.start();
  try{
   yes(owner.claimed.await(5,TimeUnit.SECONDS));
   deny(config,foreign,next);
   yes(!next.isConsumed()&&foreignKills.get()==0&&ownedKills.get()==0);
   config.close();
   yes(ownedKills.get()==1&&foreignKills.get()==0);
  }finally{
   owner.finish.countDown();thread.join(6000);config.close();
  }
  yes(!thread.isAlive()&&result.get() instanceof IOException&&first.isConsumed());
  deny(config,foreign,next);
  yes(!next.isConsumed()&&foreignKills.get()==0&&ownedKills.get()==1);
 }
 public static void main(String[] args)throws Exception{
  for(String mode:new String[]{"valid","thread","replay","argv","env","cwd","redirect","transport","receipt","epoch","raw-call","double","plan-snapshot"}){
   AtomicInteger killed=new AtomicInteger();P37RemoteProcess p=process(killed);ProcessBuilder b=pb();EngineManager owner=new EngineManager(b);
   P50OriginalEngineConfig c=config(owner,b);P184ChildStartReceipt r=new P184ChildStartReceipt(p,99044,S,mode.equals("epoch")?8:9,()->true);
   if(mode.equals("argv"))owner.builder=pb().command("/system/bin/sh","-c","id");
   if(mode.equals("env")){owner.builder=pb();owner.builder.environment().put("NODE_OPTIONS","--import /private/evil");}
   if(mode.equals("cwd"))owner.builder=pb().directory(new File("/"));
   if(mode.equals("redirect"))owner.builder=pb().redirectErrorStream(true);
   if(mode.equals("transport"))p.onTransportLost();
   if(mode.equals("receipt"))r.revoke();
   if(mode.equals("thread"))owner.wrongThread=true;
   if(mode.equals("double"))owner.second=true;
   if(mode.equals("plan-snapshot")){owner.builder=pb();b.command().set(0,"/mutated");}
   if(mode.equals("raw-call")){try{P50OriginalEngineConfig.claim(b);throw new AssertionError();}catch(IOException expected){count++;}}
   else if(mode.equals("valid")||mode.equals("thread")||mode.equals("replay")||mode.equals("plan-snapshot")){
    yes(c.invoke(p,r)!=null);yes(owner.got==p);yes(r.isConsumed());
    if(mode.equals("replay")){deny(c,p,r);yes(killed.get()==0);}
   }else{
    deny(c,p,r);yes(r.isConsumed());
    yes(killed.get()==(mode.equals("receipt")||mode.equals("epoch")?0:1));
   }
   try{P50OriginalEngineConfig.claim(b);throw new AssertionError("leaked lease");}catch(IOException expected){count++;}
   c.close();
  }
  oneOwnerDuringClose();
  System.out.println("ORIGINAL_CONFIG_HANDOFF_JVM_NEGATIVES=PASS checks="+count);
  System.out.println("ORIGINAL_CONFIG_REAL_ART_AND_BINDER=NOT_ATTESTED_BY_JVM");
 }
}
