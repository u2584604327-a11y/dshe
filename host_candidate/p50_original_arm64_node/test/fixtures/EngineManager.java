// JVM test double only. Never packaged in the APK or reported as original ART execution.
package com.dsh.android;
import java.lang.Process;import com.dsh.android.p50.P50OriginalEngineConfig;
public class EngineManager {
 public ProcessBuilder builder;public Process got;public boolean second,wrongThread,lost;
 public EngineManager(ProcessBuilder b){builder=b;}
 public static class DumpResult{}
 public DumpResult runDumpConfig()throws Exception{
  if(wrongThread){final Exception[] e={null};Thread t=new Thread(()->{try{P50OriginalEngineConfig.claim(builder);}catch(Exception x){e[0]=x;}});t.start();t.join();if(e[0]==null)throw new AssertionError();}
  got=P50OriginalEngineConfig.claim(builder);
  if(second)P50OriginalEngineConfig.claim(builder);
  return new DumpResult();
 }
}