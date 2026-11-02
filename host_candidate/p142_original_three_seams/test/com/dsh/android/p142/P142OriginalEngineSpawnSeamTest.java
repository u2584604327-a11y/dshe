package com.dsh.android.p142;
import java.io.*;
import java.util.*;
public final class P142OriginalEngineSpawnSeamTest {
  private static int checks=0;
  private static void ok(boolean value,String why){
    checks++;
    if(!value)throw new AssertionError("P142_"+why);
  }
  private static ProcessBuilder make(String... argv){
    ProcessBuilder b=new ProcessBuilder(argv);
    b.directory(new File("/"));
    return b;
  }
  private static void mustDeny(ProcessBuilder b,int mode,String error){
    try{
      if(mode==1)P142OriginalEngineSpawnSeam.probeOrDeny(b);
      if(mode==2)P142OriginalEngineSpawnSeam.configOrDeny(b);
      if(mode==3)P142OriginalEngineSpawnSeam.primaryOrDeny(b);
      throw new AssertionError("P142_SPAWN_UNEXPECTEDLY_ALLOWED");
    }catch(IOException expected){
      ok(error.equals(expected.getMessage()),"EXPECTED_ERROR_"+mode+"_"+expected.getMessage());
    }
  }
  private static final String NODE="/host/prefix/bin/node";
  private static final String JS="/host/engine/node_modules/@deepseek-ai/dsh/lib/bin.js";
  public static void main(String[] arg)throws Exception {
    ProcessBuilder probe=make(NODE,JS,"--profile","web","--patch",
                               "/host/patch.yml","--port","0","--no-open");
    probe.redirectErrorStream(true);
    mustDeny(probe,1,"P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK");
    mustDeny(probe,3,"P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK");
    ProcessBuilder primary=make(NODE,JS,"--profile","rescue","--no-open");
    primary.redirectErrorStream(true);
    mustDeny(primary,3,"P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK");
    mustDeny(primary,1,"P142_PROBE_EPHEMERAL_PORT_REQUIRED");
    ProcessBuilder cfg=make(NODE,JS,"--profile","web","--dump-config");
    mustDeny(cfg,2,"P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK");
    cfg.redirectErrorStream(true);
    mustDeny(cfg,2,"P142_ORIGINAL_LAUNCH_SHAPE_DRIFT");
    cfg.redirectErrorStream(false);
    cfg.command().set(4,"--no-open");
    mustDeny(cfg,2,"P142_CONFIG_PROBE_SHAPE_DRIFT");
    cfg.command().set(4,"--dump-config");
    cfg.command().set(0,"/system/bin/sh");
    mustDeny(cfg,2,"P142_ORIGINAL_LAUNCH_SHAPE_DRIFT");
    ProcessBuilder fake=make(NODE,JS,"--profile","web","--patch",
                              "/bad.yml","--port","3030","--no-open");
    fake.redirectErrorStream(true);
    mustDeny(fake,3,"P142_MAIN_DYNAMIC_PORT_SHAPE_DRIFT");
    fake.command().set(7,"0");
    fake.command().set(4,"--eval");
    mustDeny(fake,3,"P142_MAIN_DYNAMIC_PORT_SHAPE_DRIFT");
    fake.command().set(4,"--patch");
    fake.command().set(8,"--eval");
    mustDeny(fake,3,"P142_UNKNOWN_ORIGINAL_ENGINE_ARGUMENT");
    ProcessBuilder injected=make(NODE,JS,"--profile","web","--patch",
                                 "../relative", "--no-open");
    injected.redirectErrorStream(true);
    mustDeny(injected,3,"P142_PATCH_PATH_SHAPE_DRIFT");
    // P173: original EngineManager uses inherited *pipe* handles only.
    // File/INHERIT redirects could read or overwrite a private host file
    // if later handed to a production Broker. Setting these Redirects
    // doesn't spawn a process, open or create a file.
    ProcessBuilder probeInput=make(NODE,JS,"--profile","web",
        "--port","0","--no-open");
    probeInput.redirectErrorStream(true);
    probeInput.redirectInput(ProcessBuilder.Redirect.INHERIT);
    mustDeny(probeInput,1,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder probeOutput=make(NODE,JS,"--profile","web",
        "--port","0","--no-open");
    probeOutput.redirectErrorStream(true);
    probeOutput.redirectOutput(ProcessBuilder.Redirect.to(new File("/p173-disallowed-out")));
    mustDeny(probeOutput,1,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder configError=make(NODE,JS,"--profile","web","--dump-config");
    configError.redirectError(ProcessBuilder.Redirect.to(new File("/p173-disallowed-err")));
    mustDeny(configError,2,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder configInput=make(NODE,JS,"--profile","web","--dump-config");
    configInput.redirectInput(ProcessBuilder.Redirect.from(new File("/p173-disallowed-in")));
    mustDeny(configInput,2,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder mainOutput=make(NODE,JS,"--profile","rescue","--no-open");
    mainOutput.redirectErrorStream(true);
    mainOutput.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    mustDeny(mainOutput,3,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder mainError=make(NODE,JS,"--profile","web","--no-open");
    mainError.redirectErrorStream(true);
    mainError.redirectError(ProcessBuilder.Redirect.to(new File("/p173-disallowed-merged-err")));
    mustDeny(mainError,3,"P142_UNSAFE_ORIGINAL_STDIO_REDIRECT");
    ProcessBuilder defaultPipes=make(NODE,JS,"--profile","web","--dump-config");
    ok(defaultPipes.redirectInput()==ProcessBuilder.Redirect.PIPE &&
       defaultPipes.redirectOutput()==ProcessBuilder.Redirect.PIPE &&
       defaultPipes.redirectError()==ProcessBuilder.Redirect.PIPE,
       "original_config_uses_unredirected_pipes");
    mustDeny(defaultPipes,2,"P142_ISOLATED_PRODUCTION_BROKER_UNAVAILABLE_NO_HOST_FALLBACK");
    System.out.println("P173_THREE_ORIGINAL_ENGINEMANAGER_STDIO_PIPE_SHAPES=PASS");
    System.out.println("P173_NO_HOST_REDIRECT_FILE_OPEN_OR_SPAWN=YES");
    ProcessBuilder empty=new ProcessBuilder("/bin/false");
    mustDeny(empty,1,"P142_MISSING_ORIGINAL_BUILDER");
    ProcessBuilder unset=make(NODE,JS,"--profile","web","--no-open");
    mustDeny(unset,3,"P142_ORIGINAL_LAUNCH_SHAPE_DRIFT");
    System.out.println("P142_ORIGINAL_THREE_START_SITES_JAVA_DENY=PASS assertions="+checks);
    System.out.println("P142_NO_HOST_PROCESSBUILDER_START=PASS");
    System.out.println("P142_VALID_PRODUCTION_REQUEST_WILL_BE_DENIED=YES");
    System.out.println("P142_PRODUCTION_FD_AND_BINDER_BROKER=NOT_WIRED");
    System.out.println("P142_V139_FIXED_SIGNED_APK=BLOCKED");
  }
}
