package com.dsh.android.engine;
import static com.dsh.android.engine.OriginalMainHttpChecks.*;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.security.*;import java.util.*;import java.util.concurrent.*;
/** Full original runCli, real HTTP/RPC/WebSocket and durable owner storage.
 * HOST ONLY: ARM64 dlopen is explicitly spied to host internal loader objects.
 * Never an Android native, EngineManager coroutine, model or READY attestation. */
public final class OriginalMainHostControlTest {
 static int checks;static void yes(boolean v,String code){checks++;if(!v)throw new AssertionError(code);}
 static void deniedReady(Process owner,String url)throws IOException{
  try{OriginalMainStartup.requireVerifiedReady(owner,url);throw new AssertionError("unverified_ready_accepted");}
  catch(IOException expected){yes("MAIN_READY_PROOF_REQUIRED".equals(expected.getMessage()),"ready_denial_is_private");}
 }
 static final class Activation implements AutoCloseable{
  final HttpProcessTransport process;final Process actual;final OriginalMainStartup startup;String cookie;int port;
  Activation(String[] args,Path root,int wanted)throws Exception{
   Path executable=Paths.get(args[3],"libdshnode_p21_exec.so"),nativeFile=Paths.get(args[3],"libdsh_original_require_builtin.so");
   ProcessBuilder builder=new ProcessBuilder(args[0],"--expose-internals","--no-warnings","--permission","--allow-fs-read="+args[1],"--allow-fs-read="+nativeFile,"--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home",args[1],executable.toString());
   builder.directory(new File("/"));builder.environment().clear();builder.environment().put("HOME","/dsh-home");builder.environment().put("DSH_HOME","/dsh-home");
   actual=builder.start();HttpProcessTransport owned=null;
   try{
    try(InputStream resource=Files.newInputStream(Paths.get(args[2]))){byte[] block=new byte[65536];int n;while((n=resource.read(block))!=-1)actual.getOutputStream().write(block,0,n);actual.getOutputStream().flush();}
    owned=new HttpProcessTransport(actual,ProfileSnapshotWireTest.OWNER,System.nanoTime(),wanted,true,new DurableSessionSnapshot(root,ProfileSnapshotWireTest.OWNER));process=owned;
    yes(process.getErrorStream().read()==-1,"original_main_engine_merged_stderr_contract");
    startup=OriginalMainStartup.await(process);port=startup.port();
   }catch(Exception|AssertionError failure){if(owned!=null)owned.close();else actual.destroyForcibly();throw failure;}
  }
  void login()throws Exception{
   CookieHandler previous=CookieHandler.getDefault();
   CookieHandler.setDefault(new CookieHandler(){
    @Override public Map<String,List<String>> get(URI uri,Map<String,List<String>> headers){throw new AssertionError("startup_read_shared_cookie_jar");}
    @Override public void put(URI uri,Map<String,List<String>> headers){throw new AssertionError("startup_write_shared_cookie_jar");}
   });
   try{cookie=startup.verifyForReady();}
   finally{CookieHandler.setDefault(previous);}
  }
  public void close()throws Exception{process.destroy();deniedReady(process,startup.privateUrl());yes(process.waitFor(8,TimeUnit.SECONDS),"original_main_actual_shutdown_deadline");yes(process.exitValue()==0,"original_main_actual_shutdown_exit0");process.close();yes(process.awaitClosed(5,TimeUnit.SECONDS),"original_main_owner_disposed");yes(process.failure().equals("NONE/NONE"),"original_main_transport_clean_"+process.failure());}
 }
 public static void main(String[] args)throws Exception{
  String shape="/?token="+String.join("",Collections.nCopies(43,"a"));
  String url="dsh web: http://127.0.0.1:34567";
  yes(shape.equals(OriginalMainStartup.launchTarget(url+shape,34567)),"exact_original_startup_url");
  for(String wrong:Arrays.asList(url+shape+"&token=b",url+shape+"#fragment",url+shape+"\r\n",
      "dsh web: http://localhost:34567"+shape,"dsh web: http://127.0.0.1:34568"+shape,
      "dsh web: http://guest@127.0.0.1:34567"+shape,"dsh web: https://127.0.0.1:34567"+shape)){
   try{OriginalMainStartup.launchTarget(wrong,34567);throw new AssertionError("invalid_startup_url_accepted");}
   catch(IOException expected){yes("MAIN_PRIVATE_URL".equals(expected.getMessage()),"invalid_startup_url_redacted");}
  }
  Path root=ProfileSnapshotWireTest.root();String oldCookie=null,oldToken=null,oldUrl=null;int port=0;
  try{
   for(int generation=0;generation<2;generation++)try(Activation a=new Activation(args,root,port)){
    port=a.port;yes(request(port,"/",null,null).status==401,"original_main_unauth_frontend_denied");
    if(generation==1)a.startup.verifyRetiredCredentials(oldToken,oldCookie);
    String ownUrl=a.startup.privateUrl(),announcement="dsh web: "+ownUrl;
    deniedReady(a.process,ownUrl);
    yes(!OriginalMainStartup.permitsVerifiedAnnouncement(a.process,announcement),"stdout_before_http_proof_not_ready");
    yes(a.process.getInputStream().read()==-1,"raw_startup_line_not_exposed_before_proof");
    a.login();OriginalMainStartup.requireVerifiedReady(a.process,ownUrl);
    yes(OriginalMainStartup.permitsVerifiedAnnouncement(a.process,announcement),"verified_http_announcement_accepted");
    InputStream admitted=a.process.getInputStream();
    yes(announcement.equals(line(admitted)),"exact_verified_original_stdout_released_after_proof");
    ProfileSnapshotWireTest.drain(admitted);
    try{a.startup.verifyForReady();throw new AssertionError("ready_proof_reissued");}
    catch(IOException expected){yes("MAIN_READY_PROOF_ALREADY_ATTEMPTED".equals(expected.getMessage()),"ready_proof_issued_once");}
    deniedReady(a.actual,ownUrl);deniedReady(a.process,ownUrl+"#wrong");
    yes(!OriginalMainStartup.permitsVerifiedAnnouncement(a.process,"preamble "+announcement),"embedded_announcement_denied");
    if(oldUrl!=null)deniedReady(a.process,oldUrl);
    Reply frontend=request(port,"/",a.cookie,null);yes(frontend.status==200,"original_main_authenticated_frontend");
    java.util.regex.Matcher script=java.util.regex.Pattern.compile("src=\"([.]/assets/[^\"]+[.]js)\"").matcher(new String(frontend.body,StandardCharsets.UTF_8));yes(script.find(),"actual_main_frontend_asset");String asset=script.group(1).substring(1);Reply js=request(port,asset,null,null);
    yes(js.status==200&&MessageDigest.isEqual(js.body,Files.readAllBytes(Paths.get(args[4],"node_modules/@deepseek-ai/dsh-web-frontend/dist"+asset))),"actual_main_original_sealed_frontend_js_bytes");
    String json="{\"type\":\"client-request\",\"rpcId\":\"control\",\"method\":\"workspace/create\",\"payload\":{\"args\":{\"request\":{\"path\":\"/dsh-workspace\"}}}}";
    Reply rpc=request(port,"/api/workspace/create",a.cookie,json);String value=new String(rpc.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
    yes(rpc.status==200&&value.contains("\"ok\":true")&&value.contains("\"created\":"+(generation==0))&&value.contains("/dsh-workspace"),"original_workspace_rpc_create_and_durable_restart");
    workspaceStream(a.port,a.cookie);hostFence(a.port,a.cookie);oldCookie=a.cookie;oldToken=a.startup.privateTarget();oldUrl=ownUrl;
   }
   System.out.println("FULL_ORIGINAL_MAIN_HTTP_AUTH_FRONTEND_WORKSPACE_RPC_WS_AND_RESTART=PASS_HOST_INTERNALS_CONTROL checks="+checks);
   System.out.println("ORIGINAL_MAIN_PRIVATE_STARTUP_AND_COOKIE_JAR_ISOLATION=PASS_HOST");
   System.out.println("ORIGINAL_MAIN_OWNED_READY_PROOF_FOREIGN_CHANGED_RETIRED_AND_STOPPED=PASS_HOST");
   System.out.println("ORIGINAL_ARM64_BINDING_ANDROID_ENGINE_COROUTINE_MODEL_AND_READY=NOT_ATTESTED");
  }finally{ProfileSnapshotWireTest.clean(root);}
 }
}
