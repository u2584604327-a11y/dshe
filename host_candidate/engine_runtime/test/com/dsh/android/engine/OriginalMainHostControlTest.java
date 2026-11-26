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
 // Fixed, non-secret lines extracted from the signed workspace patch generator.
 private static final String WORKSPACE_PREFIX = String.join("\n",
  "# 由 DSH Android 客户端生成，请勿手改（每次启动会整体覆盖）。",
  "# Android 落不进引擎的平台分支（只认 darwin/win32/linux），",
  "# 必须显式给 documentsDirectory，否则首次使用建不出默认工作区。",
  "# 详见 EngineManager.writeWorkspacePatch() 的注释。",
  "- id: workspace-controller", "  name: '@deepseek-ai/dsh-api-workspace-controller'", "  config:", "");
 private static final String BROWSER_PREFIX = String.join("\n",
  "# 由 DSH Android 客户端生成，请勿手改（每次启动会整体覆盖）。",
  "# 挂载右侧栏「AI 浏览器」入口插件；插件包随 APK 分发，已解到 .dsh/browser-pane。",
  "- insert:", "    - id: dsh-android-browser-pane", "      name: 'file://");
 private static final String MOBILE_PREFIX = String.join("\n",
  "# 由 DSH Android 客户端生成，请勿手改（每次启动会整体覆盖）。",
  "# 挂载移动端 UI 适配插件；插件包随 APK 分发，已解到 .dsh/mobile-ui。",
  "# 用 file:// 绝对路径挂载：包刻意放在 profile 的 node_modules 之外，",
  "# 否则用户每次用插件管理器装东西都会被 pnpm 挪进 .ignored/。",
  "- insert:", "    - id: dsh-android-mobile", "      name: 'file://");
 static OriginalWebLaunch launch(Integer port,boolean checkDrift,OriginalClientPlugin mobile,
     OriginalClientPlugin browser)throws IOException{
  File node=new File("/private/termux/usr/bin/node"),entry=new File("/private/engine/"+OriginalWebLaunch.ENTRY);
  File workspace=new File("/private/workspace"),patch=new File("/private/home/.dsh/workspace.patch.yml");
  File mobilePatch=new File(patch.getParentFile(),mobile.kind.patch);
  String mobileEntry=new File(patch.getParentFile(),mobile.kind.entry).getPath();
  byte[] mobileSource=(MOBILE_PREFIX+mobileEntry+"'\n").getBytes(StandardCharsets.UTF_8);
  File browserPatch=new File(patch.getParentFile(),browser.kind.patch);
  String browserEntry=new File(patch.getParentFile(),browser.kind.entry).getPath();
  byte[] browserSource=(BROWSER_PREFIX+browserEntry+"'\n").getBytes(StandardCharsets.UTF_8);
  List<String> argv=new ArrayList<>(Arrays.asList(node.getPath(),entry.getPath(),"--profile","web",
      "--patch",mobilePatch.getPath(),"--patch",browserPatch.getPath(),"--patch",patch.getPath()));
  if(port!=null)argv.addAll(Arrays.asList("--port",port.toString()));argv.add("--no-open");
  byte[] original=(WORKSPACE_PREFIX+"    documentsDirectory: '/private/workspace'\n").getBytes(StandardCharsets.UTF_8);
  ProcessBuilder builder=new ProcessBuilder(argv).directory(workspace).redirectErrorStream(true);
  OriginalWebLaunch launch=OriginalWebLaunch.capture(builder,node,entry,workspace,patch,original,mobilePatch,mobileSource,mobile,browserPatch,browserSource,browser);
  if(checkDrift){
   launch.requireSame(builder);
   byte[] tampered=original.clone();tampered[4]^=1;
   try{OriginalWebLaunch.capture(builder,node,entry,workspace,patch,tampered,mobilePatch,mobileSource,mobile,browserPatch,browserSource,browser);throw new AssertionError("workspace_patch_tamper_accepted");}
   catch(IOException denied){yes("MAIN_WORKSPACE_PATCH_SOURCE".equals(denied.getMessage()),"workspace_patch_tamper_denied");}
   byte[] foreign=(WORKSPACE_PREFIX+"    documentsDirectory: '/foreign/workspace'\n").getBytes(StandardCharsets.UTF_8);
   try{OriginalWebLaunch.capture(builder,node,entry,workspace,patch,foreign,mobilePatch,mobileSource,mobile,browserPatch,browserSource,browser);throw new AssertionError("workspace_owner_tamper_accepted");}
   catch(IOException denied){yes("MAIN_WORKSPACE_PATCH_OWNER".equals(denied.getMessage()),"workspace_owner_tamper_denied");}
   byte[] foreignBrowser=(BROWSER_PREFIX+"/foreign/lib/index.js'\n").getBytes(StandardCharsets.UTF_8);
   try{OriginalWebLaunch.capture(builder,node,entry,workspace,patch,original,mobilePatch,mobileSource,mobile,browserPatch,foreignBrowser,browser);throw new AssertionError("browser_owner_tamper_accepted");}
   catch(IOException denied){yes("MAIN_BROWSER_PATCH_OWNER".equals(denied.getMessage()),"browser_owner_tamper_denied");}
   byte[] foreignMobile=(MOBILE_PREFIX+"/foreign/lib/index.js'\n").getBytes(StandardCharsets.UTF_8);
   try{OriginalWebLaunch.capture(builder,node,entry,workspace,patch,original,mobilePatch,foreignMobile,mobile,browserPatch,browserSource,browser);throw new AssertionError("mobile_owner_tamper_accepted");}
   catch(IOException denied){yes("MAIN_MOBILE_PATCH_OWNER".equals(denied.getMessage()),"mobile_owner_tamper_denied");}
   builder.environment().put("TEST_DRIFT","1");
   try{launch.requireSame(builder);throw new AssertionError("environment_drift_accepted");}
   catch(IOException denied){yes("MAIN_LAUNCH_CHANGED".equals(denied.getMessage()),"environment_drift_denied");}
  }
  return launch;
 }
 static final class Activation implements AutoCloseable{
  final HttpProcessTransport process;final Process actual;final OriginalMainStartup startup;String cookie;int port;
  Activation(String[] args,Path root,OriginalWebLaunch launch)throws Exception{
   Path executable=Paths.get(args[3],"libdshnode_p21_exec.so"),nativeFile=Paths.get(args[3],"libdsh_original_require_builtin.so");
   ProcessBuilder builder=new ProcessBuilder(args[0],"--expose-internals","--no-warnings","--permission","--allow-fs-read="+args[1],"--allow-fs-read="+nativeFile,"--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home",args[1],executable.toString());
   builder.directory(new File("/"));builder.environment().clear();builder.environment().put("HOME","/dsh-home");builder.environment().put("DSH_HOME","/dsh-home");
   actual=builder.start();HttpProcessTransport owned=null;
   try{
    try(InputStream resource=Files.newInputStream(Paths.get(args[2]))){byte[] block=new byte[65536];int n;while((n=resource.read(block))!=-1)actual.getOutputStream().write(block,0,n);actual.getOutputStream().flush();}
    owned=HttpProcessTransport.forOriginalWebLaunch(actual,ProfileSnapshotWireTest.OWNER,System.nanoTime(),launch,new DurableSessionSnapshot(root,ProfileSnapshotWireTest.OWNER));process=owned;
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
 private static OriginalClientPlugin readPlugin(OriginalClientPlugin.Kind kind,String filename)throws IOException{
  byte[] archive=Files.readAllBytes(Paths.get(filename));
  OriginalClientPlugin plugin=OriginalClientPlugin.read(kind,new ByteArrayInputStream(archive));
  archive[0]^=1;
  try{OriginalClientPlugin.read(kind,new ByteArrayInputStream(archive));throw new AssertionError("archive_tamper_accepted_"+kind);}
  catch(IOException denied){yes(kind.failure("ARCHIVE_SEAL").equals(denied.getMessage()),"archive_tamper_denied_"+kind);}
  return plugin;
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
  Integer originalOption=HttpProcessTransport.originalWebPortOption();
  yes(originalOption==null||originalOption==0,"original_android_port_plan");
  Path root=ProfileSnapshotWireTest.root();String oldCookie=null,oldToken=null,oldUrl=null;int port=0;
  try{
   OriginalClientPlugin browser=readPlugin(OriginalClientPlugin.Kind.BROWSER,args[5]);
   OriginalClientPlugin mobile=readPlugin(OriginalClientPlugin.Kind.MOBILE,args[6]);
   for(int generation=0;generation<2;generation++)try(Activation a=new Activation(args,root,
       launch(generation==0?originalOption:Integer.valueOf(port),generation==0,mobile,browser))){
    port=a.port;yes(request(port,"/",null,null).status==401,"original_main_unauth_frontend_denied");
    if(generation==0&&originalOption==null){
     yes(port==HttpProcessTransport.ORIGINAL_WEB_DEFAULT_PORT,"original_sealed_web_default_port");
     yes(Integer.valueOf(0).equals(HttpProcessTransport.originalWebPortOption()),"busy_original_web_port_asks_kernel");
     System.out.println("ORIGINAL_MAIN_OMITTED_WEB_PORT_AND_BUSY_PORT_SELECTION=PASS_HOST");
    }
    if(generation==0&&originalOption!=null){
     yes(port!=HttpProcessTransport.ORIGINAL_WEB_DEFAULT_PORT,"original_busy_port_uses_owned_ephemeral_listener");
     System.out.println("ORIGINAL_MAIN_BUSY_DEFAULT_EXPLICIT_ZERO=PASS_HOST");
    }
    if(generation==1)a.startup.verifyRetiredCredentials(oldToken,oldCookie);
    String ownUrl=a.startup.privateUrl(),announcement="dsh web: "+ownUrl;
    deniedReady(a.process,ownUrl);
    yes(!OriginalMainStartup.permitsVerifiedAnnouncement(a.process,announcement),"stdout_before_http_proof_not_ready");
    yes(a.process.getInputStream().read()==-1,"raw_startup_line_not_exposed_before_proof");
    a.login();OriginalMainStartup.requireVerifiedReady(a.process,ownUrl);
    Reply status=request(port,"/api/dsh-android/privileged",a.cookie,"{}");
    yes(status.status==403&&status.body.length==0,"isolated_mobile_privilege_post_denied");
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
    verifyDefaultWorkspace(port,a.cookie);
    String json="{\"type\":\"client-request\",\"rpcId\":\"control\",\"method\":\"workspace/create\",\"payload\":{\"args\":{\"request\":{\"path\":\"/dsh-workspace\"}}}}";
    Reply rpc=request(port,"/api/workspace/create",a.cookie,json);String value=new String(rpc.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
    yes(rpc.status==200&&value.contains("\"ok\":true")&&value.contains("\"created\":"+(generation==0))&&value.contains("/dsh-workspace"),"original_workspace_rpc_create_and_durable_restart");
    workspaceStream(a.port,a.cookie);hostFence(a.port,a.cookie);oldCookie=a.cookie;oldToken=a.startup.privateTarget();oldUrl=ownUrl;
   }
   System.out.println("FULL_ORIGINAL_MAIN_HTTP_AUTH_FRONTEND_WORKSPACE_RPC_WS_AND_RESTART=PASS_HOST_INTERNALS_CONTROL checks="+checks);
   System.out.println("ORIGINAL_MAIN_PRIVATE_STARTUP_AND_COOKIE_JAR_ISOLATION=PASS_HOST");
   System.out.println("ORIGINAL_MAIN_WORKSPACE_OVERLAY_SOURCE_OWNER_AND_DEFAULT_RPC=PASS_HOST");
   System.out.println("ORIGINAL_MAIN_BROWSER_AND_MOBILE_SIGNED_CLIENTS_AND_PRIVILEGE_FENCE=PASS_HOST");
   System.out.println("ORIGINAL_MAIN_OWNED_READY_PROOF_FOREIGN_CHANGED_RETIRED_AND_STOPPED=PASS_HOST");
   System.out.println("ORIGINAL_ARM64_BINDING_ANDROID_ENGINE_COROUTINE_MODEL_AND_READY=NOT_ATTESTED");
  }finally{ProfileSnapshotWireTest.clean(root);}
 }
}
