package com.dsh.android.engine;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.security.*;import java.util.*;import java.util.concurrent.*;
/** Full original runCli, real HTTP/RPC/WebSocket and durable owner storage.
 * HOST ONLY: ARM64 dlopen is explicitly spied to host internal loader objects.
 * Never an Android native, EngineManager coroutine, model or READY attestation. */
public final class OriginalMainHostControlTest {
 static int checks;static void yes(boolean v,String code){checks++;if(!v)throw new AssertionError(code);}
 static String digest(byte[] data,String algorithm)throws Exception{StringBuilder s=new StringBuilder();for(byte b:MessageDigest.getInstance(algorithm).digest(data))s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
 static String line(InputStream in)throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();int c;while((c=in.read())!=-1&&c!='\n'){if(b.size()>=8192)throw new IOException("CONTROL_LINE_BOUND");if(c!='\r')b.write(c);}if(c==-1&&b.size()==0)return null;return b.toString("UTF-8");}
 static byte[] read(InputStream in,int max)throws Exception{try(InputStream owned=in){ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] block=new byte[4096];int n;while((n=owned.read(block))!=-1){if(n>max-bytes.size())throw new IOException("CONTROL_RESPONSE_BOUND");bytes.write(block,0,n);}return bytes.toByteArray();}}
 static final class Reply{int status;String cookie;byte[] body;}
 static Reply request(int port,String target,String cookie,String json)throws Exception{
  HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:"+port+target).openConnection();c.setInstanceFollowRedirects(false);c.setConnectTimeout(5000);c.setReadTimeout(8000);if(cookie!=null)c.setRequestProperty("Cookie",cookie);
  try{if(json!=null){c.setRequestMethod("POST");c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");try(OutputStream out=c.getOutputStream()){out.write(json.getBytes(StandardCharsets.UTF_8));}}
   Reply r=new Reply();r.status=c.getResponseCode();r.cookie=c.getHeaderField("Set-Cookie");InputStream body=r.status>=400?c.getErrorStream():c.getInputStream();r.body=body==null?new byte[0]:read(body,2*1024*1024);return r;
  }finally{c.disconnect();}
 }
 static final class Activation implements AutoCloseable{
  final HttpProcessTransport process;final Process actual;final BlockingQueue<String> logs=new ArrayBlockingQueue<>(96);String target,cookie;int port;
  Activation(String[] args,Path root,int wanted)throws Exception{
   Path executable=Paths.get(args[3],"libdshnode_p21_exec.so"),nativeFile=Paths.get(args[3],"libdsh_original_require_builtin.so");
   ProcessBuilder builder=new ProcessBuilder(args[0],"--expose-internals","--no-warnings","--permission","--allow-fs-read="+args[1],"--allow-fs-read="+nativeFile,"--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home",args[1],executable.toString());
   builder.directory(new File("/"));builder.environment().clear();builder.environment().put("HOME","/dsh-home");builder.environment().put("DSH_HOME","/dsh-home");
   actual=builder.start();HttpProcessTransport owned=null;
   try{
    try(InputStream resource=Files.newInputStream(Paths.get(args[2]))){byte[] block=new byte[65536];int n;while((n=resource.read(block))!=-1)actual.getOutputStream().write(block,0,n);actual.getOutputStream().flush();}
    owned=new HttpProcessTransport(actual,ProfileSnapshotWireTest.OWNER,System.nanoTime(),wanted,false,new DurableSessionSnapshot(root,ProfileSnapshotWireTest.OWNER));process=owned;
    Thread output=new Thread(()->{try{String row;while((row=line(process.getInputStream()))!=null){if(!logs.offer(row))throw new IOException("CONTROL_LOG_BOUND");}}catch(Exception error){logs.offer("CONTROL_LOG_FAILURE");}});output.setDaemon(true);output.start();
    ProfileSnapshotWireTest.drain(process.getErrorStream());
    yes(process.awaitListening(15,TimeUnit.SECONDS),"actual_original_main_listener_"+process.failure());port=process.port();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);boolean returned=false;
    while(target==null||!returned){long remaining=deadline-System.nanoTime();if(remaining<=0)throw new AssertionError("original_main_boot_output_deadline");String row=logs.poll(remaining,TimeUnit.NANOSECONDS);if(row==null||row.equals("CONTROL_LOG_FAILURE"))throw new AssertionError("original_main_boot_output_missing");
     if(row.startsWith("dsh web: http://127.0.0.1:")){URL url=new URL(row.substring(9));yes(url.getPort()==port&&url.getHost().equals("127.0.0.1"),"original_url_matches_owned_actual_listener");target=url.getFile();}
     if(row.equals("ORIGINAL_MAIN_ENTRY_RETURNED_NOT_READY_ATTESTATION"))returned=true;
    }
   }catch(Exception|AssertionError failure){if(owned!=null)owned.close();else actual.destroyForcibly();throw failure;}
  }
  void login()throws Exception{Reply login=request(port,target,null,null);yes(login.status==303,"original_main_real_launch_token_exchange");yes(login.cookie!=null&&login.cookie.contains("HttpOnly")&&login.cookie.contains("SameSite=Strict"),"original_main_cookie_flags");cookie=login.cookie.split(";")[0];}
  public void close()throws Exception{process.destroy();yes(process.waitFor(8,TimeUnit.SECONDS),"original_main_actual_shutdown_deadline");yes(process.exitValue()==0,"original_main_actual_shutdown_exit0");process.close();yes(process.awaitClosed(5,TimeUnit.SECONDS),"original_main_owner_disposed");yes(process.failure().equals("NONE/NONE"),"original_main_transport_clean_"+process.failure());}
 }
 static void sendWs(OutputStream out,int opcode,byte[] data)throws Exception{
  if(data.length>65535)throw new IOException("CONTROL_WS_BOUND");byte[] mask=new byte[4];new SecureRandom().nextBytes(mask);out.write(0x80|opcode);if(data.length<126)out.write(0x80|data.length);else{out.write(0xfe);out.write(data.length>>>8);out.write(data.length&255);}out.write(mask);for(int i=0;i<data.length;i++)out.write(data[i]^mask[i%4]);out.flush();
 }
 static void workspaceStream(Activation a)throws Exception{
  try(Socket socket=new Socket("127.0.0.1",a.port)){
   socket.setSoTimeout(8000);OutputStream out=socket.getOutputStream();InputStream in=socket.getInputStream();String key=Base64.getEncoder().encodeToString(new byte[16]);
   out.write(("GET /api/remote.mux HTTP/1.1\r\nHost: 127.0.0.1:"+a.port+"\r\nOrigin: http://127.0.0.1:"+a.port+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\nCookie: "+a.cookie+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.flush();
   yes("HTTP/1.1 101 Switching Protocols".equals(line(in)),"actual_original_websocket_upgrade");Map<String,String> headers=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);String row;while(!(row=line(in)).isEmpty()){int colon=row.indexOf(':');if(colon>0)headers.put(row.substring(0,colon),row.substring(colon+1).trim());}
   String expected=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));yes(expected.equals(headers.get("Sec-WebSocket-Accept")),"original_ws_accept_proof");
   sendWs(out,1,"{\"type\":\"open\",\"streamId\":\"one\",\"endpoint\":\"workspace/follow\",\"payload\":{\"args\":{}}}".getBytes(StandardCharsets.UTF_8));
   for(int frames=0;frames<5;frames++){
    DataInputStream data=new DataInputStream(in);int flags=data.readUnsignedByte(),length=data.readUnsignedByte();yes((flags&0x80)!=0&&(length&0x80)==0,"bounded_unmasked_complete_server_frame");int size=length&127;if(size==126)size=data.readUnsignedShort();else if(size==127)throw new AssertionError("control_ws_large_frame");byte[] bytes=new byte[size];data.readFully(bytes);
    if((flags&15)==9){sendWs(out,10,bytes);continue;}yes((flags&15)==1,"original_workspace_stream_text");String message=new String(bytes,StandardCharsets.UTF_8);
    yes(message.contains("\"type\":\"item\"")&&message.contains("\"type\":\"baseline\"")&&message.contains("/dsh-workspace"),"real_original_workspace_stream_baseline");
    sendWs(out,1,"{\"type\":\"cancel\",\"streamId\":\"one\"}".getBytes(StandardCharsets.UTF_8));return;
   }throw new AssertionError("original_workspace_stream_no_baseline");
  }
 }
 public static void main(String[] args)throws Exception{
  Path root=ProfileSnapshotWireTest.root();String oldCookie=null,oldToken=null;int port=0;
  try{
   for(int generation=0;generation<2;generation++)try(Activation a=new Activation(args,root,port)){
    port=a.port;yes(request(port,"/",null,null).status==401,"original_main_unauth_frontend_denied");
    if(generation==1){yes(request(port,"/",oldCookie,null).status==401,"main_restart_old_cookie_revoked");yes(request(port,oldToken,null,null).status==401,"main_restart_old_launch_token_revoked");}
    a.login();Reply frontend=request(port,"/",a.cookie,null);yes(frontend.status==200,"original_main_authenticated_frontend");
    java.util.regex.Matcher script=java.util.regex.Pattern.compile("src=\"([.]/assets/[^\"]+[.]js)\"").matcher(new String(frontend.body,StandardCharsets.UTF_8));yes(script.find(),"actual_main_frontend_asset");String asset=script.group(1).substring(1);Reply js=request(port,asset,null,null);
    yes(js.status==200&&MessageDigest.isEqual(js.body,Files.readAllBytes(Paths.get(args[4],"node_modules/@deepseek-ai/dsh-web-frontend/dist"+asset))),"actual_main_original_sealed_frontend_js_bytes");
    String json="{\"type\":\"client-request\",\"rpcId\":\"control\",\"method\":\"workspace/create\",\"payload\":{\"args\":{\"request\":{\"path\":\"/dsh-workspace\"}}}}";
    Reply rpc=request(port,"/api/workspace/create",a.cookie,json);String value=new String(rpc.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
    yes(rpc.status==200&&value.contains("\"ok\":true")&&value.contains("\"created\":"+(generation==0))&&value.contains("/dsh-workspace"),"original_workspace_rpc_create_and_durable_restart");
    workspaceStream(a);oldCookie=a.cookie;oldToken=a.target;
   }
   System.out.println("FULL_ORIGINAL_MAIN_HTTP_AUTH_FRONTEND_WORKSPACE_RPC_WS_AND_RESTART=PASS_HOST_INTERNALS_CONTROL checks="+checks);
   System.out.println("ORIGINAL_ARM64_BINDING_ANDROID_ENGINE_COROUTINE_MODEL_AND_READY=NOT_ATTESTED");
  }finally{ProfileSnapshotWireTest.clean(root);}
 }
}
