package com.dsh.android.engine;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

/** Host integration only. Real original HTTP/auth/frontend modules and real
 * TCP/OS pipes, without granting the Node child native network permission.
 * This is not Android, full EngineManager, full profile or model chat proof. */
public final class HttpProcessTransportTest {
  private static String node,fixture,reference,transport,home;
  private static int checks;
  private static String renderedSha;
  private static void yes(boolean v,String label){checks++;if(!v)throw new AssertionError(label);}
  private static String sha(byte[] bytes)throws Exception{
    StringBuilder s=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();
  }
  private static final class Response {
    int status;Map<String,String> headers=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);byte[] body;
  }
  private static Response request(int port,String target,String cookie,String host,byte[] data)throws Exception{
    try(Socket socket=new Socket("127.0.0.1",port)){
      socket.setSoTimeout(10000);OutputStream out=socket.getOutputStream();
      String header=(data==null?"GET":"POST")+" "+target+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n"+
          (cookie==null?"":"Cookie: "+cookie+"\r\n")+(data==null?"":"Content-Length: "+data.length+"\r\nContent-Type: application/octet-stream\r\n")+"\r\n";
      // Upload concurrently with response reads: streaming echo would otherwise
      // deadlock when both real TCP buffers/credits are full.
      Thread writer=new Thread(()->{try{out.write(header.getBytes(StandardCharsets.US_ASCII));if(data!=null)out.write(data);out.flush();}catch(IOException ignored){}});
      writer.setDaemon(true);writer.start();Response result=read(socket.getInputStream());writer.join(10000);yes(!writer.isAlive(),"upload_writer_closed");return result;
    }
  }
  private static String line(InputStream input)throws IOException{
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();int value;
    while((value=input.read())!=-1){if(value=='\n')break;if(value!='\r')bytes.write(value);if(bytes.size()>65536)throw new IOException("header_bound");}
    if(value==-1&&bytes.size()==0)throw new EOFException();return bytes.toString("US-ASCII");
  }
  private static byte[] exact(InputStream input,int size)throws IOException{
    byte[] data=new byte[size];new DataInputStream(input).readFully(data);return data;
  }
  private static Response read(InputStream input)throws Exception{
    Response r=new Response();r.status=Integer.parseInt(line(input).split(" ")[1]);String row;
    while(!(row=line(input)).isEmpty()){int at=row.indexOf(':');if(at>0)r.headers.put(row.substring(0,at),row.substring(at+1).trim());}
    ByteArrayOutputStream body=new ByteArrayOutputStream();
    if("chunked".equalsIgnoreCase(r.headers.get("Transfer-Encoding"))){
      for(;;){int size=Integer.parseInt(line(input).split(";")[0],16);if(size==0){while(!line(input).isEmpty()){}break;}body.write(exact(input,size));yes(line(input).isEmpty(),"chunk_delimiter");}
    }else if(r.headers.containsKey("Content-Length"))body.write(exact(input,Integer.parseInt(r.headers.get("Content-Length"))));
    else{byte[] b=new byte[8192];int n;while((n=input.read(b))!=-1){body.write(b,0,n);if(body.size()>32*1024*1024)throw new IOException("response_bound");}}
    r.body=body.toByteArray();return r;
  }
  private static final class Session implements AutoCloseable{
    Process child;HttpProcessTransport process;String tokenTarget,indexSha,cookie;int port;BufferedReader stdout;
    Session(int desired,String policy)throws Exception{this(desired,policy,false);}
    Session(int desired,String policy,boolean merge)throws Exception{
      List<String> args=new ArrayList<>(Arrays.asList(node,"--permission","--allow-fs-read="+fixture,"--allow-fs-read="+reference,
          "--allow-fs-read="+Paths.get(transport).getParent(),"--allow-fs-read="+home,"--allow-fs-write="+home,fixture,reference,transport,home,policy));
      ProcessBuilder builder=new ProcessBuilder(args);builder.environment().clear();builder.environment().put("HOME",home);builder.environment().put("DSH_HOME",home);
      child=builder.start();process=new HttpProcessTransport(child,sha(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)),System.nanoTime(),desired,merge);
      threadDrain(process.getErrorStream());
      yes(process.awaitListening(15,TimeUnit.SECONDS),"original_webserver_listening_"+process.failure());port=process.port();
      stdout=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8));
      int observed=0;for(int i=0;i<(merge?4:2);i++){
        String row=stdout.readLine();yes(row!=null,"original_boot_output");
        if(row.equals("ORIGINAL_HTTP_FIXTURE_STDERR")||row.equals("ORIGINAL_HTTP_NATIVE_STDERR"))observed++;
        if(row.startsWith("DSH_INDEX_SHA="))indexSha=row.substring(14);
        if(row.startsWith("DSH_WEB_URL="))tokenTarget=new URL(row.substring(12)).getFile();
      }
      yes(tokenTarget!=null&&indexSha!=null,"actual_original_token_and_frontend_digest");
      if(merge)yes(observed==2&&process.getErrorStream().read()==-1,"merged_framed_and_native_stderr");
      // Never print the URL, token, cookie, credentials or HTTP payload.
    }
    String authority(){return "127.0.0.1:"+port;}
    Response get(String target,String value)throws Exception{return request(port,target,value,authority(),null);}
    void login()throws Exception{
      Response reply=get(tokenTarget,null);yes(reply.status==303,"original_token_exchange");
      String set=reply.headers.get("Set-Cookie");yes(set!=null&&set.contains("HttpOnly")&&set.contains("SameSite=Strict"),"original_cookie_flags");cookie=set.split(";")[0];
    }
    public void close()throws Exception{
      process.destroy();yes(process.waitFor(8,TimeUnit.SECONDS),"graceful_exit_deadline");yes(process.exitValue()==0,"graceful_exit_code");
      yes(!process.isAlive(),"process_dead");
      try(Socket ignored=new Socket("127.0.0.1",port)){throw new AssertionError("old_listener_live");}catch(ConnectException expected){checks++;}
    }
  }
  private static void threadDrain(InputStream stream){Thread t=new Thread(()->{try{byte[] b=new byte[1024];while(stream.read(b)!=-1){}}catch(IOException ignored){}});t.setDaemon(true);t.start();}
  public static void main(String[] a)throws Exception{
    node=a[0];fixture=a[1];reference=a[2];transport=a[3];home=a[4];
    String oldCookie,oldTarget;int samePort;
    try(Session first=new Session(0,"persistent-baseline")){first.login();oldCookie=first.cookie;samePort=first.port;oldTarget=first.tokenTarget;}
    try(Session baseline=new Session(samePort,"persistent-baseline")){
      yes(baseline.get("/",oldCookie).status==200,"original_persistent_cookie_survives_same_port_restart");
      yes(baseline.get(oldTarget,null).status==401,"original_launch_token_does_not_survive");
    }
    System.out.println("ORIGINAL_BROWSER_COOKIE_SAME_AUTHORITY_RESTART=REPRODUCED_PERSISTENT");
    byte[] originalCredentialFile=Files.readAllBytes(Paths.get(home,".credentials.yaml"));
    try(Session active=new Session(samePort,"generation-scoped",true)){
      yes(active.get("/",oldCookie).status==401,"scoped_old_cookie_rejected");
      yes(active.get("/",null).status==401,"unauthenticated_frontend_rejected");
      yes(active.get("/api/transport-sse",null).status==401,"unauthenticated_api_rejected");
      yes(request(active.port,"/api/transport-sse",null,"evil.invalid",null).status==403,"host_fence_preserved");
      active.login();
      Response frontend=active.get("/",active.cookie);renderedSha=sha(frontend.body);yes(frontend.status==200&&sha(frontend.body).equals(active.indexSha),"actual_original_frontend_bytes");
      String html=new String(frontend.body,StandardCharsets.UTF_8);
      java.util.regex.Matcher script=java.util.regex.Pattern.compile("src=\"([.]/assets/[^\"]+[.]js)\"").matcher(html);
      yes(script.find(),"real_frontend_script");String asset=script.group(1).substring(1);
      Response javascript=active.get(asset,null);
      byte[] originalScript=Files.readAllBytes(Paths.get(reference,"node_modules/@deepseek-ai/dsh-web-frontend/dist"+asset));
      yes(javascript.status==200&&MessageDigest.isEqual(javascript.body,originalScript),"actual_original_frontend_script_bytes");
      byte[] payload=new byte[2*1024*1024];new SecureRandom().nextBytes(payload);
      Response echo;
      try{echo=request(active.port,"/api/transport-echo",active.cookie,active.authority(),payload);}
      catch(Exception failure){throw new AssertionError("stream_failure="+active.process.failure(),failure);}
      yes(echo.status==200&&MessageDigest.isEqual(echo.body,payload),"two_megabyte_bidirectional_stream");
      Response sse=active.get("/api/transport-sse",active.cookie);yes(sse.status==200&&new String(sse.body,StandardCharsets.UTF_8).equals("data: 1\n\ndata: 2\n\ndata: 3\n\ndata: 4\n\ndata: 5\n\ndata: 6\n\n"),"sse_frames_exact");
      byte[] stdin=new byte[96*1024];new SecureRandom().nextBytes(stdin);
      active.process.getOutputStream().write(stdin);active.process.getOutputStream().close();
      yes(active.stdout.readLine().equals("DSH_STDIN_SHA="+sha(stdin)),"application_stdin_and_eof_independent_of_http_ipc");
      try(Socket keep=new Socket("127.0.0.1",active.port)){
        keep.setSoTimeout(10000);OutputStream out=keep.getOutputStream();
        out.write(("GET / HTTP/1.1\r\nHost: "+active.authority()+"\r\nCookie: "+active.cookie+"\r\nConnection: keep-alive\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.flush();
        yes(read(keep.getInputStream()).status==200,"keepalive_first_authorized");
        out.write(("GET /api/transport-sse HTTP/1.1\r\nHost: "+active.authority()+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.flush();
        yes(read(keep.getInputStream()).status==401,"keepalive_next_request_must_reauthenticate");
      }
      try(Socket slow=new Socket()){
        slow.setReceiveBufferSize(1024);slow.connect(new InetSocketAddress("127.0.0.1",active.port));
        java.util.concurrent.CountDownLatch sent=new java.util.concurrent.CountDownLatch(1);
        Thread blocked=new Thread(()->{try{
          OutputStream out=slow.getOutputStream();out.write(("POST /api/transport-echo HTTP/1.1\r\nHost: "+active.authority()+"\r\nCookie: "+active.cookie+"\r\nContent-Length: 16777216\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
          out.write(new byte[65536]);out.flush();sent.countDown();for(int i=0;i<255;i++)out.write(new byte[65536]);out.flush();
        }catch(IOException cancelled){sent.countDown();}});blocked.setDaemon(true);blocked.start();
        yes(sent.await(3,TimeUnit.SECONDS),"slow_connection_started");Thread.sleep(100);
        yes(blocked.isAlive(),"real_tcp_backpressure");
        yes(active.get("/",active.cookie).status==200,"slow_client_does_not_stall_other_connections");
        slow.close();blocked.join(3000);yes(!blocked.isAlive(),"blocked_upload_cancelled");
      }
      oldCookie=active.cookie;oldTarget=active.tokenTarget;
    }
    try(Session restarted=new Session(samePort,"generation-scoped")){
      yes(restarted.get("/",oldCookie).status==401,"new_generation_cookie_rejected");
      yes(restarted.get(oldTarget,null).status==401,"new_generation_launch_token_rejected");restarted.login();
      yes(restarted.get("/",restarted.cookie).status==200,"restart_recoverable");
      restarted.process.getInputStream().close();
      yes(restarted.get("/api/transport-log",restarted.cookie).status==200,"closing_application_stdout_does_not_close_http_transport");
    }
    yes(MessageDigest.isEqual(originalCredentialFile,Files.readAllBytes(Paths.get(home,".credentials.yaml"))),"existing_credential_file_byte_preserved");
    System.out.println("ORIGINAL_HTTP_FRONTEND_AUTH_STREAM_SSE_AND_GENERATION_REVOCATION=PASS checks="+checks);
    System.out.println("ORIGINAL_RENDERED_FRONTEND_SHA256="+renderedSha);
    System.out.println("ANDROID_ARM64_MAIN_PROFILE_AND_ENGINE_READY=NOT_ATTESTED");
  }
}
