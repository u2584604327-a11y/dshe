package com.dsh.android.engine;
import java.io.*;import java.nio.file.*;import java.net.*;import java.security.*;import java.util.*;import java.util.concurrent.*;
/** Verified resources over stdin, no native read permission for the extracted
 * modules or any real profile. Same real original HTTP/auth/frontend services. */
public final class ClosedResourceHttpTest {
 private static void yes(boolean value,String name){if(!value)throw new AssertionError(name);}
 private static String sha(byte[] bytes)throws Exception{StringBuilder s=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
 private static byte[] read(InputStream stream)throws IOException{try(InputStream in=stream;ByteArrayOutputStream bytes=new ByteArrayOutputStream()){byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){if(n>2*1024*1024-bytes.size())throw new IOException("OUTPUT_BOUND");bytes.write(b,0,n);}return bytes.toByteArray();}}
 public static void main(String[] a)throws Exception{
  ProcessBuilder builder=new ProcessBuilder(a[0],"--permission","--allow-fs-read="+a[1],"--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home",a[1]);
  builder.environment().clear();builder.environment().put("HOME","/dsh-home");builder.environment().put("DSH_HOME","/dsh-home");
  Process child=builder.start();
  HttpProcessTransport process=null;
  try{
   boolean denied=a.length>4;
   try(InputStream wire=Files.newInputStream(Paths.get(a[2]))){byte[] block=new byte[65536];int n;while((n=wire.read(block))!=-1)child.getOutputStream().write(block,0,n);child.getOutputStream().flush();}
   catch(IOException broken){if(!denied)throw broken;}
   if(denied){
    child.getOutputStream().close();yes(child.waitFor(8,TimeUnit.SECONDS),"resource_rejection_exit");
    yes(child.exitValue()==125,"resource_rejection_code");
    String diagnostics=new String(read(child.getErrorStream()),"US-ASCII");
    yes(diagnostics.equals("DSH_ORIGINAL_HTTP_ERROR="+a[4]+"\n"),"resource_rejection_reason");
    yes(read(child.getInputStream()).length==0,"no_http_or_frontend_before_resource_seal");
    System.out.println("SEALED_HTTP_RESOURCE_MUTATION=DENY code="+a[4]);return;
   }
   process=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
   yes(process.awaitListening(15,TimeUnit.SECONDS),"sealed_http_listening_"+process.failure());
   BufferedReader stdout=new BufferedReader(new InputStreamReader(process.getInputStream(),"UTF-8"));
   String row=stdout.readLine();yes(row!=null&&row.startsWith("DSH_ORIGINAL_HTTP_URL="),"original_auth_url");
   URL url=new URL(row.substring("DSH_ORIGINAL_HTTP_URL=".length())); // never log tokens or cookies
   HttpURLConnection first=(HttpURLConnection)url.openConnection();first.setInstanceFollowRedirects(false);first.setReadTimeout(5000);
   yes(first.getResponseCode()==303,"original_auth_exchange");String cookie=first.getHeaderField("Set-Cookie").split(";")[0];first.disconnect();
   HttpURLConnection frontend=(HttpURLConnection)new URL("http://127.0.0.1:"+process.port()+"/").openConnection();
   frontend.setRequestProperty("Cookie",cookie);frontend.setReadTimeout(5000);
   yes(frontend.getResponseCode()==200,"sealed_original_frontend");yes(sha(read(frontend.getInputStream())).equals(a[3]),"independent_original_frontend_render_sha");frontend.disconnect();
   String modules=stdout.readLine();yes(modules!=null&&modules.matches("DSH_ORIGINAL_HTTP_RESOURCE_MODULES=[0-9]+"),"actual_module_loading_count");
   int count=Integer.parseInt(modules.substring(modules.indexOf('=')+1));yes(count>69&&count<30411,"real_service_dependency_modules");
   process.destroy();yes(process.waitFor(8,TimeUnit.SECONDS)&&process.exitValue()==0,"sealed_runtime_graceful_exit");
   yes(read(process.getErrorStream()).length==0&&process.failure().equals("NONE/NONE"),"no_resource_or_transport_error");
   System.out.println("SEALED_ORIGINAL_HTTP_FRONTEND_AND_AUTH=PASS modules="+count);
   System.out.println("SEALED_HTTP_NATIVE_HOST_MODULE_OR_PROFILE_FS_ACCESS=NOT_GRANTED");
  }finally{if(process!=null)process.close();else{child.destroyForcibly();child.waitFor();}}
 }
}
