package com.dsh.android.p50;

import android.content.Context;
import android.content.ContextWrapper;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.android.p77.P77TarAudit;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Calls the original runDumpConfig in a fresh P51-owned profile. No singleton,
 * production installation, host execution, original user data or READY claim.
 * The disposable CI build redirects ONLY the typed config seam to claim().
 */
public final class P50OriginalEngineConfig implements AutoCloseable {
  private static final String ENTRY="node_modules/@deepseek-ai/dsh/lib/bin.js";
  private static final String NODE_SHA="a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6";
  private static final ThreadLocal<Lease> SLOT=new ThreadLocal<>();
  private final Object engine;
  private final Method run;
  private final ProcessBuilder expected;
  private final String session;
  private File privateRoot;
  private volatile boolean closed;
  private static final class Lease {
    final P37RemoteProcess process;
    final List<String> argv;
    final Map<String,String> env;
    final File directory;
    final long deadline=System.nanoTime()+12000000000L;
    boolean claimed;
    Lease(P37RemoteProcess process,ProcessBuilder expected){
      this.process=process;argv=new ArrayList<>(expected.command());
      env=new HashMap<>(expected.environment());directory=expected.directory();
    }
  }
  private P50OriginalEngineConfig(Object engine,Method run,ProcessBuilder expected,String session){
    this.engine=engine;this.run=run;this.expected=expected;this.session=session;
  }
  public static P50OriginalEngineConfig prepare(Context host,String session)throws Exception {
    if(host==null||!"com.dsh.p51.isolatedprobe".equals(host.getPackageName())||
        session==null||!session.matches("[0-9a-f]{64}"))
      throw new SecurityException("ORIGINAL_CONFIG_FRESH_SIDECAR_ONLY");
    // A new directory per invocation. No read, replace or delete in original DSH.
    File root=new File(host.getCacheDir(),"original-config-"+UUID.randomUUID());
    if(!root.mkdir())throw new IOException("ORIGINAL_CONFIG_FRESH_ROOT");
    boolean prepared=false;
    try{
    File files=new File(root,"files"),cache=new File(root,"cache");
    if(!files.mkdir()||!cache.mkdir())throw new IOException("ORIGINAL_CONFIG_PRIVATE_DIRS");
    Context isolated=new ContextWrapper(host){
      @Override public File getFilesDir(){return files;}
      @Override public File getCacheDir(){return cache;}
      @Override public Context getApplicationContext(){return this;}
    };
    File prefix=new File(files,"termux/usr"),workspace=new File(files,"workspace");
    File node=new File(prefix,"bin/node"),entry=new File(files,"engine/"+ENTRY);
    if(!node.getParentFile().mkdirs()||!entry.getParentFile().mkdirs()||!workspace.mkdir())
      throw new IOException("ORIGINAL_CONFIG_LAYOUT");
    File source=new File(host.getApplicationInfo().nativeLibraryDir,"libdshnode_p21_exec.so");
    if(!NODE_SHA.equals(hashFile(source)))throw new SecurityException("ORIGINAL_CONFIG_NODE_HASH");
    try(InputStream in=new FileInputStream(source);OutputStream out=new FileOutputStream(node)){
      byte[] block=new byte[32768];int n;while((n=in.read(block))!=-1)out.write(block,0,n);
    }
    // This is genuine original content for the original isFile guards. It is
    // never made executable or passed to a host ProcessBuilder.start().
    if(!node.setReadable(true,true)||!node.setWritable(false,false)||!node.setExecutable(false,false)||
        !NODE_SHA.equals(hashFile(node)))throw new SecurityException("ORIGINAL_CONFIG_NODE_COPY");
    ByteArrayOutputStream entryBytes=new ByteArrayOutputStream();
    try(InputStream archive=host.getAssets().open("engine.bin")){
      P77TarAudit.inspectGzipTo(archive,new P77TarAudit.MemberSink(){
        boolean selected,found,sealed;
        public void begin(String path,boolean directory,long size)throws IOException{
          selected=ENTRY.equals(path);
          if(selected&&(found||directory||size<1||size>65536))throw new IOException("ORIGINAL_CONFIG_ENTRY_TYPE");
          if(selected)found=true;
        }
        public void accept(byte[] bytes,int offset,int length)throws IOException{
          if(selected){if(length>65536-entryBytes.size())throw new IOException("ORIGINAL_CONFIG_ENTRY_BOUND");
            entryBytes.write(bytes,offset,length);}
        }
        public void endMember(){selected=false;}
        public void sealOriginal(P77TarAudit.Result complete)throws IOException{
          if(sealed||!found||!complete.isExactOriginal())throw new IOException("ORIGINAL_CONFIG_ENTRY_SEAL");
          sealed=true;
        }
      });
    }
    try(OutputStream out=new FileOutputStream(entry)){entryBytes.writeTo(out);}
    Class<?> type=Class.forName("com.dsh.android.EngineManager",true,host.getClassLoader());
    Constructor<?> constructor=type.getDeclaredConstructor(Context.class);constructor.setAccessible(true);
    Object engine=constructor.newInstance(isolated);
    Method run=type.getDeclaredMethod("runDumpConfig");run.setAccessible(true);
    ProcessBuilder expected=new ProcessBuilder(node.getAbsolutePath(),entry.getAbsolutePath(),
        "--profile","web","--dump-config").directory(workspace);
    Map<String,String> env=expected.environment();String p=prefix.getAbsolutePath();
    env.put("PREFIX",p);env.put("HOME",new File(files,"home").getAbsolutePath());
    env.put("DSH_HOME",new File(files,"home/.dsh").getAbsolutePath());
    env.put("TMPDIR",cache.getAbsolutePath());
    env.put("PATH",p+"/bin:"+p+"/bin/applets:/system/bin:/system/xbin");
    env.put("SSL_CERT_FILE",p+"/etc/tls/cert.pem");env.put("CURL_CA_BUNDLE",p+"/etc/tls/cert.pem");
    env.put("NODE_OPTIONS","--max-old-space-size=1024");
    P50OriginalEngineConfig result=new P50OriginalEngineConfig(engine,run,expected,session);
    result.privateRoot=root;prepared=true;return result;
    }finally{if(!prepared)deleteOwnLayout(root);}

  }
  /** A real receipt is the only route into a thread-bound, one-use lease. */
  public Object invoke(P37RemoteProcess process,P184ChildStartReceipt receipt,long epoch)throws Exception {
    if(closed||SLOT.get()!=null||process==null||receipt==null||!receipt.consume(process,session,epoch)){
      if(process!=null)process.destroyForcibly();
      throw new SecurityException("ORIGINAL_CONFIG_AUTHENTICATED_RECEIPT");
    }
    Lease lease=new Lease(process,expected);SLOT.set(lease);
    boolean succeeded=false;
    try{
      Object result=run.invoke(engine);
      if(!lease.claimed||result==null||
          !result.getClass().getName().equals("com.dsh.android.EngineManager$DumpResult"))throw new IOException("ORIGINAL_CONFIG_CALL_OR_HANDOFF_DENIED");
      succeeded=true;return result;
    }finally{
      SLOT.remove();
      if(!succeeded)process.destroyForcibly();
    }
  }
  /** Called only from the disposable typed P47 config bridge, never main/probe. */
  public static Process claim(ProcessBuilder builder)throws IOException {
    Lease lease=SLOT.get();SLOT.remove();
    if(lease==null)throw new IOException("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK");
    boolean accepted=false;
    try{
      boolean originalCaller=false;
      for(StackTraceElement frame:Thread.currentThread().getStackTrace())
        if(frame.getClassName().equals("com.dsh.android.EngineManager")&&
            frame.getMethodName().equals("runDumpConfig"))originalCaller=true;
      P37RemoteProcess.TerminalReason state=lease.process.terminalReason();
      if((state!=P37RemoteProcess.TerminalReason.RUNNING&&state!=P37RemoteProcess.TerminalReason.REMOTE_EXIT)||
          !originalCaller||builder==null||System.nanoTime()-lease.deadline>=0||lease.claimed||
          !lease.argv.equals(builder.command())||!lease.env.equals(builder.environment())||
          !lease.directory.equals(builder.directory())||builder.redirectErrorStream()||
          builder.redirectInput()!=ProcessBuilder.Redirect.PIPE||
          builder.redirectOutput()!=ProcessBuilder.Redirect.PIPE||builder.redirectError()!=ProcessBuilder.Redirect.PIPE)
        throw new IOException("ORIGINAL_CONFIG_LAUNCH_DRIFT");
      lease.claimed=true;accepted=true;return lease.process;
    }finally{if(!accepted)lease.process.destroyForcibly();}
  }
  public static Object value(Object result,String getter)throws Exception{
    if(!Arrays.asList("getExitCode","getStdout","getStderr").contains(getter)||result==null||
        !result.getClass().getName().equals("com.dsh.android.EngineManager$DumpResult"))
      throw new SecurityException("ORIGINAL_CONFIG_RESULT_TYPE");
    Method method=result.getClass().getDeclaredMethod(getter);method.setAccessible(true);
    return method.invoke(result);
  }
  /** Delete only this invocation's fixed files and empty directories. Never a
   * recursive profile/cache purge, and never the installed DSH's storage. */
  @Override public void close(){closed=true;if(privateRoot!=null)deleteOwnLayout(privateRoot);}
  private static void deleteOwnLayout(File root){
    for(String relative:new String[]{"files/termux/usr/bin/node","files/engine/"+ENTRY}){
      File file=new File(root,relative);file.delete();
      for(File directory=file.getParentFile();directory!=null&&!directory.equals(root);
          directory=directory.getParentFile())directory.delete();
    }
    new File(root,"files/workspace").delete();new File(root,"files").delete();
    new File(root,"cache").delete();root.delete();
  }
  private static String hashFile(File file)throws Exception{
    if(!file.isFile()||file.length()<1000||file.length()>128L*1024*1024)
      throw new IOException("ORIGINAL_CONFIG_NODE_BOUNDS");
    MessageDigest digest=MessageDigest.getInstance("SHA-256");
    try(InputStream in=new FileInputStream(file)){byte[] block=new byte[32768];int n;
      while((n=in.read(block))!=-1)digest.update(block,0,n);}
    StringBuilder out=new StringBuilder();for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b&255));
    return out.toString();
  }
}
