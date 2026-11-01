package com.dsh.android.p145;
import com.dsh.android.p77.P77TarAudit;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
/** Fixed source-only original CLI entry + package; never execute or export bytes. */
public final class P145ExactBootEntry implements AutoCloseable {
  public static final String ENTRY="node_modules/@deepseek-ai/dsh/lib/bin.js";
  public static final String PACKAGE="node_modules/@deepseek-ai/dsh/package.json";
  public static final int MAX_ENTRY_BYTES=262144, MAX_PACKAGE_BYTES=131072;
  private static final class Slot {
    final byte[] bytes;
    int written;
    String sha;
    boolean ended,taken;
    Slot(int n) {bytes=new byte[n];}
  }
  private final String session;
  private Slot entry,manifest,current;
  private boolean sealed,closed;
  public P145ExactBootEntry(String s) {
    if(s==null||!s.matches("[0-9a-f]{64}"))
      throw new SecurityException("P145_AUTHENTICATED_SESSION_REQUIRED");
    session=s;
  }
  private static String hash(byte[] bytes) {
    try{
      byte[] h=MessageDigest.getInstance("SHA-256").digest(bytes);
      char[] out=new char[h.length*2];String hex="0123456789abcdef";
      for(int i=0;i<h.length;i++) {
        out[2*i]=hex.charAt((h[i]&255)>>>4);
        out[2*i+1]=hex.charAt(h[i]&15);
      }
      return new String(out);
    }catch(Exception e){throw new IllegalStateException("P145_HASH_UNAVAILABLE",e);}
  }
  public boolean begin(String name,boolean directory,long length)throws IOException {
    if(closed||sealed||current!=null)throw new IOException("P145_BAD_STATE");
    if(!ENTRY.equals(name)&&!PACKAGE.equals(name))return false;
    int cap=ENTRY.equals(name)?MAX_ENTRY_BYTES:MAX_PACKAGE_BYTES;
    if(directory||length<1||length>cap)
      throw new IOException("P145_EXPECTED_ENTRY_SIZE_OR_TYPE_INVALID");
    if(ENTRY.equals(name)){
      if(entry!=null)throw new IOException("P145_ENTRY_DUPLICATE");
      current=entry=new Slot((int)length);
    }else{
      if(manifest!=null)throw new IOException("P145_PACKAGE_DUPLICATE");
      current=manifest=new Slot((int)length);
    }
    return true;
  }
  public void accept(byte[] source,int offset,int length)throws IOException {
    if(closed||sealed||current==null||source==null||offset<0||length<0||
       offset>source.length-length||length>current.bytes.length-current.written)
      throw new IOException("P145_SOURCE_BOUNDS");
    System.arraycopy(source,offset,current.bytes,current.written,length);
    current.written+=length;
  }
  public void endMember()throws IOException {
    if(current==null||current.written!=current.bytes.length)
      throw new IOException("P145_SHORT_ENTRY");
    current.sha=hash(current.bytes);current.ended=true;current=null;
  }
  public void sealOriginal(P77TarAudit.Result original)throws IOException {
    if(closed||sealed||current!=null||original==null||!original.isExactOriginal()||
       entry==null||manifest==null||!entry.ended||!manifest.ended)
      throw new IOException("P145_EXACT_ORIGINAL_CLI_AND_PACKAGE_REQUIRED");
    sealed=true;
  }
  private void verified() {
    if(closed||!sealed)throw new SecurityException("P145_NOT_SEALED");
  }
  public boolean isReady(){return sealed&&!closed&&!entry.taken&&!manifest.taken;}
  public String entrySha(){verified();return entry.sha;}
  public String packageSha(){verified();return manifest.sha;}
  public byte[] takeOnce(String s,boolean requestedEntry) {
    verified();
    if(!session.equals(s))throw new SecurityException("P145_SESSION_MISMATCH");
    Slot selected=requestedEntry?entry:manifest;
    if(selected.taken)throw new SecurityException("P145_REPLAY_DENIED");
    selected.taken=true;return selected.bytes;
  }
  public boolean exhausted(){return sealed&&!closed&&entry.taken&&manifest.taken;}
  public void close(){
    if(!closed) {
      if(entry!=null)Arrays.fill(entry.bytes,(byte)0);
      if(manifest!=null)Arrays.fill(manifest.bytes,(byte)0);
      closed=true;
    }
  }
}
