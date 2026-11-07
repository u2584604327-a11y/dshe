package com.dsh.android.p144;

import com.dsh.android.p77.P77TarAudit;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * One authenticated session; two immutable source leases captured from the
 * exact original archive in the isolated UID. No host paths or Binder bytes.
 * Source-only: no Node, imports, native addon loading, disk writes or network.
 */
public final class P144ScopedSourceBroker implements AutoCloseable {
  public static final int MAX_JS_BYTES=65536;
  public static final int MAX_PACKAGE_BYTES=32768;
  private static final class Slot {
    final String opaqueId;
    final byte[] bytes;
    int filled;
    String digest;
    boolean done, taken;
    Slot(String name,int length) {
      opaqueId=hex(sha(name.getBytes(StandardCharsets.UTF_8)));
      bytes=new byte[length];
    }
    void clear(){Arrays.fill(bytes,(byte)0);}
  }
  private final String session;
  private Slot script, manifest, active;
  private boolean sealed, closed;
  public P144ScopedSourceBroker(String authenticatedSession) {
    if(authenticatedSession==null ||
       !authenticatedSession.matches("[0-9a-f]{64}"))
      throw new SecurityException("P144_SESSION_REQUIRED");
    session=authenticatedSession;
  }
  private static byte[] sha(byte[] raw) {
    try {return MessageDigest.getInstance("SHA-256").digest(raw);}
    catch(Exception e){throw new IllegalStateException("P144_SHA_UNAVAILABLE",e);}
  }
  private static String hex(byte[] raw) {
    String alphabet="0123456789abcdef";
    char[] c=new char[raw.length*2];
    for(int i=0;i<raw.length;i++) {
      int v=raw[i]&255;
      c[2*i]=alphabet.charAt(v>>>4);
      c[2*i+1]=alphabet.charAt(v&15);
    }
    return new String(c);
  }
  // Invoked exclusively by P77 after canonical TAR path validation.
  public boolean begin(String canonicalName,boolean directory,long length)
      throws IOException {
    if(closed||sealed||active!=null)
      throw new IOException("P144_BAD_BROKER_STATE");
    if(directory||length<1)return false;
    boolean isJs=canonicalName.endsWith(".js") ||
                 canonicalName.endsWith(".cjs") ||
                 canonicalName.endsWith(".mjs");
    boolean isPackage=canonicalName.equals("package.json") ||
                      canonicalName.endsWith("/package.json");
    if(isJs&&script==null&&length<=MAX_JS_BYTES){
      active=script=new Slot(canonicalName,(int)length);
      return true;
    }
    if(isPackage&&manifest==null&&length<=MAX_PACKAGE_BYTES){
      active=manifest=new Slot(canonicalName,(int)length);
      return true;
    }
    return false;
  }
  public void accept(byte[] bytes,int offset,int length)throws IOException {
    if(closed||sealed||active==null||bytes==null||length<0||
       offset<0||offset>bytes.length-length||
       length>active.bytes.length-active.filled)
      throw new IOException("P144_LEASE_WINDOW_VIOLATION");
    System.arraycopy(bytes,offset,active.bytes,active.filled,length);
    active.filled+=length;
  }
  public void endMember()throws IOException {
    if(closed||active==null||active.filled!=active.bytes.length)
      throw new IOException("P144_TRUNCATED_SELECTED_MEMBER");
    active.digest=hex(sha(active.bytes));
    active.done=true;
    active=null;
  }
  public void sealOriginal(P77TarAudit.Result tree)throws IOException {
    if(closed||sealed||active!=null||tree==null||!tree.isExactOriginal()||
       script==null||manifest==null||!script.done||!manifest.done)
      throw new IOException("P144_EXACT_ORIGINAL_AND_TWO_SLOTS_REQUIRED");
    sealed=true;
  }
  public boolean isReady(){return sealed&&!closed&&
                             !script.taken&&!manifest.taken;}
  private void requireReady() {
    if(!sealed||closed)throw new SecurityException("P144_UNVERIFIED");
  }
  public String scriptId(){requireReady();return script.opaqueId;}
  public String manifestId(){requireReady();return manifest.opaqueId;}
  public String scriptHash(){requireReady();return script.digest;}
  public String manifestHash(){requireReady();return manifest.digest;}
  // Only the authenticated isolated worker can consume. Never place bytes in ACK.
  public byte[] takeOnce(String authenticatedSession,String opaqueId) {
    requireReady();
    if(!session.equals(authenticatedSession)||opaqueId==null)
      throw new SecurityException("P144_SESSION_OR_ID_MISMATCH");
    Slot slot=opaqueId.equals(script.opaqueId)?script:
              opaqueId.equals(manifest.opaqueId)?manifest:null;
    if(slot==null||slot.taken||!slot.done)
      throw new SecurityException("P144_UNKNOWN_OR_REPLAYED_LEASE");
    slot.taken=true;
    return slot.bytes;
  }
  public boolean exhausted(){return sealed&&!closed&&script.taken&&manifest.taken;}
  @Override public void close() {
    if(!closed) {
      if(script!=null)script.clear();
      if(manifest!=null)manifest.clear();
      closed=true;
    }
  }
}
