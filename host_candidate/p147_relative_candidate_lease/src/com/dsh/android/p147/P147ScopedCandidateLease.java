package com.dsh.android.p147;
import com.dsh.android.p77.P77TarAudit;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

/** A single private, verified TAR member. Not a Node loader or dependency proof. */
public final class P147ScopedCandidateLease implements AutoCloseable {
  public static final int MAX_SOURCE_BYTES=524288;
  private static final String ROOT="node_modules/@deepseek-ai/dsh/";
  private final String session,target;
  private byte[] bytes;
  private int filled;
  private String sha256;
  private boolean seen,done,sealed,taken,closed;
  public P147ScopedCandidateLease(String authenticatedSession,String canonical) {
    if(authenticatedSession==null || !authenticatedSession.matches("[a-f0-9]{64}") ||
       canonical==null || !canonical.startsWith(ROOT) || canonical.length()>512 ||
       canonical.indexOf('\\')>=0 || canonical.indexOf(':')>=0 ||
       !(canonical.endsWith(".js")||canonical.endsWith(".cjs")||
         canonical.endsWith(".mjs")||canonical.endsWith(".json")))
      throw new SecurityException("P147_SESSION_OR_SCOPE");
    for(String part:canonical.split("/",-1))
      if(part.isEmpty()||part.equals(".")||part.equals(".."))
        throw new SecurityException("P147_CANONICAL_PATH_REQUIRED");
    session=authenticatedSession;
    target=canonical;
  }
  private static String hash(byte[] b) {
    try{
      byte[] digest=MessageDigest.getInstance("SHA-256").digest(b);
      StringBuilder sb=new StringBuilder(64);
      final char[] h="0123456789abcdef".toCharArray();
      for(byte n:digest){int v=n&255;sb.append(h[v>>>4]).append(h[v&15]);}
      return sb.toString();
    }catch(Exception e){throw new IllegalStateException("P147_SHA256_UNAVAILABLE",e);}
  }
  public boolean begin(String name,boolean directory,long length)throws IOException {
    if(closed||sealed||seen&&!done)throw new IOException("P147_BAD_LEASE_STATE");
    if(!target.equals(name))return false;
    if(seen||directory||length<1||length>MAX_SOURCE_BYTES)
      throw new IOException("P147_DUPLICATE_OR_OVERSIZE");
    seen=true;
    bytes=new byte[(int)length];filled=0;return true;
  }
  public void accept(byte[] b,int off,int n)throws IOException {
    if(closed||!seen||done||sealed||b==null||off<0||n<0||
       off>b.length-n||n>bytes.length-filled)
      throw new IOException("P147_SOURCE_BOUNDS");
    System.arraycopy(b,off,bytes,filled,n);filled+=n;
  }
  public void endMember()throws IOException {
    if(closed||!seen||done||filled!=bytes.length)
      throw new IOException("P147_INCOMPLETE_SOURCE");
    sha256=hash(bytes);done=true;
  }
  public void sealOriginal(P77TarAudit.Result root)throws IOException {
    if(closed||sealed||root==null||!root.isExactOriginal()||
       !root.hasOriginalMember(target)||!done||sha256==null)
      throw new IOException("P147_SECOND_PASS_EXACT_ROOT_AND_MEMBER_REQUIRED");
    sealed=true;
  }
  public boolean ready(){return sealed&&!taken&&!closed;}
  public String digest() {
    if(!ready())throw new SecurityException("P147_NOT_READY");
    return sha256;
  }
  public byte[] takeOnce(String authenticatedSession) {
    if(!ready()||!session.equals(authenticatedSession))
      throw new SecurityException("P147_SESSION_REPLAY_OR_ROOT_DENIED");
    taken=true;return bytes;
  }
  public boolean exhausted(){return sealed&&taken&&!closed;}
  @Override public void close(){
    if(!closed){
      if(bytes!=null)Arrays.fill(bytes,(byte)0);
      closed=true;
    }
  }
}
