package com.dsh.android.p149;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Trusted-host-only, source-private prelaunch ProcessBuilder equality witness.
 * HMAC never crosses Binder and is not a broker approval. All entrypoints DENY.
 */
public final class P149OriginalBuilderWitness {
  private static final int MAX_ARGC=128, MAX_ENV=1024, MAX_TOTAL=1024*1024;
  private static final SecureRandom RANDOM=new SecureRandom();
  private static final byte[] DOMAIN=
      "P149_BUILDER_SNAPSHOT_V1".getBytes(StandardCharsets.US_ASCII);
  private P149OriginalBuilderWitness() {}

  private static void field(DataOutputStream out,String value,int cap)
      throws IOException {
    if(value==null || value.length()>cap || value.indexOf('\u0000')>=0)
      throw new IOException("P149_INVALID_FIELD_OR_LENGTH");
    byte[] raw=null;
    try {
      ByteBuffer buffer=StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(value));
      raw=new byte[buffer.remaining()];buffer.get(raw);
      if(raw.length>cap*4)throw new IOException("P149_UTF8_FIELD_TOO_LONG");
      out.writeInt(raw.length);out.write(raw);
    }catch(CharacterCodingException invalid) {
      throw new IOException("P149_MALFORMED_UTF8",invalid);
    }finally{
      if(raw!=null)Arrays.fill(raw,(byte)0);
    }
  }
  /** Erase the internal growable buffer even if validation throws. */
  private static final class SensitiveMemory extends ByteArrayOutputStream {
    void wipe(){Arrays.fill(buf,(byte)0);reset();}
  }
  private static byte[] bounded(ProcessBuilder builder,int kind,String session,long sequence)
      throws IOException {
    if(kind<1 || kind>3 || session==null ||
       !session.matches("[a-f0-9]{64}") || sequence<1 ||
       builder==null || builder.directory()==null ||
       builder.command()==null || builder.command().isEmpty() ||
       builder.command().size()>MAX_ARGC)
      throw new IOException("P149_UNTRUSTED_OR_INCOMPLETE_BUILDER");
    List<String> args=builder.command();
    Map<String,String> env=builder.environment();
    if(env==null||env.size()>MAX_ENV)
      throw new IOException("P149_ENV_LIMIT");
    SensitiveMemory memory=new SensitiveMemory();
    try {
      DataOutputStream out=new DataOutputStream(memory);
      out.writeInt(DOMAIN.length);out.write(DOMAIN);
      out.writeInt(kind);out.writeLong(sequence);
      field(out,session,64);
      out.writeInt(args.size());
      for(String arg:args)field(out,arg,8192);
      field(out,builder.directory().getPath(),8192);
      TreeMap<String,String> ordered=new TreeMap<>(env);
      out.writeInt(ordered.size());
      for(Map.Entry<String,String> e:ordered.entrySet()) {
        field(out,e.getKey(),4096);field(out,e.getValue(),16384);
        if(memory.size()>MAX_TOTAL)throw new IOException("P149_ENV_SIZE_LIMIT");
      }
      out.writeBoolean(builder.redirectErrorStream());
      field(out,builder.redirectInput().toString(),8192);
      field(out,builder.redirectOutput().toString(),8192);
      field(out,builder.redirectError().toString(),8192);
      out.flush();
      if(memory.size()>MAX_TOTAL)throw new IOException("P149_SERIALIZED_CAP");
      return memory.toByteArray();
    }finally {
      // Even on an exception, destroy the scratch backing buffer before exit.
      memory.wipe();
    }
  }
  private static byte[] mac(byte[] key,byte[] payload)throws IOException {
    try {
      Mac h=Mac.getInstance("HmacSHA256");
      h.init(new SecretKeySpec(key,"HmacSHA256"));
      return h.doFinal(payload);
    }catch(Exception e){
      throw new IOException("P149_HMAC_UNAVAILABLE",e);
    }
  }
  public static final class Witness implements AutoCloseable {
    private final int mode;
    private final long seq;
    private final String session;
    private final byte[] key=new byte[32];
    private final byte[] tag;
    private boolean used,closed;
    private Witness(ProcessBuilder builder,int kind,String s,long sequence)
        throws IOException {
      mode=kind;seq=sequence;session=s;
      // Validate/serialize the complete bounded builder BEFORE generating a
      // live secret. Malformed argv/env must not leave a generated HMAC key
      // in a constructor that can never return a closeable Witness.
      byte[] payload=bounded(builder,kind,s,sequence);
      byte[] computed=null;
      try {
        RANDOM.nextBytes(key);
        computed=mac(key,payload);
        if(computed==null || computed.length!=32)
          throw new IOException("P149_HMAC_TAG_LENGTH_DRIFT");
        tag=computed;
      }finally {
        Arrays.fill(payload,(byte)0);
        // A failed constructor cannot be closed by its caller: erase its
        // generated secret immediately, including HMAC/provider failure.
        if(computed==null || computed.length!=32){
          Arrays.fill(key,(byte)0);
          if(computed!=null)Arrays.fill(computed,(byte)0);
        }
      }
    }
    /** One attempt only; fail-closed even after a mismatch. */
    public synchronized void matchOnce(ProcessBuilder builder,int kind,String s,long sequence)
        throws IOException {
      if(closed||used)throw new IOException("P149_USED_OR_CLOSED");
      used=true;
      byte[] fresh=null,payload=null;
      try {
        if(kind!=mode || seq!=sequence || !session.equals(s))
          throw new IOException("P149_SESSION_MODE_OR_SEQUENCE_DRIFT");
        payload=bounded(builder,kind,s,sequence);
        fresh=mac(key,payload);
        if(!MessageDigest.isEqual(tag,fresh))
          throw new IOException("P149_MUTATED_LAUNCH_ARGUMENTS");
      }finally {
        if(payload!=null)Arrays.fill(payload,(byte)0);
        if(fresh!=null)Arrays.fill(fresh,(byte)0);
        close();
      }
    }
    @Override public synchronized void close() {
      if(!closed){
        Arrays.fill(key,(byte)0);Arrays.fill(tag,(byte)0);
        closed=true;
      }
    }
  }
  public static Witness capture(ProcessBuilder builder,int mode,String session,long sequence)
      throws IOException {
    return new Witness(builder,mode,session,sequence);
  }
  /**
   * Current production defaults remain DENY_ALL, independent of witness PASS.
   * The caller must ALWAYS throw after this returns; no permission is granted.
   */
  public static void observeWithoutLaunch(ProcessBuilder builder,int mode)
      throws IOException {
    byte[] random=new byte[32];RANDOM.nextBytes(random);
    char[] abc="0123456789abcdef".toCharArray();
    char[] session=new char[64];
    for(int i=0;i<random.length;i++){
      int n=random[i]&255;
      session[2*i]=abc[n>>>4];session[2*i+1]=abc[n&15];
    }
    Arrays.fill(random,(byte)0);
    String sid=new String(session);Arrays.fill(session,'\0');
    try(Witness witness=capture(builder,mode,sid,1)){
      witness.matchOnce(builder,mode,sid,1);
    }
  }
}
