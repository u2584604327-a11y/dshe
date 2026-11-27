package com.dsh.android.p187;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One-shot IPC test: host connects to an isolated UID's ephemeral 127.0.0.1
 * listener using a test-only nonce received via authenticated Binder.
 * Never resolves a hostname, sends Internet traffic or reads user data.
 * Does NOT enable the production DSH HTTP server or grant network rights.
 */
public final class P187LoopbackCapability {
  private static final int DEADLINE_MS=1600;
  private static final byte[] ACK="P187OK".getBytes(StandardCharsets.US_ASCII);
  private static final InetAddress LOCAL=localhost();
  private P187LoopbackCapability() {}
  private static InetAddress localhost() {
    try { return InetAddress.getByAddress(new byte[]{127,0,0,1}); }
    catch(IOException impossible) { throw new AssertionError(impossible); }
  }
  private static String reason(Throwable cause) {
    if(cause instanceof SecurityException) return "SECURITY";
    if(cause instanceof SocketTimeoutException) return "TIMEOUT";
    String message=cause.getMessage();
    String m=message==null?"":message.toUpperCase(Locale.ROOT);
    if(m.contains("EACCES") || m.contains("PERMISSION DENIED")) return "EACCES";
    if(m.contains("EPERM") || m.contains("OPERATION NOT PERMITTED")) return "EPERM";
    if(m.contains("CONNECTION REFUSED")) return "REFUSED";
    return "OTHER";
  }
  public static String failure(String step,Throwable cause) {
    if(!"BIND".equals(step) && !"CONNECT".equals(step) &&
        !"ACCEPT".equals(step) && !"ECHO".equals(step))
      throw new IllegalArgumentException("P187_EXACT_STEP_REQUIRED");
    return step+"_"+reason(cause);
  }
  public static boolean isValidStatus(String status) {
    return "PASS".equals(status) || (status!=null &&
      status.matches("(BIND|CONNECT|ACCEPT|ECHO)_(SECURITY|TIMEOUT|EACCES|EPERM|REFUSED|OTHER)"));
  }
  private static byte[] fromHex(String raw) {
    if(raw==null || !raw.matches("[0-9a-f]{32}"))
      throw new IllegalArgumentException("P187_INVALID_TEST_NONCE");
    byte[] out=new byte[16];
    for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(raw.substring(i*2,i*2+2),16);
    return out;
  }
  private static String hex(byte[] data) {
    char[] digits="0123456789abcdef".toCharArray();
    char[] out=new char[data.length*2];
    for(int i=0;i<data.length;i++){
      out[2*i]=digits[(data[i]&255)>>4];out[2*i+1]=digits[data[i]&15];
    }
    return new String(out);
  }
  /** Must be closed on all paths; at most one TCP connection, max 1600 ms. */
  public static final class Listener implements AutoCloseable {
    private final ServerSocket server;
    private final byte[] nonce;
    private boolean consumed;
    private Listener(ServerSocket server,byte[] nonce){this.server=server;this.nonce=nonce;}
    public int port(){return server.getLocalPort();}
    public String nonceHex(){return hex(nonce);}
    public synchronized String acceptOnce() {
      if(consumed)return "ACCEPT_OTHER";
      consumed=true;
      try(Socket peer=server.accept()){
        peer.setSoTimeout(DEADLINE_MS);
        if(!LOCAL.equals(peer.getInetAddress()))return "ACCEPT_OTHER";
        byte[] received=new byte[nonce.length];
        int n=0;
        try {
          while(n<received.length){
            int more=peer.getInputStream().read(received,n,received.length-n);
            if(more<0)return "ECHO_OTHER";
            n+=more;
          }
          if(!Arrays.equals(nonce,received))return "ECHO_OTHER";
          peer.getOutputStream().write(ACK);
          peer.getOutputStream().flush();
          return "PASS";
        } catch(IOException | SecurityException error) {return failure("ECHO",error);}
      }catch(IOException | SecurityException error){return failure("ACCEPT",error);}
    }
    @Override public void close(){try{server.close();}catch(IOException ignored){}}
  }
  public static Listener bind() throws IOException {
    ServerSocket server=new ServerSocket();
    try {
      server.setSoTimeout(DEADLINE_MS);
      server.setReuseAddress(false);
      server.bind(new InetSocketAddress(LOCAL,0),1);
      if(!LOCAL.equals(server.getInetAddress()))
        throw new SecurityException("P187_LOOPBACK_ONLY");
      byte[] nonce=new byte[16];new SecureRandom().nextBytes(nonce);
      return new Listener(server,nonce);
    }catch(IOException | RuntimeException ex){try{server.close();}catch(IOException ignored){}throw ex;}
  }
  /** Host-only side; accepts exclusively exact 127.0.0.1 and Binder-sourced nonce. */
  public static String connect(int port,String nonceHex) {
    if(port<=0||port>65535||nonceHex==null||!nonceHex.matches("[0-9a-f]{32}"))
      return "CONNECT_OTHER";
    byte[] nonce=fromHex(nonceHex);
    try(Socket client=new Socket()) {
      client.setSoTimeout(DEADLINE_MS);
      try {client.connect(new InetSocketAddress(LOCAL,port),DEADLINE_MS);}
      catch(IOException | SecurityException error){return failure("CONNECT",error);}
      try {
        client.getOutputStream().write(nonce);
        client.getOutputStream().flush();
        byte[] actual=new byte[ACK.length];int n=0;
        while(n<actual.length){int k=client.getInputStream().read(actual,n,actual.length-n);
          if(k<0)return "ECHO_OTHER";n+=k;}
        return Arrays.equals(ACK,actual)?"PASS":"ECHO_OTHER";
      }catch(IOException | SecurityException error){return failure("ECHO",error);}
    }catch(IOException | SecurityException error){return failure("CONNECT",error);}
  }
  /** Local JVM self-check; DOES NOT infer host-to-isolated Android capability. */
  public static String probeSelf() {
    try(Listener server=bind()) {
      AtomicReference<String> clientResult=new AtomicReference<>("CONNECT_OTHER");
      Thread client=new Thread(()->clientResult.set(connect(server.port(),server.nonceHex())),
                               "p187-self-loopback-client");
      client.setDaemon(true);client.start();
      String accepted=server.acceptOnce();
      try{client.join(DEADLINE_MS+300L);}catch(InterruptedException interrupted){
        Thread.currentThread().interrupt();return "ECHO_OTHER";}
      return "PASS".equals(accepted)&&"PASS".equals(clientResult.get()) ?
          "PASS" : !"PASS".equals(accepted)?accepted:clientResult.get();
    }catch(IOException | SecurityException error){return failure("BIND",error);}
  }
}
