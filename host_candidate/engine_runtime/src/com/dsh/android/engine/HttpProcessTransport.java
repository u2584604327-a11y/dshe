package com.dsh.android.engine;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Host-owned loopback listener and bounded stdio transport for one already
 * authenticated isolated Process. No launcher, destination URL, arbitrary
 * forwarding, production authorization or READY assertion. Package-private
 * construction until the production launch lease and owner are installed.
 */
final class HttpProcessTransport extends Process implements Closeable {
  static final int CHUNK=16384, WINDOW=65536, MAX_CONNECTIONS=16;
  // Signed v138 EngineManager.resolveWebPort() probes this port. The main
  // worker independently resolves the default from the sealed web bundle.
  static final int ORIGINAL_WEB_DEFAULT_PORT=3080;
  private static final int OMITTED_MAIN_PORT=65536;
  private static final int APPROVED_WORKSPACE_OVERLAY=131072;
  private static final int APPROVED_BROWSER_OVERLAY=262144;
  private static final int APPROVED_MOBILE_OVERLAY=524288;
  private static final int CLIENT_PLUGIN_DATA=15;
  static final int OPEN=1, DATA=2, END=3, CLOSE=4, ACK=5,
      APP_DATA=6, APP_END=7, LOG_ACK=8, SHUTDOWN=9, LOG_CLOSE=10;
  static final int LISTEN=16, RESPONSE=17, RESPONSE_END=18, RESPONSE_CLOSE=19,
      REQUEST_ACK=20, LOG=21, STOP=22, APP_ACK=24, FINISH=25;
  private final Process child;
  private final DurableSessionSnapshot profileStore;
  private final OriginalClientPlugin mobilePlugin, browserPlugin;
  private final Object snapshotLock=new Object();
  private byte[] snapshotIncoming,snapshotExpectedHash;
  private int snapshotOffset,snapshotTransaction;
  private long snapshotExpectedVersion,snapshotDeadline;
  private volatile boolean snapshotInitializationQueued;
  private static final int FS_INIT_BEGIN=11,FS_INIT_DATA=12,FS_INIT_END=13,FS_ACK=14,
      FS_BEGIN=26,FS_DATA=27,FS_COMMIT=28;
  private final ServerSocket listener=new ServerSocket();
  private final byte[] key=new byte[32],session,epochBytes;
  private final DataInputStream input;
  private final DataOutputStream output;
  private final boolean mergedError;
  private final Object appInputLock=new Object();
  private final AtomicBoolean closed=new AtomicBoolean(),accepting=new AtomicBoolean();
  private final AtomicBoolean stdinOpen=new AtomicBoolean(true),peerFinished=new AtomicBoolean();
  private final AtomicBoolean peerEof=new AtomicBoolean();
  private final AtomicInteger allocated=new AtomicInteger();
  private final ConcurrentHashMap<Integer,Peer> peers=new ConcurrentHashMap<>();
  private final ArrayBlockingQueue<Frame> writes=new ArrayBlockingQueue<>(256);
  private final Credit appCredit=new Credit();
  private final LogSink[] logs={new LogSink(0),new LogSink(1)};
  private final ScheduledExecutorService deadlines=Executors.newSingleThreadScheduledExecutor(daemonFactory("dsh-http-deadline"));
  private final CountDownLatch listened=new CountDownLatch(1),nativeErrorDone=new CountDownLatch(1);
  private final CountDownLatch cleanupDone=new CountDownLatch(1);
  private long sending,received;
  private volatile String failure="NONE",peerFault="NONE";
  private volatile boolean listenSeen;
  private final AtomicBoolean stopping=new AtomicBoolean();
  private final AtomicReference<OriginalMainStartup.ReadyProof> readyProof=new AtomicReference<>();
  private final AtomicBoolean mainOutputClaimed=new AtomicBoolean();
  private volatile InputStream verifiedMainOutput;
  private static final class Frame {
    final int type,id;final byte[] data;
    Frame(int type,int id,byte[] data){this.type=type;this.id=id;this.data=data;}
  }
  private static ThreadFactory daemonFactory(String name){return task->{Thread t=new Thread(task,name);t.setDaemon(true);return t;};}
  private static void thread(String name,Runnable task){daemonFactory(name).newThread(task).start();}
  private static byte[] integer(int value){return ByteBuffer.allocate(4).putInt(value).array();}
  private static int integer(byte[] data)throws IOException{
    if(data.length!=4)throw new IOException("INVALID_CREDIT");return ByteBuffer.wrap(data).getInt();
  }
  HttpProcessTransport(Process authenticatedChild,String hostSession,long ownerEpoch,int requestedPort)throws IOException{
    this(authenticatedChild,hostSession,ownerEpoch,requestedPort,false);
  }
  HttpProcessTransport(Process authenticatedChild,String hostSession,long ownerEpoch,int requestedPort,boolean mergedError)throws IOException{
    this(authenticatedChild,hostSession,ownerEpoch,requestedPort,mergedError,null);
  }
  /** Match the original Android precheck. An actual bind race still denies. */
  static Integer originalWebPortOption()throws IOException{
    try(ServerSocket probe=new ServerSocket()){
      probe.bind(loopback(ORIGINAL_WEB_DEFAULT_PORT),1);
      return null;
    }catch(BindException occupied){return 0;}
  }
  private static InetSocketAddress loopback(int port)throws UnknownHostException{
    return new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port);
  }
  /** Only a trusted receipt/owner factory may provide this directory capability.
   * A null option preserves an omitted --port in the original web main. */
  HttpProcessTransport(Process authenticatedChild,String hostSession,long ownerEpoch,Integer requestedPort,boolean mergedError,DurableSessionSnapshot profileStore)throws IOException{
    this(authenticatedChild,hostSession,ownerEpoch,requestedPort,mergedError,profileStore,null);
  }
  static HttpProcessTransport forOriginalWebLaunch(Process child,String session,long epoch,
      OriginalWebLaunch launch,DurableSessionSnapshot store)throws IOException{
    if(launch==null||store==null)throw new IOException("MAIN_LAUNCH_CAPABILITY_REQUIRED");
    return new HttpProcessTransport(child,session,epoch,launch.port(),true,store,launch);
  }
  private HttpProcessTransport(Process authenticatedChild,String hostSession,long ownerEpoch,Integer requestedPort,
      boolean mergedError,DurableSessionSnapshot profileStore,OriginalWebLaunch launch)throws IOException{
    if(authenticatedChild==null||!authenticatedChild.isAlive()||hostSession==null||
       !hostSession.matches("[0-9a-f]{64}")||ownerEpoch<=0||
       (requestedPort==null?profileStore==null:requestedPort<0||requestedPort>65535))
      throw new IOException("AUTHENTICATED_RUNTIME_REQUIRED");
    child=authenticatedChild;this.profileStore=profileStore;this.mergedError=mergedError;
    mobilePlugin=launch==null?null:launch.mobile;browserPlugin=launch==null?null:launch.browser;
    session=new byte[32];for(int i=0;i<32;i++)session[i]=(byte)Integer.parseInt(hostSession.substring(i*2,i*2+2),16);
    epochBytes=ByteBuffer.allocate(8).putLong(ownerEpoch).array();
    new SecureRandom().nextBytes(key);
    input=new DataInputStream(child.getInputStream());output=new DataOutputStream(child.getOutputStream());
    try{
      // Port 0 asks the kernel. An omitted flag binds the verified original
      // default without replacing that flag with an explicit value.
      listener.setReuseAddress(true);
      listener.bind(loopback(requestedPort==null?ORIGINAL_WEB_DEFAULT_PORT:requestedPort),16);
      output.writeBytes("DSHHTTP1");output.write(key);output.write(session);output.write(epochBytes);
      int wirePort=requestedPort==null?OMITTED_MAIN_PORT:requestedPort;
      if(launch!=null)wirePort|=APPROVED_WORKSPACE_OVERLAY|APPROVED_BROWSER_OVERLAY|APPROVED_MOBILE_OVERLAY;
      output.writeInt(wirePort);output.writeInt(listener.getLocalPort());output.flush();
      // Register deadlines before any reader can observe immediate child exit
      // and close this executor. Fast startup failure is a valid Process exit.
      deadlines.schedule(()->{if(!listenSeen)fail("LISTEN_DEADLINE");},90,TimeUnit.SECONDS);
      deadlines.scheduleWithFixedDelay(()->{
        long now=System.nanoTime();for(Peer peer:peers.values())if(peer.writeStarted>0&&now-peer.writeStarted>TimeUnit.SECONDS.toNanos(60))peer.close(true);
        synchronized(snapshotLock){if(snapshotIncoming!=null&&now-snapshotDeadline>=0)fail("STORE_WIRE_TIMEOUT");}
      },1,1,TimeUnit.SECONDS);
      thread("dsh-app-stdout",()->logs[0].run());if(!mergedError)thread("dsh-app-stderr",()->logs[1].run());
      thread("dsh-http-frame-writer",this::writeFrames);
      thread("dsh-http-frame-reader",this::readFrames);
      if(profileStore!=null)thread("dsh-owner-snapshot-initialization",this::sendInitialSnapshot);
      thread("dsh-http-child-stderr",()->{
        try(InputStream err=child.getErrorStream()){
          // Unframed native diagnostics are not application output or authority.
          // Drain a bounded amount to avoid a startup deadlock, then revoke.
          byte[] block=new byte[4096];int total=0,n;ByteArrayOutputStream diagnostic=new ByteArrayOutputStream();
          while((n=err.read(block))!=-1){total+=n;if(total>65536)throw new IOException("NATIVE_STDERR_BOUND");diagnostic.write(block,0,n);log(1).accept(Arrays.copyOf(block,n),1,false);
            String text=diagnostic.toString("US-ASCII");for(String line:text.split("\n"))if(line.matches("DSH_RUNTIME_TRANSPORT_DENY=[A-Z0-9_]{1,64}"))peerFault=line.substring(27);}
        }catch(IOException bad){if(!closed.get()&&!log(1).discarded.get())fail("NATIVE_STDERR");}
        finally{nativeErrorDone.countDown();}
      });
      thread("dsh-http-process-exit",()->{try{child.waitFor();stopListener();}catch(InterruptedException e){Thread.currentThread().interrupt();fail("WAIT_INTERRUPTED");}});

    }catch(IOException|RuntimeException error){close();throw error;}
  }
  int port(){return listener.getLocalPort();}
  OriginalClientPlugin mobilePlugin(){return mobilePlugin;}
  OriginalClientPlugin browserPlugin(){return browserPlugin;}
  boolean ownsListener(int port){
    return port>0&&port==port()&&accepting.get()&&!stopping.get()&&!closed.get()&&child.isAlive();
  }
  InputStream claimMainStartupOutput()throws IOException{
    if(!mainOutputClaimed.compareAndSet(false,true))throw new IOException("MAIN_STARTUP_OUTPUT_ALREADY_CLAIMED");
    return logs[0].reader;
  }
  synchronized void attachReadyProof(OriginalMainStartup.ReadyProof proof,InputStream output)throws IOException{
    if(!mainOutputClaimed.get()||verifiedMainOutput!=null||!proof.isCurrent(this)||!readyProof.compareAndSet(null,proof))
      throw new IOException("MAIN_READY_PROOF_NOT_CURRENT");
    if(!proof.isCurrent(this)){
      readyProof.compareAndSet(proof,null);
      throw new IOException("MAIN_READY_PROOF_NOT_CURRENT");
    }
    verifiedMainOutput=output;
  }
  boolean hasVerifiedReadyUrl(String url){
    OriginalMainStartup.ReadyProof proof=readyProof.get();
    return proof!=null&&proof.matches(this,url)&&readyProof.get()==proof;
  }
  boolean hasCurrentReadyProof(){
    OriginalMainStartup.ReadyProof proof=readyProof.get();
    return proof!=null&&proof.isCurrent(this)&&readyProof.get()==proof;
  }
  String failure(){return failure+"/"+peerFault;}
  boolean awaitListening(long timeout,TimeUnit unit)throws InterruptedException{return listened.await(timeout,unit)&&accepting.get()&&!closed.get();}
  /** A new owner must wait for resource disposal, not merely OS child exit. */
  boolean awaitClosed(long timeout,TimeUnit unit)throws InterruptedException{return cleanupDone.await(timeout,unit);}
  private byte[] mac(byte direction,byte[] header,byte[] data)throws GeneralSecurityException{
    Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));
    mac.update(direction);mac.update(session);mac.update(epochBytes);mac.update(header);return mac.doFinal(data);
  }
  private void send(int type,int id,byte[] data)throws IOException{
    if(closed.get()||peerFinished.get()||peerEof.get()||data.length>CHUNK||!writes.offer(new Frame(type,id,data)))throw new IOException("TRANSPORT_CLOSED_OR_BOUND");
  }
  private void sendOrFail(int type,int id,byte[] data){if(peerFinished.get()||peerEof.get())return;try{send(type,id,data);}catch(IOException e){if(!peerFinished.get()&&!peerEof.get())fail("WRITE_QUEUE");}}
  private void writeFrames(){
    try{
      while(!closed.get()&&!peerEof.get()){
        Frame frame=writes.poll(1,TimeUnit.SECONDS);if(frame==null)continue;if(peerFinished.get())return;
        if(sending==Long.MAX_VALUE)throw new IOException("SEQUENCE_EXHAUSTED");
        byte[] header=ByteBuffer.allocate(21).putInt(0x44484631).put((byte)frame.type).putLong(++sending).putInt(frame.id).putInt(frame.data.length).array();
        try{output.write(header);output.write(mac((byte)'H',header,frame.data));output.write(frame.data);output.flush();}
        finally{if(frame.type==FS_INIT_DATA)Arrays.fill(frame.data,(byte)0);}
      }
    }catch(Exception error){if(!closed.get()&&!peerFinished.get()&&!peerEof.get())fail("WRITE_TRANSPORT");}
  }
  private void readFrames(){
    try{
      while(!closed.get()){
        byte[] header=new byte[21],signature=new byte[32];input.readFully(header);input.readFully(signature);
        ByteBuffer fields=ByteBuffer.wrap(header);
        if(fields.getInt()!=0x44484631)throw new IOException("FRAME_MAGIC");
        int type=fields.get()&255;long seq=fields.getLong();int id=fields.getInt(),length=fields.getInt();
        if(seq<=0||seq!=received+1||received==Long.MAX_VALUE||id<0||length<0||length>CHUNK)throw new IOException("FRAME_SHAPE");
        byte[] data=new byte[length];input.readFully(data);
        if(!MessageDigest.isEqual(signature,mac((byte)'N',header,data)))throw new IOException("FRAME_AUTH");
        if(peerFinished.get())throw new IOException("FRAME_AFTER_FINISH");
        received=seq;
        if(type==FS_BEGIN||type==FS_DATA||type==FS_COMMIT){try{receiveSnapshot(type,id,data);}finally{Arrays.fill(data,(byte)0);}continue;}
        if(type==LISTEN){
          if(id!=0||length!=4||integer(data)!=port()||listenSeen||stopping.get()||!accepting.compareAndSet(false,true))throw new IOException("LISTEN_REPLAY");
          listenSeen=true;listened.countDown();thread("dsh-http-accept",this::accept);continue;
        }
        if(type==LOG){if(id>1||length==0)throw new IOException("LOG_SHAPE");log(id).accept(data,id,true);continue;}
        if(type==APP_ACK){if(id!=0)throw new IOException("STDIN_CREDIT_ID");credit(appCredit,data);continue;}
        if(type==STOP){if(id!=0||length!=0)throw new IOException("STOP_SHAPE");stopListener();continue;}
        if(type==FINISH){
          if(id!=0||length!=0)throw new IOException("FINISH_SHAPE");
          peerFinished.set(true);stopListener();stdinOpen.set(false);appCredit.revoke();discardFrames();
          // Authenticated final frame follows application-log acknowledgments.
          // Release upstream stdin before the isolated supervisor drains pipes
          // and publishes the actual child exit. No writes race that closure.
          try{output.close();}catch(IOException ignored){}
          continue;
        }
        if(type!=RESPONSE&&type!=RESPONSE_END&&type!=RESPONSE_CLOSE&&type!=REQUEST_ACK)throw new IOException("FRAME_TYPE");
        if(!listenSeen||id==0||id>allocated.get())throw new IOException("CONNECTION_ID");
        Peer peer=peers.get(id);if(peer==null)continue; // late traffic for a closed, never-reused id
        if(type==RESPONSE)peer.receive(data);
        else if(type==REQUEST_ACK)credit(peer.credit,data);
        else {if(length!=0)throw new IOException("TERMINAL_PAYLOAD");if(type==RESPONSE_END)peer.end();else if(!peer.ending)peer.close(false);}
      }
    }catch(EOFException ended){
      peerEof.set(true);stopListener();stdinOpen.set(false);appCredit.revoke();discardFrames();
      // Closing a buffered pipe can itself block behind a stalled writer.
      // Keep a separate cancellation deadline alive while releasing it.
      ScheduledFuture<?> eofDeadline;
      try{eofDeadline=deadlines.schedule(()->{if(child.isAlive())fail("PREMATURE_EOF");else close();},2,TimeUnit.SECONDS);}
      catch(RejectedExecutionException disposed){return;}
      // EOF releases this exact producer before waiting for the authenticated
      // supervisor's EXIT. Otherwise its pipe drain can wait on this writer.
      try{output.close();}catch(IOException ignored){}
      try{if(child.waitFor(2,TimeUnit.SECONDS)){nativeErrorDone.await(2,TimeUnit.SECONDS);close();}else fail("PREMATURE_EOF");}
      catch(InterruptedException interrupted){Thread.currentThread().interrupt();fail("WAIT_INTERRUPTED");}
      finally{eofDeadline.cancel(false);}
    }catch(Exception error){if(!closed.get())fail(error instanceof IOException&&error.getMessage()!=null&&error.getMessage().matches("[A-Z_]{1,64}")?error.getMessage():"READ_PROTOCOL");}
  }
  private void sendOwnedFrame(int type,int id,byte[] data,long deadline)throws IOException{
    try{
      while(!closed.get()&&!peerFinished.get()&&!peerEof.get()){
        long remaining=deadline-System.nanoTime();if(remaining<=0)throw new IOException("STORE_WIRE_TIMEOUT");
        if(writes.offer(new Frame(type,id,data),Math.min(100,Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining))),TimeUnit.MILLISECONDS))return;
      }
      throw new IOException("STORE_WIRE_CLOSED");
    }catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new InterruptedIOException("STORE_WIRE_INTERRUPTED");}
  }
  private void sendClientPlugin(int slot,OriginalClientPlugin plugin,long deadline)throws IOException{
    byte[] capsule=plugin.framedBytes();
    for(int offset=0;offset<capsule.length;offset+=CHUNK)
      sendOwnedFrame(CLIENT_PLUGIN_DATA,slot,Arrays.copyOfRange(capsule,offset,Math.min(offset+CHUNK,capsule.length)),deadline);
  }
  private void sendInitialSnapshot(){
    DurableSessionSnapshot.State state=null;
    try{
      state=profileStore.read();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
      if(mobilePlugin!=null){
        sendClientPlugin(1,mobilePlugin,deadline);
        sendClientPlugin(0,browserPlugin,deadline);
      }
      byte[] hash=MessageDigest.getInstance("SHA-256").digest(state.bytes);
      sendOwnedFrame(FS_INIT_BEGIN,0,ByteBuffer.allocate(44).putLong(state.version).putInt(state.bytes.length).put(hash).array(),deadline);
      for(int offset=0;offset<state.bytes.length;offset+=CHUNK)
        sendOwnedFrame(FS_INIT_DATA,0,Arrays.copyOfRange(state.bytes,offset,Math.min(offset+CHUNK,state.bytes.length)),deadline);
      synchronized(snapshotLock){sendOwnedFrame(FS_INIT_END,0,new byte[0],deadline);snapshotInitializationQueued=true;}
    }catch(Exception failure){if(!closed.get()&&!peerEof.get())fail("STORE_INITIALIZATION");}
    finally{if(state!=null)Arrays.fill(state.bytes,(byte)0);}
  }
  private void receiveSnapshot(int type,int id,byte[] data)throws IOException{
    synchronized(snapshotLock){
      // Graceful stop closes public admission immediately, but the exact old
      // owner may flush its shutdown state until EXIT/forced revocation. A new
      // generation cannot acquire this root before awaitClosed completes.
      if(profileStore==null||closed.get()||peerEof.get()||!snapshotInitializationQueued)throw new IOException("STORE_WIRE_NOT_AUTHORIZED");
      if(type==FS_BEGIN){
        if(snapshotIncoming!=null||snapshotTransaction==Integer.MAX_VALUE||id!=snapshotTransaction+1||data.length!=44)throw new IOException("STORE_WIRE_BEGIN");
        ByteBuffer meta=ByteBuffer.wrap(data);long expected=meta.getLong();int size=meta.getInt();
        if(expected<0||size<12||size>SessionSnapshotCodec.MAX_BYTES)throw new IOException("STORE_WIRE_BOUND");
        snapshotTransaction=id;snapshotExpectedVersion=expected;snapshotIncoming=new byte[size];snapshotOffset=0;
        snapshotExpectedHash=new byte[32];meta.get(snapshotExpectedHash);snapshotDeadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);return;
      }
      if(snapshotIncoming==null||id!=snapshotTransaction||System.nanoTime()-snapshotDeadline>=0)throw new IOException("STORE_WIRE_TRANSACTION");
      if(type==FS_DATA){if(data.length==0||data.length>snapshotIncoming.length-snapshotOffset)throw new IOException("STORE_WIRE_DATA");
        System.arraycopy(data,0,snapshotIncoming,snapshotOffset,data.length);snapshotOffset+=data.length;return;}
      if(type!=FS_COMMIT||data.length!=0||snapshotOffset!=snapshotIncoming.length)throw new IOException("STORE_WIRE_COMMIT");
      try{
        if(!MessageDigest.isEqual(snapshotExpectedHash,MessageDigest.getInstance("SHA-256").digest(snapshotIncoming)))throw new IOException("STORE_WIRE_SEAL");
        long next=profileStore.commit(snapshotExpectedVersion,snapshotIncoming);
        sendOwnedFrame(FS_ACK,id,ByteBuffer.allocate(9).putLong(next).put((byte)0).array(),snapshotDeadline);
      }catch(GeneralSecurityException unavailable){throw new IOException("STORE_SHA_UNAVAILABLE");}
      finally{Arrays.fill(snapshotIncoming,(byte)0);snapshotIncoming=null;Arrays.fill(snapshotExpectedHash,(byte)0);snapshotExpectedHash=null;}
    }
  }
  /** Count only bytes actually submitted, not a reservation for a blocked
   * socket read. A compromised peer cannot manufacture credit for unsent data. */
  private static final class Credit {
    int available=WINDOW,outstanding;boolean revoked;
    synchronized void reserve(int n)throws IOException,InterruptedException{
      while(!revoked&&available<n)wait();if(revoked)throw new IOException("CREDIT_REVOKED");available-=n;
    }
    synchronized void submitted(int reservation,int bytes)throws IOException{
      if(bytes<0||bytes>reservation||outstanding>WINDOW-bytes)throw new IOException("CREDIT_ACCOUNTING");
      available+=reservation-bytes;outstanding+=bytes;notifyAll();
    }
    synchronized void acknowledge(int n)throws IOException{
      if(n<=0||n>outstanding)throw new IOException("CREDIT_OVERFLOW");outstanding-=n;available+=n;notifyAll();
    }
    synchronized void revoke(){revoked=true;notifyAll();}
  }
  private static void credit(Credit credit,byte[] data)throws IOException{credit.acknowledge(integer(data));}
  private void accept(){
    try{
      while(!closed.get()){
        Socket socket=listener.accept();
        if(!socket.getInetAddress().isLoopbackAddress()||peers.size()>=MAX_CONNECTIONS){socket.close();continue;}
        socket.setTcpNoDelay(true);socket.setSoTimeout(0); // Original HTTP header/request timers own idle/SSE policy.
        int id=allocated.incrementAndGet();if(id<=0){socket.close();throw new IOException("ID_EXHAUSTED");}
        Peer peer=new Peer(id,socket);peers.put(id,peer);
        byte[] address=socket.getInetAddress().getAddress();
        if(address.length!=4){peer.close(false);throw new IOException("PEER_FAMILY");}
        send(OPEN,id,ByteBuffer.allocate(8).put(address).putInt(socket.getPort()).array());peer.start();
      }
    }catch(IOException error){if(!closed.get()&&accepting.get())fail("ACCEPT");}
  }
  private final class Peer {
    final int id;final Socket socket;final Credit credit=new Credit();
    final ArrayBlockingQueue<byte[]> pending=new ArrayBlockingQueue<>(16);
    final AtomicBoolean done=new AtomicBoolean();
    volatile long progress=System.nanoTime(),writeStarted;
    int buffered;boolean ending;
    Peer(int id,Socket socket){this.id=id;this.socket=socket;}
    synchronized void receive(byte[] data)throws IOException{
      if(ending||data.length==0||data.length>WINDOW-buffered||!pending.offer(data))throw new IOException("RESPONSE_BOUND");buffered+=data.length;
    }
    synchronized void end()throws IOException{
      if(ending||!pending.offer(new byte[0]))throw new IOException("RESPONSE_END");ending=true;
    }
    void start(){thread("dsh-http-request",()->{
      try{InputStream in=socket.getInputStream();while(!done.get()){
        credit.reserve(CHUNK);if(done.get())break;
        byte[] block=new byte[CHUNK];int n=in.read(block);
        credit.submitted(CHUNK,Math.max(0,n));
        if(n==-1){send(END,id,new byte[0]);break;}
        if(n>0){progress=System.nanoTime();send(DATA,id,Arrays.copyOf(block,n));}
      }}catch(Exception error){close(true);}
    });thread("dsh-http-response",()->{
      try{OutputStream out=socket.getOutputStream();while(!done.get()){
        byte[] block=pending.poll(1,TimeUnit.SECONDS);if(block==null)continue;
        if(block.length==0){socket.shutdownOutput();close(false);break;}
        writeStarted=System.nanoTime();out.write(block);out.flush();progress=System.nanoTime();writeStarted=0;
        synchronized(this){buffered-=block.length;}send(ACK,id,integer(block.length));
      }}catch(Exception error){close(true);}
    });}
    void close(boolean notify){
      if(!done.compareAndSet(false,true))return;peers.remove(id,this);pending.clear();credit.revoke();
      try{socket.close();}catch(IOException ignored){}
      if(notify&&!closed.get())sendOrFail(CLOSE,id,new byte[0]);
    }
  }
  private LogSink log(int channel){return logs[mergedError?0:channel];}
  private static final class LogPart {
    final byte[] data;final int channel;final boolean credit;
    LogPart(byte[] data,int channel,boolean credit){this.data=data;this.channel=channel;this.credit=credit;}
  }
  /** Bounded log buffer whose lifetime does not depend on its reader thread. */
  private class LogPipe extends InputStream {
    private final byte[] bytes=new byte[WINDOW];
    private int head,size;
    private boolean inputClosed,outputClosed;

    private void awaitChange()throws InterruptedIOException{
      try{wait();}catch(InterruptedException interrupted){
        Thread.currentThread().interrupt();throw new InterruptedIOException("LOG_PIPE_INTERRUPTED");
      }
    }
    private boolean readable()throws IOException{
      while(size==0&&!inputClosed&&!outputClosed)awaitChange();
      if(inputClosed)throw new IOException("LOG_PIPE_INPUT_CLOSED");
      return size!=0;
    }
    @Override public synchronized int read()throws IOException{
      if(!readable())return -1;
      int value=bytes[head]&255;
      consume(1);
      return value;
    }
    @Override public synchronized int read(byte[] target,int offset,int length)throws IOException{
      Objects.requireNonNull(target);
      if(offset<0||length<0||offset>target.length-length)throw new IndexOutOfBoundsException();
      if(length==0)return 0;
      if(!readable())return -1;
      int count=Math.min(length,size),first=Math.min(count,bytes.length-head);
      System.arraycopy(bytes,head,target,offset,first);
      System.arraycopy(bytes,0,target,offset+first,count-first);
      consume(count);
      return count;
    }
    @Override public synchronized int available(){return size;}
    private void consume(int count){
      int first=Math.min(count,bytes.length-head);
      Arrays.fill(bytes,head,head+first,(byte)0);
      Arrays.fill(bytes,0,count-first,(byte)0);
      head=(head+count)%bytes.length;size-=count;notifyAll();
    }
    synchronized void write(byte[] source)throws IOException{
      int offset=0;
      while(offset<source.length){
        while(size==bytes.length&&!inputClosed&&!closed.get())awaitChange();
        if(inputClosed||size==bytes.length)throw new IOException("LOG_PIPE_DISPOSED");
        int end=(head+size)%bytes.length;
        int count=Math.min(source.length-offset,bytes.length-size),first=Math.min(count,bytes.length-end);
        System.arraycopy(source,offset,bytes,end,first);
        System.arraycopy(source,offset+first,bytes,0,count-first);
        size+=count;offset+=count;notifyAll();
      }
    }
    synchronized void finish(){outputClosed=true;notifyAll();}
    synchronized void wakeWriter(){notifyAll();}
    @Override public synchronized void close()throws IOException{
      inputClosed=true;Arrays.fill(bytes,(byte)0);size=0;notifyAll();
    }
  }
  private final class LogSink {
    final int channel;final AtomicBoolean discarded=new AtomicBoolean();
    final LogPipe reader=new LogPipe(){
      @Override public void close()throws IOException{
        super.close();if(!discarded.compareAndSet(false,true))return;
        synchronized(LogSink.this){pending.clear();buffered=0;}
        if(!HttpProcessTransport.this.closed.get()){
          sendOrFail(LOG_CLOSE,channel,new byte[0]);
          if(mergedError&&channel==0)sendOrFail(LOG_CLOSE,1,new byte[0]);
          if(channel==1||mergedError)child.getErrorStream().close();
        }
      }
    };
    final ArrayBlockingQueue<LogPart> pending=new ArrayBlockingQueue<>(16);
    int buffered;
    LogSink(int channel){this.channel=channel;}
    synchronized void accept(byte[] data,int channel,boolean credit)throws IOException{
      if(discarded.get())return;
      if(data.length>(mergedError?2*WINDOW:WINDOW)-buffered||!pending.offer(new LogPart(data,channel,credit)))throw new IOException("LOG_BOUND");buffered+=data.length;
    }
    void run(){
      try{while(true){LogPart part=pending.poll(1,TimeUnit.SECONDS);if(part==null){if(closed.get()&&nativeErrorDone.getCount()==0)break;continue;}
        reader.write(part.data);synchronized(this){if(!discarded.get())buffered-=part.data.length;}
        if(part.credit&&!closed.get()&&!discarded.get()&&!peerFinished.get())send(LOG_ACK,part.channel,integer(part.data.length));
      }}catch(Exception bad){if(!closed.get()&&!discarded.get())fail("LOG_CONSUMER");}
      finally{reader.finish();}
    }
  }
  private final OutputStream applicationInput=new OutputStream(){
    @Override public void write(int value)throws IOException{write(new byte[]{(byte)value});}
    @Override public synchronized void write(byte[] data,int offset,int length)throws IOException{
      if(data==null)throw new NullPointerException();if(offset<0||length<0||offset>data.length-length)throw new IndexOutOfBoundsException();
      while(length>0){if(closed.get()||!stdinOpen.get())throw new IOException("STDIN_CLOSED");int n=Math.min(CHUNK,length);
        try{appCredit.reserve(n);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new InterruptedIOException("STDIN_INTERRUPTED");}
        synchronized(appInputLock){
          if(closed.get()||!stdinOpen.get())throw new IOException("STDIN_CLOSED");
          appCredit.submitted(n,n);send(APP_DATA,0,Arrays.copyOfRange(data,offset,offset+n));
        }offset+=n;length-=n;
      }
    }
    @Override public void close()throws IOException{synchronized(appInputLock){if(stdinOpen.compareAndSet(true,false)&&!closed.get()){appCredit.revoke();send(APP_END,0,new byte[0]);}}}
  };
  synchronized void revokeReady(){
    stopping.set(true);accepting.set(false);readyProof.set(null);
  }
  private void stopListener(){
    revokeReady();
    try{listener.close();}catch(IOException ignored){}
    for(Peer peer:peers.values())peer.close(false);
  }
  private void fail(String category){synchronized(this){if(closed.get()||!failure.equals("NONE"))return;failure=category;}close();}
  private void discardFrames(){Frame frame;while((frame=writes.poll())!=null)if(frame.type==FS_INIT_DATA)Arrays.fill(frame.data,(byte)0);}
  @Override public void close(){
    synchronized(this){
      if(!closed.compareAndSet(false,true))return;
      accepting.set(false);readyProof.set(null);
    }
    try{
    listened.countDown();stdinOpen.set(false);appCredit.revoke();
    for(LogSink sink:logs)sink.reader.wakeWriter();
    deadlines.shutdownNow();try{listener.close();}catch(IOException ignored){}
    for(Peer peer:peers.values())peer.close(false);discardFrames();
    // Closing the authenticated Process owns cancellation of blocked native I/O.
    try{if(child.isAlive())child.destroyForcibly();}catch(RuntimeException cancellation){if(failure.equals("NONE"))failure="CHILD_CANCELLATION";}
    try{child.getOutputStream().close();}catch(IOException|RuntimeException ignored){}
    try{input.close();}catch(IOException|RuntimeException ignored){}
    synchronized(snapshotLock){
      if(snapshotIncoming!=null){Arrays.fill(snapshotIncoming,(byte)0);snapshotIncoming=null;}
      if(snapshotExpectedHash!=null){Arrays.fill(snapshotExpectedHash,(byte)0);snapshotExpectedHash=null;}
      if(profileStore!=null)try{profileStore.close();}catch(IOException failure){if(this.failure.equals("NONE"))this.failure="STORE_CLOSE";}
    }
    Arrays.fill(key,(byte)0);
    }finally{cleanupDone.countDown();}
  }
  @Override public OutputStream getOutputStream(){return applicationInput;}
  @Override public InputStream getInputStream(){
    if(!mainOutputClaimed.get())return logs[0].reader;
    InputStream ready=verifiedMainOutput;
    return ready==null?new ByteArrayInputStream(new byte[0]):ready;
  }
  @Override public InputStream getErrorStream(){return mergedError?new ByteArrayInputStream(new byte[0]):logs[1].reader;}
  @Override public int waitFor()throws InterruptedException{return child.waitFor();}
  @Override public boolean waitFor(long timeout,TimeUnit unit)throws InterruptedException{return child.waitFor(timeout,unit);}
  @Override public int exitValue(){return child.exitValue();}
  @Override public boolean isAlive(){return child.isAlive();}
  @Override public void destroy(){
    synchronized(this){if(closed.get()||peerFinished.get()||!stopping.compareAndSet(false,true))return;}
    stopListener();stdinOpen.set(false);appCredit.revoke();
    sendOrFail(SHUTDOWN,0,new byte[0]);
    try{deadlines.schedule(()->{if(child.isAlive())close();},5,TimeUnit.SECONDS);}
    catch(RejectedExecutionException ended){if(child.isAlive())close();}
  }
  @Override public Process destroyForcibly(){close();return this;}
}
