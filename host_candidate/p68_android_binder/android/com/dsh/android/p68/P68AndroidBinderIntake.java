package com.dsh.android.p68;
import android.os.Bundle;
import android.os.Message;
import android.os.Parcel;
import android.os.Parcelable;
import com.dsh.android.p53.P53StartOrder;
import com.dsh.android.p67.P67AuthenticatedHandoff;
import com.dsh.p37.P37RemoteProcess;
import java.util.Set;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.system.ErrnoException;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Android framework sendingUid -> P67 ordered child-start -> P37 Process.
 * Test fixture only. HELLO never creates or hands out Process; no engine READY.
 */
public final class P68AndroidBinderIntake {
  /** Host-owned anonymous reliable pipes. Worker endpoints have one delivery. */
  public static final class HostPipes implements AutoCloseable {
    private final ParcelFileDescriptor[] ends;
    private final P37RemoteProcess.Stdio stdio;
    private boolean delivered;
    private boolean workerCopiesReleased,closed;

    private HostPipes(ParcelFileDescriptor[] descriptors) {
      // Each pair is [read, write], in stdin/stdout/stderr order.
      ends=descriptors;
      stdio=P37RemoteProcess.Stdio.split(
          new ParcelFileDescriptor.AutoCloseOutputStream(ends[1]),
          new ParcelFileDescriptor.AutoCloseInputStream(ends[2]),
          new ParcelFileDescriptor.AutoCloseInputStream(ends[4]));
    }
    public static HostPipes create() throws IOException {
      if(android.os.Process.isIsolated())
        throw new SecurityException("P68_HOST_PIPE_OWNER_REQUIRED");
      ParcelFileDescriptor[] ends=new ParcelFileDescriptor[6];
      try {
        for(int i=0;i<3;i++) {
          ParcelFileDescriptor[] pair=ParcelFileDescriptor.createReliablePipe();
          ends[2*i]=pair[0];
          ends[2*i+1]=pair[1];
        }
        return new HostPipes(ends);
      } catch(IOException|RuntimeException failure) {
        closeDescriptors(ends);
        throw failure;
      }
    }
    public synchronized Bundle workerBundle() {
      if(delivered)throw new IllegalStateException("P68_PIPE_DELIVERY_ALREADY_USED");
      delivered=true;
      Bundle bundle=new Bundle();
      bundle.putParcelable("stdin",ends[0]);
      bundle.putParcelable("stdout",ends[3]);
      bundle.putParcelable("stderr",ends[5]);
      return bundle;
    }
    /**
     * Call after Messenger.send. Ordinary close() would publish a premature
     * reliable-pipe status from this local copy, stealing/masking the actual
     * peer's EOF/error status. Release transferred ownership without a status.
     */
    public synchronized boolean closeWorkerCopies() {
      if(workerCopiesReleased)return !closed;
      workerCopiesReleased=true;
      if(!delivered){close();return false;}
      try{
        for(ParcelFileDescriptor fd:new ParcelFileDescriptor[] {ends[0],ends[3],ends[5]})
          releaseTransferredCopy(fd);
        return true;
      }catch(RuntimeException transferFailure){close();return false;}
    }
    @Override public synchronized void close() {
      delivered=true;closed=true;workerCopiesReleased=true;
      try {stdio.close();}catch(IOException ignored) { }
      closeDescriptors(ends);
    }
  }
  /** Public Parcel ownership semantics; no detachFd, hidden API or skipped checkError.
   * The throwaway Parcel owns a duplicate until recycle. RETURN_VALUE closes
   * the sender object without emitting a false peer status (AOSP Status.SILENCE).
   * The already-transferred receiver remains the sole protocol endpoint owner.
   */
  static void releaseTransferredCopy(ParcelFileDescriptor descriptor) {
    if(descriptor==null)return;
    Parcel parcel=Parcel.obtain();
    try{descriptor.writeToParcel(parcel,Parcelable.PARCELABLE_WRITE_RETURN_VALUE);}
    finally{parcel.recycle();}
  }

  /** Worker-side pipe adapter. The service authenticates the enclosing Message. */
  public static final class WorkerPipes implements AutoCloseable {
    private final ParcelFileDescriptor[] ends;
    private final InputStream stdinPipe;
    private final OutputStream stdoutPipe,stderrPipe;
    private final AtomicBoolean closed=new AtomicBoolean();
    private final AtomicBoolean failed=new AtomicBoolean();
    private final AtomicBoolean childEnded=new AtomicBoolean();
    private volatile StdinTermination stdinTermination=StdinTermination.PENDING;
    private Thread input,output,error;
    private Process child;
    private WorkerPipes(ParcelFileDescriptor[] descriptors) {
      ends=descriptors;
      stdinPipe=new ParcelFileDescriptor.AutoCloseInputStream(ends[0]);
      stdoutPipe=new ParcelFileDescriptor.AutoCloseOutputStream(ends[1]);
      stderrPipe=new ParcelFileDescriptor.AutoCloseOutputStream(ends[2]);
    }

    public static WorkerPipes receive(Bundle bundle, int frameworkSenderUid,
        int authenticatedHostUid) throws IOException {
      if(!android.os.Process.isIsolated() || authenticatedHostUid<0 ||
         frameworkSenderUid!=authenticatedHostUid ||
         frameworkSenderUid==android.os.Process.myUid())
        throw new SecurityException("P68_AUTHENTICATED_HOST_REQUIRED");
      ParcelFileDescriptor[] ends=new ParcelFileDescriptor[3];
      try {
        if(bundle==null)throw new IOException("P68_PIPE_BUNDLE_REQUIRED");
        bundle.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
        String[] names={"stdin","stdout","stderr"};
        for(int i=0;i<names.length;i++) {
          Object value=bundle.getParcelable(names[i]);
          if(!(value instanceof ParcelFileDescriptor))
            throw new IOException("P68_PIPE_DESCRIPTOR_REQUIRED");
          ends[i]=(ParcelFileDescriptor)value;
        }
        if(bundle.size()!=3)throw new IOException("P68_PIPE_BUNDLE_SHAPE");
        Set<String> identities=new HashSet<>();
        for(int i=0;i<ends.length;i++) {
          StructStat stat=Os.fstat(ends[i].getFileDescriptor());
          int access=Os.fcntlInt(ends[i].getFileDescriptor(),OsConstants.F_GETFL,0)
              &OsConstants.O_ACCMODE;
          if(!OsConstants.S_ISFIFO(stat.st_mode) ||
             access!=(i==0?OsConstants.O_RDONLY:OsConstants.O_WRONLY) ||
             !identities.add(stat.st_dev+"/"+stat.st_ino))
            throw new IOException("P68_DISTINCT_PIPE_DIRECTIONS_REQUIRED");
        }
        return new WorkerPipes(ends);
      } catch(Exception failure) {
        closeDescriptors(ends);
        throw new IOException("P68_WORKER_PIPES_REJECTED");
      }
    }
    /** Called only after the service actually creates its authorized child. */
    public synchronized void attach(Process startedChild) {
      if(child!=null || startedChild==null || closed.get())
        throw new IllegalStateException("P68_ONE_CHILD_PIPE_ATTACHMENT_REQUIRED");
      child=startedChild;
      input=forwardStdin(stdinPipe,child.getOutputStream(),()->{
        if(!closed.get()&&!childEnded.get()&&child.isAlive()){
          failed.set(true);child.destroyForcibly();
        }
      },termination->stdinTermination=termination);
      output=pumpOutput(child.getInputStream(),stdoutPipe,"dsh-child-stdout");
      error=pumpOutput(child.getErrorStream(),stderrPipe,"dsh-child-stderr");
    }
    public int stdinTerminationCode(){return stdinTermination.code;}
    public static String stdinTerminationName(int code){
      for(StdinTermination termination:StdinTermination.values())
        if(termination.code==code)return termination.name();
      return "UNREPORTED";
    }
    private Thread pumpOutput(InputStream source, OutputStream destination,String name) {
      Thread thread=new Thread(()->{
        try(InputStream in=source;OutputStream out=destination) {
          byte[] bytes=new byte[8192];
          int count;
          boolean discard=false;
          while((count=in.read(bytes))!=-1)if(count>0&&!discard) {
            try {out.write(bytes,0,count);}
            catch(IOException peerClosed) {
              if(!brokenPipe(peerClosed))throw peerClosed;
              // Closing a host reader releases its endpoint. Drain the child
              // output so that this local close doesn't terminate the child.
              discard=true;
            }
          }
        } catch(IOException failure) {
          if(!closed.get()) {
            failed.set(true);
            if(child.isAlive())child.destroyForcibly();
          }
        }
      },name);
      thread.setDaemon(true);
      thread.start();
      return thread;
    }
    private static boolean brokenPipe(Throwable failure) {
      for(int depth=0;failure!=null&&depth<8;depth++,failure=failure.getCause()) {
        if(failure instanceof ErrnoException &&
           ((ErrnoException)failure).errno==OsConstants.EPIPE)return true;
      }
      return false;
    }
    /** Stop stdin after child exit, then drain both output writers before EXIT. */
    public boolean finishAfterChildExit(long timeoutMillis) throws InterruptedException {
      if(timeoutMillis<=0 || child==null || child.isAlive())return false;
      childEnded.set(true);
      try {stdinPipe.close();}catch(IOException ignored) { }
      long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
      for(Thread thread:new Thread[] {input,output,error}) {
        long remaining=deadline-System.nanoTime();
        if(remaining<=0)return false;
        thread.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining)));
        if(thread.isAlive())return false;
      }
      return !failed.get()&&!closed.get();
    }
    @Override public void close() {
      closed.set(true);
      for(java.io.Closeable stream:new java.io.Closeable[] {stdinPipe,stdoutPipe,stderrPipe}) {
        try {stream.close();}catch(IOException ignored) { }
      }
    }
  }
  private enum StdinTermination {
    PENDING(0), HOST_EOF(1), HOST_READ_ERROR(2), CHILD_STDIN_CLOSED(3), CHILD_STDIN_IO(4);
    final int code;
    StdinTermination(int code){this.code=code;}
  }
  /**
   * A child may close stdin and keep running (including printing an error).
   * A failed write to child stdin closes the upstream reader so its producer
   * observes EPIPE; it must not kill the child or discard its eventual exit.
   * Only a failure reading the authenticated transport invokes onSourceFailure.
   */
  static Thread forwardStdin(InputStream source,OutputStream childInput,
      Runnable onSourceFailure) {
    return forwardStdin(source,childInput,onSourceFailure,ignored->{});
  }
  private static Thread forwardStdin(InputStream source,OutputStream childInput,
      Runnable onSourceFailure,Consumer<StdinTermination> terminal) {
    if(source==null||childInput==null||onSourceFailure==null)
      throw new IllegalArgumentException("P68_STDIN_STREAMS_REQUIRED");
    Thread thread=new Thread(()->{
      StdinTermination reason=StdinTermination.PENDING;
      try {
        byte[] bytes=new byte[8192];
        for(;;){
          final int count;
          try{count=source.read(bytes);}
          catch(IOException sourceLost){reason=StdinTermination.HOST_READ_ERROR;onSourceFailure.run();return;}
          if(count<0){reason=StdinTermination.HOST_EOF;return;}
          if(count==0)continue;
          // Process stdin can be buffered. A live interactive child must see
          // a short preface/frame before the producer sends more data or EOF.
          try{childInput.write(bytes,0,count);childInput.flush();}
          catch(IOException childClosedInput){
            reason=WorkerPipes.brokenPipe(childClosedInput)
                ?StdinTermination.CHILD_STDIN_CLOSED:StdinTermination.CHILD_STDIN_IO;
            return;
          }
        }
      }finally{
        terminal.accept(reason);
        try{source.close();}catch(IOException ignored){}
        try{childInput.close();}catch(IOException ignored){}
      }
    },"dsh-child-stdin");
    thread.setDaemon(true);thread.start();return thread;
  }
  private static void closeDescriptors(ParcelFileDescriptor[] descriptors) {
    for(ParcelFileDescriptor fd:descriptors)if(fd!=null) {
      try {fd.close();}catch(IOException ignored) { }
    }
  }
  public enum Result { HELLO, CHILD_STARTED, STDOUT, STDERR, EXIT, FAIL, REJECTED }
  private static final int MAX_FIXTURE_BYTES=128;
  private final String trustedSession;
  private final P37RemoteProcess.RemoteControl controls;
  private final boolean mergeErrorToOutput;
  private final long p184OwnerEpoch;
  private final P37RemoteProcess.Stdio ownedPipes;
  private P184ChildStartReceipt p184Receipt;
  private boolean p184Taken;
  private P67AuthenticatedHandoff handoff;
  private int isolatedUid=-1;
  private volatile boolean invalid;
  public P68AndroidBinderIntake(String hostGeneratedSession,
                                 P37RemoteProcess.RemoteControl stopControls) {
    this(hostGeneratedSession,stopControls,false,0L);
  }
  /** Trusted native host opt-in only; not inferred from worker IPC fields.
   * Existing P48/P51 constructs the two-argument split-stream variant.
   */
  public P68AndroidBinderIntake(String hostGeneratedSession,
                                 P37RemoteProcess.RemoteControl stopControls,
                                 boolean trustedHostRequestsMergedStderr) {
    this(hostGeneratedSession,stopControls,trustedHostRequestsMergedStderr,0L);
  }
  /**
   * Opt-in test path: native host owner generation only, not any worker
   * supplied value. Legacy fixture constructors deliberately issue NO receipt.
   */
  public P68AndroidBinderIntake(String hostGeneratedSession,
      P37RemoteProcess.RemoteControl stopControls,
      boolean trustedHostRequestsMergedStderr,long trustedHostOwnerEpoch) {
    this(hostGeneratedSession, stopControls, trustedHostRequestsMergedStderr,
         trustedHostOwnerEpoch, null);
  }
  /** Host-created endpoints and a positive host generation are required.
   * No descriptor, merge flag or generation is accepted from a worker Bundle.
   * Receipt issuance still follows the actual framework CHILD_STARTED event.
   */
  public P68AndroidBinderIntake(String hostGeneratedSession,
      P37RemoteProcess.RemoteControl stopControls,
      HostPipes hostOwnedPipes, long trustedHostOwnerEpoch) {
    this(hostGeneratedSession, stopControls, false,
         trustedHostOwnerEpoch, requirePipes(hostOwnedPipes, trustedHostOwnerEpoch));
  }
  private static P37RemoteProcess.Stdio requirePipes(
      HostPipes pipes, long epoch) {
    if (pipes == null || epoch <= 0)
      throw new IllegalArgumentException("P68_HOST_PIPES_AND_GENERATION_REQUIRED");
    return pipes.stdio;
  }
  private P68AndroidBinderIntake(String hostGeneratedSession,
      P37RemoteProcess.RemoteControl stopControls,
      boolean trustedHostRequestsMergedStderr, long trustedHostOwnerEpoch,
      P37RemoteProcess.Stdio hostOwnedPipes) {
    if(trustedHostOwnerEpoch<0)
      throw new IllegalArgumentException("P184_TRUSTED_OWNER_EPOCH_REQUIRED");
    if(stopControls==null || hostGeneratedSession==null ||
       !hostGeneratedSession.matches("[a-f0-9]{64}"))
      throw new IllegalArgumentException("P68_TRUSTED_HOST_SESSION_REQUIRED");
    trustedSession=hostGeneratedSession;
    controls=stopControls;
    mergeErrorToOutput=trustedHostRequestsMergedStderr;
    p184OwnerEpoch=trustedHostOwnerEpoch;
    ownedPipes=hostOwnedPipes;
  }
  private static boolean exactShape(Bundle b,int kind) {
    if(b==null || !b.containsKey("session") || !b.containsKey("seq"))return false;
    Set<String> keys=b.keySet();
    for(String key:keys){
      if("session".equals(key)||"seq".equals(key))continue;
      if("data".equals(key) &&
         (kind==P53StartOrder.STDOUT||kind==P53StartOrder.STDERR))continue;
      if("exitCode".equals(key)&&kind==P53StartOrder.EXIT)continue;
      return false;
    }
    if(kind==P53StartOrder.EXIT)
      return b.containsKey("exitCode")&&!b.containsKey("data");
    if(kind==P53StartOrder.STDOUT||kind==P53StartOrder.STDERR)
      return b.containsKey("data")&&!b.containsKey("exitCode");
    return (kind==P53StartOrder.HELLO||
            kind==P53StartOrder.CHILD_STARTED||
            kind==P53StartOrder.FAIL)&&
            !b.containsKey("data")&&!b.containsKey("exitCode");
  }
  private Result reject() {
    if(invalid)return Result.REJECTED;
    invalid=true;
    if(p184Receipt!=null)p184Receipt.revoke();
    if(handoff!=null)handoff.onTransportLost();
    else if(ownedPipes!=null) {
      try {ownedPipes.close();}catch(IOException ignored) { }
      try {controls.requestForceStop();}catch(RuntimeException ignored) { }
    }
    return Result.REJECTED;
  }
  public synchronized Result accept(Message msg) {
    if(invalid || (handoff!=null&&handoff.isTerminal()) || msg==null)
      return Result.REJECTED;
    try {
      int sender=msg.sendingUid;
      if(sender<0 || sender==android.os.Process.myUid() ||
         !android.os.Process.isIsolatedUid(sender))return reject();
      Bundle b=msg.getData();
      if(!exactShape(b,msg.what))return reject();
      if(ownedPipes!=null &&
         (msg.what==P53StartOrder.STDOUT || msg.what==P53StartOrder.STDERR))
        return reject();
      String session=b.getString("session");
      long sequence=b.getLong("seq",Long.MIN_VALUE);
      if(!trustedSession.equals(session))return reject();
      if(handoff==null) {
        if(msg.what!=P53StartOrder.HELLO||sequence!=0)return reject();
        isolatedUid=sender;
        handoff=ownedPipes==null ? new P67AuthenticatedHandoff(
            isolatedUid,trustedSession,android.os.Process::isIsolatedUid,
            controls,mergeErrorToOutput) :
            new P67AuthenticatedHandoff(isolatedUid,trustedSession,
                android.os.Process::isIsolatedUid,controls,ownedPipes);
      }else if(sender!=isolatedUid)return reject();
      byte[] data=null;
      if(msg.what==P53StartOrder.STDOUT||msg.what==P53StartOrder.STDERR){
        data=b.getByteArray("data");
        if(data==null||data.length<1||data.length>MAX_FIXTURE_BYTES)
          return reject();
      }
      int code=msg.what==P53StartOrder.EXIT?
          b.getInt("exitCode",P37RemoteProcess.SUPERVISOR_FAILURE_EXIT_CODE):0;
      if(!handoff.onAuthenticatedFrame(sender,session,msg.what,sequence,data,code))
        return reject();
      // P184 receipt is minted ONLY after the real Android Framework UID and
      // P53 strict CHILD_STARTED sequence were accepted by P67, and bound
      // to the exact P37 Process facade (never HELLO or worker Bundle UID).
      if(msg.what==P53StartOrder.CHILD_STARTED && p184OwnerEpoch>0) {
        Process verified=handoff.processAfterVerifiedChildStart();
        if(!(verified instanceof P37RemoteProcess) || p184Receipt!=null)
          return reject();
        final P37RemoteProcess exact=(P37RemoteProcess)verified;
        p184Receipt=new P184ChildStartReceipt(
            exact,sender,trustedSession,p184OwnerEpoch,
            ()->!invalid && handoff!=null &&
                handoff.hasVerifiedChildStart() &&
                handoff.processAfterVerifiedChildStart()==exact &&
                (exact.terminalReason()==P37RemoteProcess.TerminalReason.RUNNING ||
                 exact.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT));
      }
      if(msg.what==P53StartOrder.HELLO)return Result.HELLO;
      if(msg.what==P53StartOrder.CHILD_STARTED)return Result.CHILD_STARTED;
      if(msg.what==P53StartOrder.STDOUT)return Result.STDOUT;
      if(msg.what==P53StartOrder.STDERR)return Result.STDERR;
      if(msg.what==P53StartOrder.EXIT)return Result.EXIT;
      if(msg.what==P53StartOrder.FAIL)return Result.FAIL;
      return reject();
    }catch(RuntimeException invalidFrame){return reject();}
  }
  public synchronized int isolatedUid(){return isolatedUid;}
  /** One-shot delivery to a trusted P48/P75 host adapter, never to a Bundle. */
  public synchronized P184ChildStartReceipt takeVerifiedChildStartReceipt(){
    if(invalid || p184OwnerEpoch<=0 || p184Taken || p184Receipt==null)
      return null;
    p184Taken=true;
    return p184Receipt;
  }
  public synchronized Process processAfterAuthenticatedChildStart(){
    return !invalid && handoff!=null && handoff.hasVerifiedChildStart() ?
        handoff.processAfterVerifiedChildStart():null;
  }
  public synchronized boolean engineReady(){
    return handoff!=null && handoff.hasVerifiedOriginalEngineReady();
  }
  public synchronized boolean isTerminal(){
    return invalid || (handoff!=null&&handoff.isTerminal());
  }
  public synchronized void disconnected(){reject();}
}
