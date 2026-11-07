package com.dsh.android.p68;
import android.os.Bundle;
import android.os.Message;
import com.dsh.android.p53.P53StartOrder;
import com.dsh.android.p67.P67AuthenticatedHandoff;
import com.dsh.p37.P37RemoteProcess;
import java.util.Set;

/** Android framework sendingUid -> P67 ordered child-start -> P37 Process.
 * Test fixture only. HELLO never creates or hands out Process; no engine READY.
 */
public final class P68AndroidBinderIntake {
  public enum Result { HELLO, CHILD_STARTED, STDOUT, STDERR, EXIT, FAIL, REJECTED }
  private static final int MAX_FIXTURE_BYTES=128;
  private final String trustedSession;
  private final P37RemoteProcess.RemoteControl controls;
  private final boolean mergeErrorToOutput;
  private final long p184OwnerEpoch;
  private P184ChildStartReceipt p184Receipt;
  private boolean p184Taken;
  private P67AuthenticatedHandoff handoff;
  private int isolatedUid=-1;
  private boolean invalid;
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
    if(trustedHostOwnerEpoch<0)
      throw new IllegalArgumentException("P184_TRUSTED_OWNER_EPOCH_REQUIRED");
    if(stopControls==null || hostGeneratedSession==null ||
       !hostGeneratedSession.matches("[a-f0-9]{64}"))
      throw new IllegalArgumentException("P68_TRUSTED_HOST_SESSION_REQUIRED");
    trustedSession=hostGeneratedSession;
    controls=stopControls;
    mergeErrorToOutput=trustedHostRequestsMergedStderr;
    p184OwnerEpoch=trustedHostOwnerEpoch;
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
    invalid=true;
    if(p184Receipt!=null)p184Receipt.revoke();
    if(handoff!=null)handoff.onTransportLost();
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
      String session=b.getString("session");
      long sequence=b.getLong("seq",Long.MIN_VALUE);
      if(!trustedSession.equals(session))return reject();
      if(handoff==null) {
        if(msg.what!=P53StartOrder.HELLO||sequence!=0)return reject();
        isolatedUid=sender;
        handoff=new P67AuthenticatedHandoff(
            isolatedUid,trustedSession,android.os.Process::isIsolatedUid,
            controls,mergeErrorToOutput);
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
