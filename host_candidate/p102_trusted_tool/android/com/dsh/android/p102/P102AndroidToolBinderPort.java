package com.dsh.android.p102;

import com.dsh.android.p71.P71ToolReplyOnce;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import java.security.SecureRandom;
import java.util.Set;

/**
 * Candidate trusted-host Android Binder port for one synthetic tool read.
 *
 * Must be installed only in a trusted Android host and exposed solely to a
 * non-exported isolated worker. NO DSH MainActivity/EngineManager wiring yet.
 * Framework Message.sendingUid, never a Bundle uid, establishes caller identity.
 * No arbitrary tool, path, web access, Node code or native grant via Binder.
 */
public final class P102AndroidToolBinderPort {
  public static final int HELLO=10201,REQUEST=10202;
  public static final int HELLO_REPLY=10301,REQUEST_ACK=10302,TOOL_TERMINAL=10303;
  public interface NativeApprovalUi {
    void showTrustedNativeApproval(String callId,String toolName);
  }
  private final NativeApprovalUi approvalUi;
  private final P102TrustedToolGate.TrustedExecutor trustedExecutor;
  private final P102TrustedToolGate.OriginalCallVerifier trustedOriginalCallVerifier;
  private final Messenger inbox;
  private P102TrustedToolGate gate;
  private Messenger workerReply;
  private int workerUid=-1;
  private boolean expectingHello;
  private String session;

  public P102AndroidToolBinderPort(NativeApprovalUi ui,
      P102TrustedToolGate.TrustedExecutor executor,
      P102TrustedToolGate.OriginalCallVerifier verifiedOriginalTurn){
    if(ui==null||executor==null||verifiedOriginalTurn==null)
      throw new IllegalArgumentException("P102_NATIVE_UI_AND_EXECUTOR_REQUIRED");
    approvalUi=ui;trustedExecutor=executor;
    trustedOriginalCallVerifier=verifiedOriginalTurn;
    inbox=new Messenger(new Handler(Looper.getMainLooper()){
      @Override public void handleMessage(Message m){onWorkerFrame(m);}
    });
  }
  public Messenger trustedInbox(){return inbox;}

  /** Called by trusted Activity as it initiates a fresh non-exported bind. */
  public synchronized void onTrustedServiceBindingInitiated(){
    revoke();
    expectingHello=true;
  }
  public synchronized void onTrustedUiBackground(){revoke();}
  public synchronized void onBinderDeath(){revoke();}
  public synchronized void onWorkerDisconnected(){revoke();}

  private static String newHostSession(){
    byte[] bytes=new byte[32];
    new SecureRandom().nextBytes(bytes);
    final char[] hex="0123456789abcdef".toCharArray();
    StringBuilder value=new StringBuilder(64);
    for(byte b:bytes){int unsigned=b&255;value.append(hex[unsigned>>>4]);value.append(hex[unsigned&15]);}
    return value.toString();
  }
  private static boolean exact(Bundle b,String... allowed){
    if(b==null)return false;
    Set<String> keys=b.keySet();
    if(keys.size()!=allowed.length)return false;
    for(String key:allowed)if(!keys.contains(key))return false;
    return true;
  }
  private static String text(Bundle b,String key,int maximum){
    Object v=b.get(key);
    if(!(v instanceof String))return null;
    String s=(String)v;
    return s.length()<=maximum?s:null;
  }
  private static boolean send(Messenger destination,int what,Bundle fields){
    if(destination==null)return false;
    Message message=Message.obtain(null,what);
    message.setData(fields);
    try{destination.send(message);return true;}
    catch(RemoteException disconnected){return false;}
  }
  private synchronized void revoke(){
    expectingHello=false;
    if(gate!=null){gate.revoke();gate=null;}
    workerReply=null;workerUid=-1;session=null;
  }
  private synchronized void onWorkerFrame(Message request){
    if(request==null)return;
    try{
      final int sender=request.sendingUid;
      if(request.what==HELLO){
        if(!expectingHello||gate!=null||request.replyTo==null||
           sender<0||sender==Process.myUid()||!Process.isIsolatedUid(sender)||
           !exact(request.getData())){revoke();return;}
        workerUid=sender;workerReply=request.replyTo;
        session=newHostSession();expectingHello=false;
        gate=new P102TrustedToolGate(sender,session,SystemClock::elapsedRealtime,
          Process::isIsolatedUid,trustedExecutor,this::sendTerminal,
          trustedOriginalCallVerifier);
        Bundle fields=new Bundle();fields.putString("session",session);
        fields.putString("status","BOUND_NOT_APPROVED");
        if(!send(workerReply,HELLO_REPLY,fields))revoke();
        return;
      }
      if(request.what!=REQUEST||gate==null||workerReply==null||
         request.replyTo==null||request.replyTo.getBinder()!=workerReply.getBinder()||
         sender!=workerUid||!Process.isIsolatedUid(sender)){
        revoke();return;
      }
      Bundle b=request.getData();
      if(!exact(b,"session","originalSessionId","callId","toolName","arguments")){
        revoke();return;
      }
      String sessionIn=text(b,"session",64);
      String originalSessionId=text(b,"originalSessionId",128);
      String callId=text(b,"callId",96);
      String toolName=text(b,"toolName",80);
      String arguments=text(b,"arguments",128);
      P102TrustedToolGate.Decision decision=gate.accept(
        sender,sessionIn,originalSessionId,callId,toolName,arguments);
      Bundle reply=new Bundle();reply.putString("status",decision.name());
      if(!send(workerReply,REQUEST_ACK,reply)){
        Log.e("P102_TOOL_BINDER","P102_HOST_REQUEST_ACK_SEND=FAIL");
        revoke();return;
      }
      Log.i("P102_TOOL_BINDER","P102_HOST_REQUEST_ACK_SEND=PASS");
      if(decision!=P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL){
        revoke();return;
      }
      // Only trusted native Android UI receives a display request.
      approvalUi.showTrustedNativeApproval(callId,toolName);
    }catch(RuntimeException malformed){revoke();}
  }
  /** No remote IPC dispatches this method; only trusted Activity button. */
  public synchronized boolean onTrustedNativeUiApprove(String callId){
    if(gate==null)return false;
    P102TrustedToolGate.Decision decision=gate.onTrustedNativeApproval(callId);
    if(decision==P102TrustedToolGate.Decision.EXPIRED)revoke();
    return decision==P102TrustedToolGate.Decision.DISPATCHED;
  }
  /** Actual terminal result is only sent after the trusted executor has run. */
  private synchronized void sendTerminal(P71ToolReplyOnce.Terminal terminal){
    if(workerReply==null)return;
    Bundle fields=new Bundle();
    fields.putString("callId",terminal.id);
    fields.putString("status",terminal.ok?"SUCCESS":terminal.code);
    fields.putBoolean("outcomeUnknown",terminal.outcomeUnknown);
    fields.putBoolean("retrySafe",terminal.retrySafe);
    if(terminal.ok)fields.putString("fixedResult","fixture-read-success");
    if(!send(workerReply,TOOL_TERMINAL,fields)){
      Log.e("P102_TOOL_BINDER","P102_HOST_TERMINAL_SEND=FAIL");
      revoke();
    }else{
      // Successful Messenger.send is delivery to Binder, NOT worker receipt.
      Log.i("P102_TOOL_BINDER","P102_HOST_TERMINAL_SEND=PASS_NOT_RECEIPT");
    }
  }
}
