package com.dsh.p1.smoketest;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicInteger;
import android.system.Os;
import android.view.accessibility.AccessibilityNodeInfo;
import android.app.UiAutomation;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import com.dsh.p1.AndroidFdQueue;
import com.dsh.p1.NativeDiagnosticReview;

/** Test-only same-signer instrumentation for the pinned disposable APK.
 * No real logs, tokens, network access, production signing, or user data.
 * It proves UI invokability from a real Activity context, NOT host integration.
 */
public final class DshInstrumentation extends Instrumentation {
  private static final String DESTINATION = "https://diagnostic-test.invalid/v1/review";
  private static final String VALID =
      "{\"schema\":\"dsh-safe-diagnostic-v1\",\"appVersion\":\"0.4.1\","
      + "\"sdk\":35,\"events\":[{\"code\":\"APP_START\",\"count\":1}]}";
  private static final String INVALID =
      "{\"schema\":\"untrusted\",\"token\":\"CANARY_MUST_NOT_DISPLAY\"}";
  private volatile String phase = "NOT_STARTED";
  @Override public void onCreate(Bundle args) {
    super.onCreate(args);
    start();
  }

  private static void assertTrue(boolean condition,String message) {
    if(!condition)throw new AssertionError(message);
  }
  private static void write(File path, String text)throws Exception {
    try(FileOutputStream output=new FileOutputStream(path,false)) {
      output.write(text.getBytes(StandardCharsets.UTF_8));
      output.getFD().sync();
    }
    Os.chmod(path.getAbsolutePath(),0600);
  }

  private boolean contains(AccessibilityNodeInfo root,String search) {
    if(root==null)return false;
    CharSequence value=root.getText();
    if(value!=null&&value.toString().contains(search))return true;
    CharSequence description=root.getContentDescription();
    if(description!=null&&description.toString().contains(search))return true;
    for(int i=0;i<root.getChildCount();i++) {
      AccessibilityNodeInfo child=root.getChild(i);
      if(child!=null) {
        try {if(contains(child,search))return true;}
        finally {child.recycle();}
      }
    }
    return false;
  }
  private boolean waitForText(String text,int seconds)throws Exception{
    UiAutomation automation=getUiAutomation();
    for(int attempt=0;attempt<seconds*2;attempt++){
      AccessibilityNodeInfo root=automation.getRootInActiveWindow();
      if(root!=null){
        try{if(contains(root,text))return true;}
        finally {root.recycle();}
      }
      SystemClock.sleep(500);
    }
    return false;
  }

  private static boolean containsNativeText(View view,String expected){
    if(view instanceof TextView) {
      CharSequence label=((TextView)view).getText();
      if(label!=null&&label.toString().contains(expected))return true;
    }
    if(view instanceof ViewGroup) {
      ViewGroup container=(ViewGroup)view;
      for(int i=0;i<container.getChildCount();i++)
        if(containsNativeText(container.getChildAt(i),expected))return true;
    }
    return false;
  }
  private boolean waitForNativeDialog(NativeDiagnosticReview owner,int seconds){
    for(int attempt=0;attempt<seconds*3;attempt++){
      final boolean[] found={false};
      runOnMainSync(()->{
        try {
          Field field=NativeDiagnosticReview.class.getDeclaredField("shown");
          field.setAccessible(true);
          Object window=field.get(owner);
          if(window instanceof AlertDialog) {
            AlertDialog dialog=(AlertDialog)window;
            found[0]=dialog.isShowing()&&dialog.getWindow()!=null
                &&containsNativeText(dialog.getWindow().getDecorView(),"发送器尚未接入");
          }
        }catch(Exception ignored){}
      });
      if(found[0])return true;
      SystemClock.sleep(350);
    }
    return false;
  }
  /** Real original host APK Service Binder test (disposable emulator only).
   * Does not call real tools or access any user files.
   */
  private void verifyP120IsolatedService() throws Exception {
    final android.content.Context context=getTargetContext();
    final java.util.concurrent.CountDownLatch done=
        new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.atomic.AtomicBoolean accepted=
        new java.util.concurrent.atomic.AtomicBoolean(false);
    final android.os.HandlerThread handlerThread=
        new android.os.HandlerThread("p120-authenticated-receipt");
    handlerThread.start();
    final android.os.Messenger receiver=new android.os.Messenger(
        new android.os.Handler(handlerThread.getLooper()) {
      @Override public void handleMessage(android.os.Message result) {
        try {
          final android.os.Bundle data=result.getData();
          final int sender=result.sendingUid;
          accepted.set(result.what==12002 &&
              android.os.Process.isIsolatedUid(sender) &&
              sender!=android.os.Process.myUid() &&
              data.getBoolean("isolated",false) &&
              data.getInt("observedUid",-1)==sender &&
              "DENY_ALL".equals(data.getString("toolAccess")) &&
              !data.containsKey("fixedResult"));
        } finally { done.countDown(); }
      }
    });
    final android.content.ServiceConnection connection=
        new android.content.ServiceConnection() {
      @Override public void onServiceConnected(
          android.content.ComponentName component, android.os.IBinder binder) {
        try {
          android.os.Message request=android.os.Message.obtain(null,12001);
          request.replyTo=receiver;
          new android.os.Messenger(binder).send(request);
        } catch(android.os.RemoteException failed) { done.countDown(); }
      }
      @Override public void onServiceDisconnected(
          android.content.ComponentName component) { done.countDown(); }
    };
    final android.content.Intent intent=new android.content.Intent();
    intent.setClassName("com.dsh.android","com.dsh.p120.P120IsolatedDenyService");
    boolean bound=false;
    try {
      bound=context.bindService(intent,connection,android.content.Context.BIND_AUTO_CREATE);
      assertTrue(bound,"P120_ORIGINAL_SERVICE_NOT_BINDABLE");
      assertTrue(done.await(15,java.util.concurrent.TimeUnit.SECONDS),
          "P120_REAL_BINDER_RESPONSE_MISSING");
      assertTrue(accepted.get(),"P120_ISOLATED_SENDER_UID_OR_DENY_ALL_INVALID");
    } finally {
      if(bound)context.unbindService(connection);
      handlerThread.quitSafely();
    }
  }

  /** Host owns the source asset and passes an FD; no private path goes to isolated UID. */
  private static void sendP121FdProof(android.os.Messenger service,
      android.os.Messenger replyTo,byte[] prefix)throws Exception{
    if(prefix==null||prefix.length!=4096)throw new AssertionError("P121_PREFIX_BOUND_INVALID");
    final android.os.ParcelFileDescriptor[] pipe=
        android.os.ParcelFileDescriptor.createPipe();
    try{
      android.os.Message request=android.os.Message.obtain(null,12003);
      request.replyTo=replyTo;
      android.os.Bundle args=new android.os.Bundle();
      args.putParcelable("engine_fd",pipe[0]);
      request.setData(args);
      service.send(request);
    }catch(Exception failed){
      try{pipe[1].close();}catch(Exception ignored){}
      throw failed;
    }finally{
      try{pipe[0].close();}catch(Exception ignored){}
    }
    Thread writer=new Thread(()->{
      try(java.io.OutputStream output=
          new android.os.ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])){
        output.write(prefix);
        output.flush();
      }catch(Exception ignored){}
    },"p121-original-asset-prefix-fd-writer");
    writer.setDaemon(true);
    writer.start();
  }

  /** Test the ACTUAL assets/engine.bin prefix, not a synthetic replacement. */
  private void verifyP121OriginalEngineFd() throws Exception{
    final byte[] pinned=new byte[4096];
    try(java.io.InputStream original=
        getTargetContext().getAssets().open("engine.bin")){
      int n=0;
      while(n<pinned.length){
        int part=original.read(pinned,n,pinned.length-n);
        assertTrue(part>0,"P121_ORIGINAL_ENGINE_ASSET_TOO_SMALL");
        n+=part;
      }
    }
    final java.util.concurrent.CountDownLatch finish=
        new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.atomic.AtomicBoolean success=
        new java.util.concurrent.atomic.AtomicBoolean(false);
    final java.util.concurrent.atomic.AtomicReference<String> failedCode=
        new java.util.concurrent.atomic.AtomicReference<>("NO_REPLY");
    final java.util.concurrent.atomic.AtomicInteger phase=
        new java.util.concurrent.atomic.AtomicInteger(0);
    final android.os.Messenger[] service={null};
    final android.os.Messenger[] receiverRef={null};
    final android.os.HandlerThread replies=
        new android.os.HandlerThread("p121-original-asset-fd-replies");
    replies.start();
    final android.os.Messenger receiver=new android.os.Messenger(
      new android.os.Handler(replies.getLooper()){
        @Override public void handleMessage(android.os.Message message){
          android.os.Bundle b=message.getData();
          int sender=message.sendingUid;
          boolean common=message.what==12004&&
              android.os.Process.isIsolatedUid(sender)&&
              sender!=android.os.Process.myUid()&&
              "DENY_ALL".equals(b.getString("toolAccess"))&&
              !b.containsKey("rawBytes")&&!b.containsKey("fixedResult");
          int state=phase.getAndIncrement();
          if(state==0){
            if(!common||!"PINNED_4096_SHA256_MATCH_NO_EXEC".equals(
                b.getString("assetPrefix"))){
              String code=b.getString("assetPrefix","");
              if("REJECTED_BAD_FD_NO_EXEC".equals(code))
                failedCode.set("FIRST_BAD_FD");
              else if("REJECTED_TIMEOUT_NO_EXEC".equals(code))
                failedCode.set("FIRST_TIMEOUT");
              else if("REJECTED_BUSY_NO_EXEC".equals(code))
                failedCode.set("FIRST_BUSY");
              else if("REJECTED_NO_EXEC".equals(code))
                failedCode.set("FIRST_HASH_NOT_PINNED");
              else failedCode.set("FIRST_REPLY_UID_OR_FRAME_INVALID");
              finish.countDown();return;
            }
            byte[] corrupt=java.util.Arrays.copyOf(pinned,pinned.length);
            corrupt[0]^=1;
            failedCode.set("SECOND_REPLY_MISSING");
            try{sendP121FdProof(service[0],receiverRef[0],corrupt);}
            catch(Exception invalid){
              failedCode.set("SECOND_SEND_FAILED");finish.countDown();
            }
          }else if(state==1){
            success.set(common&&"REJECTED_NO_EXEC".equals(b.getString("assetPrefix")));
            if(!success.get())failedCode.set("SECOND_REJECTION_OR_UID_INVALID");
            finish.countDown();
          }else finish.countDown();
        }
      });
    receiverRef[0]=receiver;
    final android.content.ServiceConnection bind=
        new android.content.ServiceConnection(){
      @Override public void onServiceConnected(
          android.content.ComponentName component,android.os.IBinder binder){
        service[0]=new android.os.Messenger(binder);
        try{sendP121FdProof(service[0],receiver,pinned);}
        catch(Exception failed){finish.countDown();}
      }
      @Override public void onServiceDisconnected(
          android.content.ComponentName component){finish.countDown();}
    };
    android.content.Intent intent=new android.content.Intent();
    intent.setClassName("com.dsh.android","com.dsh.p120.P120IsolatedDenyService");
    boolean bound=false;
    try{
      bound=getTargetContext().bindService(intent,bind,
          android.content.Context.BIND_AUTO_CREATE);
      assertTrue(bound,"P121_ORIGINAL_HOST_BIND_FAILED");
      assertTrue(finish.await(22,java.util.concurrent.TimeUnit.SECONDS),
          "P121_STAGE_"+phase.get()+"_REPLY_TIMEOUT");
      assertTrue(success.get()&&phase.get()==2,
          "P121_"+failedCode.get());
    }finally{
      if(bound)getTargetContext().unbindService(bind);
      replies.quitSafely();
    }
  }

  /**
   * Full original signed-v138 engine.bin from APK Assets via host-owned pipe.
   * Original engine bytes never enter logs or Binder payload, only an FD.
   * Corrupted-input negative control flips one byte but preserves full length.
   */
  private static void sendP122EngineStream(android.content.Context ctx,
      android.os.Messenger worker,android.os.Messenger recipient,
      boolean corrupt) throws Exception{
    final android.os.ParcelFileDescriptor[] pipe=
        android.os.ParcelFileDescriptor.createPipe();
    try{
      android.os.Message request=android.os.Message.obtain(null,12201);
      request.replyTo=recipient;
      android.os.Bundle payload=new android.os.Bundle();
      payload.putParcelable("engine_fd",pipe[0]);
      request.setData(payload);
      worker.send(request);
    }catch(Exception failed){
      try{pipe[1].close();}catch(Exception ignored){}
      throw failed;
    }finally{
      try{pipe[0].close();}catch(Exception ignored){}
    }
    Thread sender=new Thread(()->{
      try(java.io.InputStream original=ctx.getAssets().open("engine.bin");
          java.io.OutputStream output=
              new android.os.ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])){
        byte[] buf=new byte[65536];
        boolean first=true;
        int n;
        while((n=original.read(buf))!=-1){
          if(n==0)continue;
          if(first&&corrupt){buf[0]^=1;}
          first=false;
          output.write(buf,0,n);
        }
        output.flush();
      }catch(Exception ignored){
        // The service will fail closed on incomplete transfer or timeout.
      }
    },corrupt?"p122-corrupt-engine-full-writer":"p122-pinned-engine-full-writer");
    sender.setDaemon(true);
    sender.start();
  }

  private void verifyP122FullEngineFd() throws Exception{
    final android.content.Context host=getTargetContext();
    final java.util.concurrent.CountDownLatch done=
        new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.atomic.AtomicBoolean accepted=
        new java.util.concurrent.atomic.AtomicBoolean(false);
    final java.util.concurrent.atomic.AtomicReference<String> failure=
        new java.util.concurrent.atomic.AtomicReference<>("NO_RECEIPT");
    final java.util.concurrent.atomic.AtomicInteger stage=
        new java.util.concurrent.atomic.AtomicInteger(0);
    final android.os.Messenger[] worker={null};
    final android.os.Messenger[] replyHolder={null};
    final android.os.HandlerThread callbacks=
        new android.os.HandlerThread("p122-isolated-full-asset-receipts");
    callbacks.start();
    final android.os.Messenger receiver=new android.os.Messenger(
      new android.os.Handler(callbacks.getLooper()){
        @Override public void handleMessage(android.os.Message response){
          android.os.Bundle result=response.getData();
          int sender=response.sendingUid;
          boolean frame=response.what==12202&&
              android.os.Process.isIsolatedUid(sender)&&
              sender!=android.os.Process.myUid()&&
              "DENY_ALL".equals(result.getString("toolAccess"))&&
              !result.containsKey("rawBytes")&&
              !result.containsKey("fixedResult");
          String code=result.getString("fullEngine","");
          int n=stage.getAndIncrement();
          if(n==0){
            if(!frame||!"PINNED_FULL_ENGINE_SHA256_MATCH_NO_EXEC".equals(code)){
              failure.set("FIRST_RECEIPT_INVALID_OR_HASH_MISMATCH");
              done.countDown();return;
            }
            failure.set("SECOND_RECEIPT_MISSING");
            try{sendP122EngineStream(host,worker[0],replyHolder[0],true);}
            catch(Exception invalid){
              failure.set("SECOND_SEND_FAILED");done.countDown();
            }
          }else if(n==1){
            accepted.set(frame&&"REJECTED_CONTENT_NO_EXEC".equals(code));
            if(!accepted.get())failure.set("SECOND_REJECTION_FAILED");
            done.countDown();
          }else{
            failure.set("DUPLICATE_TERMINAL");
            done.countDown();
          }
        }
      });
    replyHolder[0]=receiver;
    final android.content.ServiceConnection connection=
        new android.content.ServiceConnection(){
      @Override public void onServiceConnected(
          android.content.ComponentName component,android.os.IBinder binder){
        worker[0]=new android.os.Messenger(binder);
        try{sendP122EngineStream(host,worker[0],receiver,false);}
        catch(Exception failed){
          failure.set("FIRST_SEND_FAILED");done.countDown();
        }
      }
      @Override public void onServiceDisconnected(
          android.content.ComponentName component){
        failure.set("ISOLATED_SERVICE_DISCONNECTED");done.countDown();
      }
    };
    android.content.Intent intent=new android.content.Intent();
    intent.setClassName("com.dsh.android","com.dsh.p120.P120IsolatedDenyService");
    boolean bound=false;
    try{
      bound=host.bindService(intent,connection,
          android.content.Context.BIND_AUTO_CREATE);
      assertTrue(bound,"P122_ORIGINAL_SERVICE_BIND_FAILED");
      assertTrue(done.await(140,java.util.concurrent.TimeUnit.SECONDS),
          "P122_STAGE_"+stage.get()+"_RECEIPT_TIMEOUT");
      assertTrue(accepted.get()&&stage.get()==2,
          "P122_"+failure.get());
    }finally{
      if(bound)host.unbindService(connection);
      callbacks.quitSafely();
    }
  }

()=>method+"  @Override public void onStart() {"
    Bundle result=new Bundle();
    Activity activity=null;
    AndroidFdQueue queue=null;
    NativeDiagnosticReview review=null;
    File folder=null;
    try {
      phase="ORIGINAL_ACTIVITY";
      Intent start=new Intent();
      start.setClassName("com.dsh.android","com.dsh.android.MainActivity");
      start.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
      activity=startActivitySync(start);
      assertTrue(activity!=null,"Original MainActivity is not launchable");
      assertTrue("com.dsh.android.MainActivity".equals(activity.getClass().getName()),
          "Unexpected Android host activity");

      phase="P5_REAL_ANDROID_CLASS_LOADING";
      Class.forName("com.dsh.p1.NativeDiagnosticReview",true,activity.getClassLoader());
      Class.forName("com.dsh.p1.ApprovedDiagnosticSendGate",true,activity.getClassLoader());

      phase="P120_REAL_ORIGINAL_HOST_ISOLATED_SERVICE";
      verifyP120IsolatedService();
      result.putString("P120_ORIGINAL_HOST_ISOLATED_UID","PASS_REAL_ANDROID_BINDER");
      phase="P121_REAL_ORIGINAL_ENGINE_FD";
      verifyP121OriginalEngineFd();
      result.putString("P121_ORIGINAL_ENGINE_FD_PREFIX",
          "PASS_REAL_ANDROID_UID_HASH_AND_DENY");
      phase="P122_REAL_ORIGINAL_FULL_ENGINE_FD";
      verifyP122FullEngineFd();
      result.putString("P122_FULL_ENGINE_FD_SHA256",
          "PASS_FULL_57724933_AND_CORRUPTED_REJECTED_NO_EXEC");
      phase="P124_REAL_ORIGINAL_ISOLATED_CHILD";
      verifyP124FixedIsolatedChildUid();
      result.putString("P124_FIXED_CHILD_ISOLATED_UID",
          "PASS_SYSTEM_ID_CHILD_MATCHES_FRAMEWORK_ISOLATED_UID_DENY_ALL");
      phase="NATIVE_PINNED_QUEUE";
      // Use a native-owned 0700 root, never the shared app filesDir itself.
      // P5 correctly rejects group/other writable roots rather than
      // silently weakening symlink/ownership hardening.
      File root=new File(activity.getFilesDir(),"p5_native_private_root");
      if(!root.isDirectory()&&!root.mkdir())
        throw new AssertionError("Could not create disposable native root");
      Os.chmod(root.getAbsolutePath(),0700);
      folder=new File(root,"p5_instrumentation_fixture");
      if(!folder.isDirectory()&&!folder.mkdir())
        throw new AssertionError("Could not create disposable fixture directory");
      Os.chmod(folder.getAbsolutePath(),0700);
      File valid=new File(folder,"review-safe.json");
      File invalid=new File(folder,"review-untrusted.json");
      write(valid,VALID);
      write(invalid,INVALID);
      queue=new AndroidFdQueue(root,folder.getName());
      // Isolate pinned Java reader behavior from dialog/UiAutomation behavior.
      phase="NATIVE_PINNED_READ";
      byte[] observed=queue.read(valid).copyBytes();
      assertTrue(observed.length==VALID.getBytes(StandardCharsets.UTF_8).length,
          "Verified descriptor did not return exact synthetic fixture length");
      phase="NATIVE_DIALOG_CONSTRUCTION";
      final Activity owner=activity;
      final AndroidFdQueue trustedQueue=queue;
      final NativeDiagnosticReview[] created=new NativeDiagnosticReview[1];
      final AtomicInteger unsupportedRejected=new AtomicInteger();
      runOnMainSync(()->{
        try{
          created[0]=new NativeDiagnosticReview(owner,trustedQueue,
              Collections.singleton(DESTINATION),DESTINATION,
              (kind,entry,reason,timestamp,count)->{
                if("DENIED".equals(kind)&&"preview".equals(entry)&&
                    "UNSUPPORTED_OR_CHANGED_FILE".equals(reason))
                  unsupportedRejected.incrementAndGet();
              });
          created[0].preview(valid);
        }catch(Exception error){throw new RuntimeException(error);}
      });
      review=created[0];

      phase="NATIVE_SAFE_PREVIEW_VISIBLE";
      if(!waitForNativeDialog(review,10)){
        phase="P5_DIALOG_NOT_SHOWING_OR_SAFE_CONTENT_MISSING";
        throw new AssertionError("Trusted P5 dialog was not shown with fail-closed notice");
      }
      phase="NATIVE_UNSUPPORTED_SCHEMA_DENIED";
      final NativeDiagnosticReview control=review;
      runOnMainSync(()->control.preview(invalid));
      for(int i=0;i<24&&unsupportedRejected.get()==0;i++)
        SystemClock.sleep(350);
      assertTrue(unsupportedRejected.get()==1,
          "Unsupported format not denied by native audit callback");

      phase="P5_REVIEW_SMOKE_PASS";
      result.putString("P5_NATIVE_UI_REAL_ACTIVITY","PASS_INSTRUMENTATION");
      result.putString("P5_FD_PINNED_READER","PASS_ANDROID_FIXTURE");
      result.putString("P5_UNTRUSTED_SCHEMA_REJECTION","PASS_ANDROID_FIXTURE");
      result.putString("P5_NETWORK_SEND","NOT_CONNECTED");
      result.putString("LEGACY_HOST_BUTTON_WIRED","NO");
      result.putString("P5_GRANTED_TRANSPORT","NONE");
      result.putString("ART_REAL_DEVICE","NOT_VERIFIED");
      finish(Activity.RESULT_OK,result);
    }catch(Throwable failure){
      result.putString("FAIL_PHASE",phase);
      result.putString("FAIL_TYPE",failure.getClass().getSimpleName());
      // Only a narrowly whitelisted synthetic FD queue errno / safe class of
      // failure. Never print an arbitrary exception message or stack trace.
      String cause=failure.getMessage();
      if(cause!=null&&cause.matches("QUEUE_(OPEN|READ) errno=[0-9]{1,4}"))
        result.putString("FAIL_REASON",cause);
      else if(cause!=null&&cause.equals("Queue ownership or permissions rejected"))
        result.putString("FAIL_REASON","SYNTHETIC_QUEUE_PERMISSIONS");
      else if(cause!=null&&cause.equals("Queue is not a directory"))
        result.putString("FAIL_REASON","SYNTHETIC_QUEUE_NOT_DIRECTORY");
      else if(cause!=null&&cause.matches("P12[124]_[A-Z0-9_]{1,90}"))
        result.putString("FAIL_REASON",cause);
      else
        result.putString("FAIL_REASON","OTHER_NO_DETAIL");
      // No raw paths, arbitrary native errors or stack traces are emitted.
      finish(Activity.RESULT_CANCELED,result);
    }finally {
      NativeDiagnosticReview close=review;
      if(close!=null)try{runOnMainSync(close::close);}catch(Throwable ignored){}
      if(queue!=null)try{queue.close();}catch(Exception ignored){}
      if(folder!=null){
        for(String name:new String[]{"review-safe.json","review-untrusted.json"})
          new File(folder,name).delete();
        folder.delete();
        // The dedicated fixture root is ours and contains no app-owned data.
        File privateRoot=folder.getParentFile();
        if(privateRoot!=null&&"p5_native_private_root".equals(privateRoot.getName()))
          privateRoot.delete();
      }
    }
  }
}
