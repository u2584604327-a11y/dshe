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

  @Override public void onStart() {
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
