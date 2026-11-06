package com.dsh.b1probe;
import android.app.Application;
import android.app.Service;
import android.content.Intent;
import android.os.*;
import android.os.Process;
import android.webkit.*;

/** Disposable B2 same-UID, separate-process WebView storage experiment. */
public abstract class ConcurrentSlotService extends Service {
  static final int INIT=1,WRITE=2,VERIFY=3,READY=101,WRITTEN=102,VERIFIED=103,DENY=199;
  private static final String URL="https://b1-offline.invalid/";
  private final Handler handler=new Handler(Looper.getMainLooper());
  private Messenger receiver;
  private WebView web;
  private CookieManager cookie;
  private int state;  // 0 uninitialized, 1 loading, 2 prepared, 3 writing, 4 written, 5 verify, 6 verified
  private boolean destroyed,loaded;
  protected abstract String slot();
  private String previous(){return "A".equals(slot())?"A":"B";}
  private String next(){return previous()+"2";}
  private String own(){return "A".equals(slot())?"b1a":"b1b";}
  private String other(){return "A".equals(slot())?"b1b":"b1a";}
  private final Messenger messenger=new Messenger(new Handler(Looper.getMainLooper(),m->{
    if(destroyed)return true;
    if(m.replyTo==null){deny();return true;}
    if(receiver!=null&&!receiver.getBinder().equals(m.replyTo.getBinder())){deny();return true;}
    if(receiver==null)receiver=m.replyTo;
    if(m.what==INIT&&state==0){state=1;initialize();}
    else if(m.what==WRITE&&state==2){state=3;write();}
    else if(m.what==VERIFY&&state==4){state=5;verify();}
    else deny();
    return true;
  }));
  @Override public IBinder onBind(Intent intent){
    if(!(getPackageName()+":slot"+slot()).equals(Application.getProcessName()))
      throw new SecurityException("B2_WRONG_PROCESS");
    return messenger.getBinder();
  }
  private void report(int code){
    if(destroyed||receiver==null)return;
    Message m=Message.obtain(null,code);
    m.arg1=Process.myPid();
    m.arg2=Process.myUid();
    try{receiver.send(m);}catch(RemoteException error){destroyed=true;}
  }
  private void deny(){report(DENY);destroyed=true;}
  private void initialize(){
    handler.postDelayed(()->{if(!destroyed&&state<6)deny();},26000);
    try{
      web=new WebView(getApplicationContext());
      WebSettings s=web.getSettings();
      s.setJavaScriptEnabled(true);
      s.setDomStorageEnabled(true);
      s.setAllowFileAccess(false);
      s.setAllowContentAccess(false);
      cookie=CookieManager.getInstance();
      cookie.setAcceptThirdPartyCookies(web,false);
      web.setWebViewClient(new WebViewClient(){
        @Override public void onPageFinished(WebView view,String url){
          if(destroyed||loaded||state!=1)return;
          loaded=true;
          check(previous(),()->{if(destroyed)return;state=2;report(READY);});
        }
      });
      web.loadDataWithBaseURL(URL,"<html><body>B2 offline synthetic only</body></html>",
          "text/html","UTF-8",null);
    }catch(RuntimeException e){deny();}
  }
  private boolean cookieMatches(String value){
    String c=cookie.getCookie(URL);
    return c!=null&&c.contains(own()+"=fix"+value)&&!c.contains(other()+"=");
  }
  private void check(String value,Runnable then){
    if(destroyed)return;
    if(!cookieMatches(value)){deny();return;}
    web.evaluateJavascript("(function(){return localStorage.getItem('b1k')})()",r->{
      if(destroyed)return;
      if(!("\""+value+"\"").equals(r)){deny();return;}
      idb(false,value,then);
    });
  }
  private void write(){
    String v=next();
    cookie.setCookie(URL,own()+"=fix"+v+"; Secure; SameSite=Lax",ok->{
      if(destroyed)return;
      if(!Boolean.TRUE.equals(ok)){deny();return;}
      cookie.flush();
      web.evaluateJavascript("(function(){localStorage.setItem('b1k','"+v+"');return localStorage.getItem('b1k')})()",r->{
        if(destroyed)return;
        if(!("\""+v+"\"").equals(r)){deny();return;}
        idb(true,v,()->{if(destroyed)return;state=4;report(WRITTEN);});
      });
    });
  }
  private void verify(){
    check(next(),()->{if(destroyed)return;state=6;report(VERIFIED);});
  }
  private void idb(boolean write,String expected,Runnable then){
    if(destroyed)return;
    String mode=write?"readwrite":"readonly";
    String expr=write?"put('"+expected+"','owner')":"get('owner')";
    String outcome=write?"'"+expected+"'":"String(req.result)";
    String js="(function(){try{window.__b2='WAIT';var open=indexedDB.open('b1_isolated_profile',1);"
      +"open.onerror=function(){window.__b2='ERR'};"
      +"open.onsuccess=function(){var db=open.result;"
      +"if(!db.objectStoreNames.contains('profile')){window.__b2='ERR';db.close();return;}"
      +"var tx=db.transaction('profile','"+mode+"');var req=tx.objectStore('profile')."+expr+";"
      +"var value='ERR';req.onsuccess=function(){value="+outcome+"};"
      +"req.onerror=function(){value='ERR'};"
      +"tx.oncomplete=function(){window.__b2=value;db.close()};"
      +"tx.onerror=function(){window.__b2='ERR'};"
      +"tx.onabort=function(){window.__b2='ERR';db.close()};"
      +"};return 'START'}catch(e){window.__b2='ERR';return 'ERR'}})()";
    web.evaluateJavascript(js,r->{
      if(destroyed)return;
      if(!"\"START\"".equals(r)){deny();return;}
      poll(expected,0,then);
    });
  }
  private void poll(String expected,int n,Runnable then){
    if(destroyed)return;
    if(n>=40){deny();return;}
    handler.postDelayed(()->{
      if(destroyed)return;
      web.evaluateJavascript("(function(){return window.__b2||'ERR'})()",r->{
        if(destroyed)return;
        if("\"WAIT\"".equals(r))poll(expected,n+1,then);
        else if(("\""+expected+"\"").equals(r))then.run();
        else deny();
      });
    },150);
  }
  @Override public void onDestroy(){
    destroyed=true;
    if(web!=null){web.stopLoading();web.destroy();web=null;}
    super.onDestroy();
  }
}
