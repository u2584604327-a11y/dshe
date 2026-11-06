package com.dsh.b1probe;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;

/**
 * Offline fixed-origin WebView test, no app INTERNET permission. No real login,
 * account, JS bridge, cookie contents printed, URL navigation or user files.
 * Four phases: A write -> B reject A/write -> A verify A -> B verify B.
 * All phases independently check IndexedDB in addition to Cookie/LocalStorage.
 */
public abstract class SlotProbe extends Activity {
  private static final String TAG="B1_PROBE";
  private static final String ORIGIN="https://b1-offline.invalid/";
  private static final String HTML="<html><head><meta charset='UTF-8'></head>"
      +"<body>offline fixed source only</body></html>";
  private static final String A_COOKIE="b1a=fixA";
  private static final String B_COOKIE="b1b=fixB";
  private WebView web;
  private CookieManager cookies;
  private boolean done;
  private int phase;

  protected abstract String slot();
  private void deny(String reason) {
    if (done) return;
    done=true;
    Log.i(TAG,"B1_ANDROID35_SLOT_" + slot() + "_" + reason + "=DENY");
    setResult(RESULT_CANCELED);
    finish();
  }
  private void succeed() {
    if (done) return;
    done=true;
    setResult(RESULT_OK);
    finish();
  }
  @Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    // Android may recreate an Activity after a harmless configuration or
    // renderer lifecycle change. Do NOT reuse an earlier success, in-memory
    // WebView, JS result or pending callback; rerun ALL store checks for the
    // same exact phase from scratch. A seed that wrote partial data must
    // fail its fresh-data predicate instead of silently continuing.
    if (state!=null) Log.i(TAG,"B1_ANDROID35_SLOT_RECREATED_REVALIDATING=OBSERVED");
    phase=getIntent().getIntExtra("phase",-1);
    boolean appropriate=("A".equals(slot())&&(phase==0||phase==2)) ||
                        ("B".equals(slot())&&(phase==1||phase==3));
    if (!appropriate || !(getPackageName()+":slot"+slot()).equals(
        Application.getProcessName())) { deny("OWNER_OR_PHASE_MISMATCH");return; }
    new Handler(Looper.getMainLooper()).postDelayed(
        () -> deny("RESULT_TIMEOUT"),12000);
    web=new WebView(this);
    WebSettings s=web.getSettings();
    s.setJavaScriptEnabled(true);
    s.setDomStorageEnabled(true);
    s.setAllowFileAccess(false);
    s.setAllowContentAccess(false);
    cookies=CookieManager.getInstance();
    cookies.setAcceptCookie(true);
    // Third-party cookies never enabled in this disposable probe.
    cookies.setAcceptThirdPartyCookies(web,false);
    String read=cookies.getCookie(ORIGIN);
    if (phase==0) {
      if (read!=null && (read.contains("b1a=")||read.contains("b1b="))) {
        deny("PREEXISTING_PROFILE_COOKIE");return;
      }
      cookies.setCookie(ORIGIN,A_COOKIE+"; Secure; SameSite=Lax", ok->{
        if (!Boolean.TRUE.equals(ok)) {deny("A_SET_COOKIE");return;}
        cookies.flush();
        loadAndEvaluate(true,"A");
      });
    } else if (phase==1) {
      if (read!=null && read.contains("b1a=")) {deny("CROSS_COOKIE_A");return;}
      loadAndEvaluate(false,null);
    } else {
      String own=phase==2?"b1a=fixA":"b1b=fixB";
      String foreign=phase==2?"b1b=":"b1a=";
      if (read==null || !read.contains(own) || read.contains(foreign)) {
        deny("COOKIE_PERSISTENCE_OR_CROSS_PROFILE");return;
      }
      loadAndEvaluate(false,phase==2?"A":"B");
    }
  }
  private void loadAndEvaluate(boolean write, String expected) {
    if (done) return;
    web.setWebViewClient(new WebViewClient(){
      @Override public void onPageFinished(WebView view,String url) {
        if(done)return;
        String js=write?
            "(function(){localStorage.setItem('b1k','A');return localStorage.getItem('b1k');})()":
            "(function(){return localStorage.getItem('b1k');})()";
        web.evaluateJavascript(js, result->{
          if(done)return;
          String value=expected==null?"null":"\""+expected+"\"";
          if(!value.equals(result)){deny("LOCALSTORAGE_MISMATCH");return;}
          if(phase==0) {
            // Fresh slot A must not silently overwrite preexisting IndexedDB.
            checkIndexedDb("EMPTY",false,()->checkIndexedDb("A",true,()->succeed()));
          } else if(phase==1) {
            // A new slot B must never see A's IndexedDB even though both
            // processes belong to the same application Linux UID.
            checkIndexedDb("EMPTY",false,()->{
              cookies.setCookie(ORIGIN,B_COOKIE+"; Secure; SameSite=Lax", ok->{
                if (!Boolean.TRUE.equals(ok)) {deny("B_SET_COOKIE");return;}
                cookies.flush();
                web.evaluateJavascript("(function(){localStorage.setItem('b1k','B');"
                    +"return localStorage.getItem('b1k');})()", b->{
                  if(!"\"B\"".equals(b)){deny("B_LOCALSTORAGE_WRITE");return;}
                  checkIndexedDb("B",true,()->succeed());
                });
              });
            });
          } else {
            checkIndexedDb(phase==2?"A":"B",false,()->succeed());
          }
        });
      }
    });
    web.loadDataWithBaseURL(ORIGIN,HTML,"text/html","UTF-8",null);
  }

  /**
   * Asynchronous IndexedDB runs entirely inside the trusted offline fixture.
   * Java only sees a fixed category A/B/EMPTY/FAIL, never an actual account,
   * origin payload, credentials or browser data. No JS/native interface.
   *
   * A write is acknowledged only after IDB transaction.oncomplete, NOT merely
   * after the put request onsuccess; this matters for force-stop persistence.
   */
  private void checkIndexedDb(String expected,boolean write,Runnable next) {
    if(done)return;
    if (write && !("A".equals(expected)||"B".equals(expected))) {
      deny("INDEXEDDB_INVALID_OPERATION");return;
    }
    if (!write && !("A".equals(expected)||"B".equals(expected)||
            "EMPTY".equals(expected))) {
      deny("INDEXEDDB_INVALID_OPERATION");return;
    }
    String transactionMode=write?"readwrite":"readonly";
    String operation=write?("put('"+expected+"','owner')"):"get('owner')";
    String observed=write?("'"+expected+"'"):
        "(r.result===undefined?'EMPTY':String(r.result))";
    String js="(function(){try{window.__b1Idb='WAIT';"
      +"if(!window.indexedDB){window.__b1Idb='FAIL';return 'FAIL';}"
      +"var opened=indexedDB.open('b1_isolated_profile',1);"
      +"opened.onupgradeneeded=function(e){var d=e.target.result;"
      +"if(!d.objectStoreNames.contains('profile'))d.createObjectStore('profile');};"
      +"opened.onerror=function(){window.__b1Idb='FAIL';};"
      +"opened.onsuccess=function(){var db=opened.result;"
      +"var tx=db.transaction('profile','"+transactionMode+"');"
      +"var r=tx.objectStore('profile')."+operation+";"
      +"var outcome='FAIL';"
      +"r.onsuccess=function(){outcome="+observed+";};"
      +"r.onerror=function(){outcome='FAIL';};"
      +"tx.onerror=function(){window.__b1Idb='FAIL';};"
      +"tx.onabort=function(){window.__b1Idb='FAIL';db.close();};"
      +"tx.oncomplete=function(){window.__b1Idb=outcome;db.close();};"
      +"};return 'START';"
      +"}catch(e){window.__b1Idb='FAIL';return 'FAIL';}})()";
    web.evaluateJavascript(js,started->{
      if(done)return;
      if(!"\"START\"".equals(started)) {deny("INDEXEDDB_START");return;}
      pollIndexedDb(0,expected,next);
    });
  }

  private void pollIndexedDb(int count,String expected,Runnable next) {
    if(done)return;
    if(count>=30) {deny("INDEXEDDB_TIMEOUT");return;}
    new Handler(Looper.getMainLooper()).postDelayed(()->{
      if(done)return;
      web.evaluateJavascript("(function(){return window.__b1Idb||'MISSING';})()",value->{
        if(done)return;
        if("\"WAIT\"".equals(value)) {
          pollIndexedDb(count+1,expected,next);
        } else if(("\""+expected+"\"").equals(value)) {
          next.run();
        } else {
          // No JavaScript exception text, database name, or contents logged.
          deny("INDEXEDDB_VALUE_OR_ERROR");
        }
      });
    },150L);
  }
  @Override protected void onDestroy() {
    // Invalidate every outstanding WebView/IndexedDB callback from this
    // Activity instance, even when Android recreates it without finishing.
    done=true;
    if (web!=null) {
      web.stopLoading();
      web.destroy();
    }
    super.onDestroy();
  }
}
