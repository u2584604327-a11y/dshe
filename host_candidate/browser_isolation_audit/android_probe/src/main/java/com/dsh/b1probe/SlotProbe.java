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
    if (state!=null) { deny("RESTORE_UNEXPECTED");return; }
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
          if(phase==1) {
            cookies.setCookie(ORIGIN,B_COOKIE+"; Secure; SameSite=Lax", ok->{
              if (!Boolean.TRUE.equals(ok)) {deny("B_SET_COOKIE");return;}
              cookies.flush();
              web.evaluateJavascript("(function(){localStorage.setItem('b1k','B');"
                  +"return localStorage.getItem('b1k');})()", b->{
                if(!"\"B\"".equals(b)){deny("B_LOCALSTORAGE_WRITE");return;}
                succeed();
              });
            });
          } else succeed();
        });
      }
    });
    web.loadDataWithBaseURL(ORIGIN,HTML,"text/html","UTF-8",null);
  }
  @Override protected void onDestroy() {
    if (web!=null) {
      web.stopLoading();
      web.destroy();
    }
    super.onDestroy();
  }
}
