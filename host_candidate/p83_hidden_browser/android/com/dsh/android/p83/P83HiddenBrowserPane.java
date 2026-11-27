package com.dsh.android.p83;

import android.app.Activity;
import android.content.SharedPreferences;
import com.dsh.android.p185.P185ManualVerificationState;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * P83 foreground in-app browser/chat panel switch. The WebView remains
 * attached and VISIBLE beneath an opaque chat overlay while hidden.
 * This avoids WebView destroy/recreation and supports evaluateJavascript
 * callbacks while the user sees chat/status. NOT an OS background service.
 * Never self-approves external side effects.
 */
public final class P83HiddenBrowserPane {
  private final Activity owner;
  private final WebView web;
  private final FrameLayout root;
  private final LinearLayout chatOverlay;
  private final TextView status;
  private final Button hideButton;
  private final Button showButton;
  private final Button startManualButton;
  private final Button endManualButton;
  private final CheckBox manualOptIn;
  private final P185ManualVerificationState manual=new P185ManualVerificationState();
  private final SharedPreferences manualPrefs;
  private final int originalIdentity;
  private boolean hidden;
  private int completed,total=6;

  public P83HiddenBrowserPane(Activity activity,WebView browser) {
    if(activity==null || browser==null ||
       !"com.dsh.p51.isolatedprobe".equals(activity.getPackageName()) ||
       Looper.myLooper()!=Looper.getMainLooper() ||
       browser.getParent()!=null)
      throw new SecurityException("P83_TRUSTED_FOREGROUND_SIDECAR_ONLY");
    owner=activity;web=browser;
    manualPrefs=activity.getSharedPreferences("p185_manual_challenge_option",0);
    manual.setEnabled(manualPrefs.getBoolean("enabled",false));
    originalIdentity=System.identityHashCode(browser);
    root=new FrameLayout(activity);
    root.setBackgroundColor(Color.rgb(15,23,42));
    root.addView(web,new FrameLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT));
    chatOverlay=new LinearLayout(activity);
    chatOverlay.setOrientation(LinearLayout.VERTICAL);
    chatOverlay.setBackgroundColor(Color.rgb(16,22,36));
    chatOverlay.setPadding(32,55,32,24);
    FrameLayout.LayoutParams page=new FrameLayout.LayoutParams(
       ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT);
    root.addView(chatOverlay,page);
    TextView title=label("DSH · AI 浏览助手",22,Color.WHITE);
    title.setTypeface(null,Typeface.BOLD);
    chatOverlay.addView(title);
    TextView explainer=label("浏览器已隐藏，聊天界面可继续使用。\n正在执行的页面操作不会因为收起面板而重置。",16,
         Color.rgb(193,204,224));
    LinearLayout.LayoutParams explain=new LinearLayout.LayoutParams(
       ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT);
    explain.topMargin=36;
    chatOverlay.addView(explainer,explain);
    status=label("",16,Color.rgb(147,197,253));
    LinearLayout.LayoutParams state=new LinearLayout.LayoutParams(
       ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT);
    state.topMargin=48;
    chatOverlay.addView(status,state);
    TextView confirmation=label(
       "评论、私信或提交等对外操作需要明确批准。\n此页面仅为本地模拟，未访问 B 站。",15,
       Color.rgb(203,213,225));
    LinearLayout.LayoutParams consent=new LinearLayout.LayoutParams(
       ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT);
    consent.topMargin=36;
    chatOverlay.addView(confirmation,consent);
    manualOptIn=new CheckBox(activity);
    manualOptIn.setText("允许人工验证模式（可选）");
    manualOptIn.setTextColor(Color.WHITE);
    manualOptIn.setChecked(manual.isEnabled());
    chatOverlay.addView(manualOptIn);
    startManualButton=new Button(activity);
    startManualButton.setText("在当前内置浏览器中人工验证");
    startManualButton.setAllCaps(false);
    startManualButton.setVisibility(manual.isEnabled()?View.VISIBLE:View.GONE);
    startManualButton.setOnClickListener(v->beginManualVerification());
    chatOverlay.addView(startManualButton);
    manualOptIn.setOnCheckedChangeListener((v,checked)->{
      requireMain();
      manual.setEnabled(checked);
      manualPrefs.edit().putBoolean("enabled",checked).apply();
      startManualButton.setVisibility(checked?View.VISIBLE:View.GONE);
    });
    showButton=new Button(activity);
    showButton.setText("打开浏览器");
    showButton.setAllCaps(false);
    showButton.setOnClickListener(v->showBrowser());
    LinearLayout.LayoutParams open=new LinearLayout.LayoutParams(
       ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT);
    open.topMargin=42;
    chatOverlay.addView(showButton,open);
    hideButton=new Button(activity);
    hideButton.setText("隐藏浏览器 · 返回聊天");
    hideButton.setAllCaps(false);
    hideButton.setOnClickListener(v->hideBrowser());
    FrameLayout.LayoutParams button=new FrameLayout.LayoutParams(
      ViewGroup.LayoutParams.WRAP_CONTENT,ViewGroup.LayoutParams.WRAP_CONTENT,
      Gravity.TOP|Gravity.END);
    button.topMargin=24;button.rightMargin=16;
    root.addView(hideButton,button);
    endManualButton=new Button(activity);
    endManualButton.setText("结束人工操作 · 返回聊天");
    endManualButton.setAllCaps(false);
    endManualButton.setOnClickListener(v->endManualVerification());
    FrameLayout.LayoutParams manualExit=new FrameLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT,ViewGroup.LayoutParams.WRAP_CONTENT,
        Gravity.BOTTOM|Gravity.CENTER_HORIZONTAL);
    manualExit.bottomMargin=16;
    root.addView(endManualButton,manualExit);
    endManualButton.setVisibility(View.GONE);
    chatOverlay.setVisibility(View.GONE);
    refresh();
  }
  private TextView label(String value,int sp,int color){
    TextView view=new TextView(owner);
    view.setText(value);view.setTextColor(color);view.setTextSize(sp);
    return view;
  }
  public void attach(){
    if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("P83_MAIN_THREAD");
    owner.setContentView(root);
  }
  public void hideBrowser(){
    requireMain();
    // The person must keep the actual challenge page interactable until
    // explicitly ending takeover. Do not cover the WebView automatically.
    if(manual.isTakeover())return;
    hidden=true;
    // Never call WebView.setVisibility(GONE), onPause(), removeView(),
    // destroy(), loadUrl() or CookieManager clear functions.
    web.setVisibility(View.VISIBLE);
    chatOverlay.setVisibility(View.VISIBLE);
    hideButton.setVisibility(View.GONE);
    refresh();
  }
  public void showBrowser(){
    requireMain();
    hidden=false;
    chatOverlay.setVisibility(View.GONE);
    hideButton.setVisibility(View.VISIBLE);
    web.setVisibility(View.VISIBLE);
    refresh();
  }
  /** Optional feature: opt-in only; preserves this exact WebView and page. */
  public boolean beginManualVerification(){
    requireMain();
    if(web.getParent()!=root || !web.isAttachedToWindow() ||
       System.identityHashCode(web)!=originalIdentity ||
       !manual.beginFromUser())return false;
    // Hide chat overlay, do NOT reload URL, reset cookies, change UA,
    // inject challenge scripts, or claim to solve site verification.
    showBrowser();
    hideButton.setVisibility(View.GONE);
    endManualButton.setVisibility(View.VISIBLE);
    return true;
  }
  /** User may end the manual interaction; no site success is inferred. */
  public boolean endManualVerification(){
    requireMain();
    if(!manual.endFromUser())return false;
    endManualButton.setVisibility(View.GONE);
    hideButton.setVisibility(View.VISIBLE);
    hideBrowser();
    return true;
  }
  /** The actual AI browser dispatcher MUST enforce this when integrated. */
  public boolean isAutomationPaused(){return manual.isTakeover();}
  public boolean isManualVerificationEnabled(){return manual.isEnabled();}
  public void revokeManualVerification(){
    requireMain();
    manual.revoke();
    endManualButton.setVisibility(View.GONE);
  }
  public void completedStep(int n,int max){
    requireMain();
    completed=n;total=max;refresh();
  }
  public boolean isHiddenAndAttached(){
    requireMain();
    return hidden && chatOverlay.getVisibility()==View.VISIBLE &&
           web.getVisibility()==View.VISIBLE && web.getParent()==root &&
           web.isAttachedToWindow() &&
           System.identityHashCode(web)==originalIdentity;
  }
  public boolean isRestoredSameWebView(){
    requireMain();
    return !hidden && chatOverlay.getVisibility()==View.GONE &&
           hideButton.getVisibility()==View.VISIBLE &&
           web.getVisibility()==View.VISIBLE && web.getParent()==root &&
           web.isAttachedToWindow() &&
           System.identityHashCode(web)==originalIdentity;
  }
  public boolean isHidden(){return hidden;}
  private void refresh(){status.setText("● AI 浏览中    已完成 "+completed+"/"+total+" 步");}
  private void requireMain(){
    if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("P83_MAIN_THREAD");
  }
}
