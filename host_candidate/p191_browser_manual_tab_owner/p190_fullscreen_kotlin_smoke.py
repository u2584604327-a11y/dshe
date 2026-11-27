#!/usr/bin/env python3
"""Extract the EXACT P190 view fields and methods from the patch AST for Kotlin JVM validation.
This never represents a real Android render/build; mock classes are explicit.
"""
import ast
from pathlib import Path
r=Path(__file__).parent
mod=ast.parse((r/'patch_original_browser.py').read_text())
fn=next(node for node in mod.body if isinstance(node,ast.FunctionDef) and node.name=='patch_view')
fragments=[]
for call in ast.walk(fn):
    if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=='once' and len(call.args)>=3:
        value=call.args[2]
        if isinstance(value,ast.Constant) and isinstance(value.value,str):
            if 'P190: exactly the SAME WebView' in value.value:fragments.append(value.value)
assert len(fragments)==1
view_code=fragments[0]
assert 'private fun enterManualFullscreen()' in view_code and 'private fun exitManualFullscreen()' in view_code
assert all(x not in view_code for x in ('loadUrl(','.reload(','.destroy(','CookieManager','setUserAgent'))
stub='''package com.dsh.android.browser
class BrowserBridge {
  companion object { var manual=false; fun isManualTakeover():Boolean=manual }
}
object Gravity { const val TOP=4; const val START=8; const val END=16; const val CENTER=32 }
open class View {
  var visibility:Int=VISIBLE
  open var layoutParams:FrameLayout.LayoutParams?=null
  fun bringToFront(){}
  fun setOnClickListener(callback:()->Unit){ click=callback }
  var click:(()->Unit)?=null
  companion object {const val VISIBLE=0}
}
open class FrameLayout:View(){
  open class LayoutParams(var width:Int,var height:Int,var gravity:Int=0){
    var leftMargin=0;var topMargin=0;var rightMargin=0;var bottomMargin=0
    fun setMargins(l:Int,t:Int,r:Int,b:Int){leftMargin=l;topMargin=t;rightMargin=r;bottomMargin=b}
    companion object {const val MATCH_PARENT=-1}
  }
  val children=mutableListOf<View>()
  fun addView(v:View,p:LayoutParams){v.layoutParams=p;children.add(v)}
  fun removeView(v:View){children.remove(v)}
}
class TextView(val context:Any):View(){
  var text:String="";var textSize:Float=0f;var gravity:Int=0
  fun setTextColor(v:Int){}
  fun setBackgroundColor(v:Int){}
  fun setPadding(l:Int,t:Int,r:Int,b:Int){}
}
class AiBrowserView:FrameLayout(){
  val context:Any=Any()
  var applied=0
  var cleared=0
  fun dp(x:Int)=x
  fun applyEmbedRect(l:Int,t:Int,w:Int,h:Int){
    if(manualFullscreen){deferredManualEmbed=intArrayOf(l,t,w,h);return}
    applied++
    val p=layoutParams!!;p.width=w;p.height=h;p.leftMargin=l;p.topMargin=t
  }
  fun clearEmbedRect(){
    if(manualFullscreen){deferredManualEmbed=intArrayOf();return}
    cleared++
  }
''' + view_code + '''
  fun enter():Boolean=enterManualFullscreen()
  fun exit():Boolean=exitManualFullscreen()
  fun isFullscreen():Boolean=manualFullscreen
  fun clickExit(){manualExitButton?.click?.invoke()}
}
fun main(){
  val view=AiBrowserView()
  val initial=FrameLayout.LayoutParams(270,410).apply{setMargins(15,21,0,0)}
  view.layoutParams=initial
  check(!view.enter())
  check(view.layoutParams===initial)
  BrowserBridge.manual=true
  check(view.enter())
  check(view.isFullscreen())
  check(view.layoutParams!!.width == -1)
  check(view.children.size==1)
  check(!view.enter())
  view.applyEmbedRect(30,48,280,360)
  check(view.applied==0)
  check(view.exit())
  check(!view.isFullscreen())
  check(view.children.isEmpty())
  check(view.applied==1)
  check(view.layoutParams!!.leftMargin==30)
  check(BrowserBridge.isManualTakeover())
  check(view.enter())
  view.clearEmbedRect()
  check(view.cleared==0)
  view.clickExit()
  check(view.cleared==1)
  check(BrowserBridge.isManualTakeover())
  BrowserBridge.manual=false
  check(!view.enter())
  println("P190_EXACT_FULLSCREEN_KOTLIN_METHODS=PASS checks=19")
}
'''
(r/'P190ExactFullscreenKotlinStub.kt').write_text(stub)
print('P190_EXACT_KOTLIN_AST_FULLSCREEN_CODE=PASS')
