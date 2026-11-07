package com.dsh.android.p150;
import java.util.concurrent.atomic.AtomicInteger;
/** Stack shape observation only; never an OS identity or permission grant. */
public final class P150OriginalCoroutineObserver {
  private static final AtomicInteger original=new AtomicInteger(),other=new AtomicInteger();
  private P150OriginalCoroutineObserver(){}
  public static boolean isOriginalStack(StackTraceElement[] frames){
    if(frames==null||frames.length==0||frames.length>512)return false;
    int p47=-1,p40=-1,engine=-1;
    for(int i=0;i<frames.length;i++){
      StackTraceElement x=frames[i];
      if(x==null)return false;
      if(x.getClassName().equals("com.dsh.android.p47.P47LaunchGate")&&
         x.getMethodName().equals("startOrDeny")) {
        if(p47>=0)return false;p47=i;
      }else if(x.getClassName().equals("com.dsh.android.p40.P40ProcessBridge")&&
               x.getMethodName().equals("start")) {
        if(p40>=0)return false;p40=i;
      }else if(x.getClassName().equals("com.dsh.android.EngineManager$start$2")&&
               x.getMethodName().equals("invokeSuspend")) {
        if(engine>=0)return false;engine=i;
      }
    }
    return p47>=0&&p40>p47&&engine>p40&&p40-p47<=5&&engine-p40<=8;
  }
  public static void recordFromP47(){
    AtomicInteger target=isOriginalStack(Thread.currentThread().getStackTrace())?original:other;
    target.updateAndGet(v->Math.min(v+1,1000000));
  }
  public static int observedOriginal(){return original.get();}
  public static int observedOther(){return other.get();}
}
