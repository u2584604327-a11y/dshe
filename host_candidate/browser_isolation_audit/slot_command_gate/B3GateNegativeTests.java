package com.dsh.b3;
import com.dsh.b3.B3SlotCommandGate.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class B3GateNegativeTests {
  private static int checks;
  private static void eq(Code a,Code b){checks++;if(a!=b)throw new AssertionError(a+" vs "+b);}
  private static void ok(boolean v){checks++;if(!v)throw new AssertionError("B3_DENY_INVARIANT");}
  private static Decision call(B3SlotCommandGate g,Lease l,Slot s,long e,long n,int b,long t){
    return g.command(l,s,e,n,Op.PROBE_STATUS,b,t);
  }
  public static void main(String[] args)throws Exception{
    B3SlotCommandGate g=new B3SlotCommandGate();
    Lease a=g.activate(Slot.A,101,1000,10000),b=g.activate(Slot.B,201,1000,10000);
    eq(Code.NO_ACTIVE,call(g,null,Slot.A,101,1,1,1001).code);
    eq(Code.WRONG_SLOT,call(g,a,Slot.B,101,1,1,1001).code);
    eq(Code.WRONG_EPOCH,call(g,a,Slot.A,201,1,1,1001).code);
    eq(Code.OUT_OF_ORDER,call(g,a,Slot.A,101,2,1,1001).code);
    for(Op forbidden:new Op[]{Op.ARBITRARY_JS,Op.FILE_ACCESS,Op.COOKIE_EXPORT})
      eq(Code.ACTION_DENIED,g.command(a,Slot.A,101,1,forbidden,1,1001).code);
    eq(Code.SIZE_DENIED,call(g,a,Slot.A,101,1,257,1001).code);
    eq(Code.SIZE_DENIED,call(g,a,Slot.A,101,1,-1,1001).code);
    Decision first=call(g,a,Slot.A,101,1,8,1001);
    eq(Code.ACCEPT,first.code);ok(first.ticket!=null);
    eq(Code.REPLAY,call(g,a,Slot.A,101,1,1,1001).code);
    eq(Code.IN_FLIGHT,call(g,a,Slot.A,101,2,1,1001).code);
    eq(Code.WRONG_RESULT_SLOT,g.result(a,first.ticket,Slot.B,101,1,Op.PROBE_STATUS,1,1002));
    eq(Code.WRONG_EPOCH,g.result(a,first.ticket,Slot.A,999,1,Op.PROBE_STATUS,1,1002));
    eq(Code.WRONG_TICKET,g.result(a,first.ticket,Slot.A,101,2,Op.PROBE_STATUS,1,1002));
    eq(Code.WRONG_RESULT_OP,g.result(a,first.ticket,Slot.A,101,1,Op.READ_SYNTHETIC,1,1002));
    eq(Code.RESULT_SIZE_DENIED,g.result(a,first.ticket,Slot.A,101,1,Op.PROBE_STATUS,513,1002));
    eq(Code.ACCEPT,g.result(a,first.ticket,Slot.A,101,1,Op.PROBE_STATUS,100,1002));
    eq(Code.RESULT_REPLAY,g.result(a,first.ticket,Slot.A,101,1,Op.PROBE_STATUS,1,1002));
    eq(Code.REPLAY,call(g,a,Slot.A,101,1,1,1003).code);
    Decision other=call(g,b,Slot.B,201,1,8,1003);
    eq(Code.ACCEPT,other.code);
    eq(Code.WRONG_TICKET,g.result(b,first.ticket,Slot.B,201,1,Op.PROBE_STATUS,1,1003));
    eq(Code.ACCEPT,g.result(b,other.ticket,Slot.B,201,1,Op.PROBE_STATUS,1,1003));
    Decision pending=call(g,a,Slot.A,101,2,10,1004);
    eq(Code.ACCEPT,pending.code);
    Lease newer=g.activate(Slot.A,102,1005,500);
    eq(Code.REVOKED,call(g,a,Slot.A,101,3,1,1006).code);
    eq(Code.REVOKED,g.result(a,pending.ticket,Slot.A,101,2,Op.PROBE_STATUS,1,1006));
    eq(Code.WRONG_EPOCH,call(g,newer,Slot.A,101,1,1,1006).code);
    eq(Code.EXPIRED,call(g,newer,Slot.A,102,1,1,1505).code);
    Lease fresh=g.activate(Slot.A,103,2000,100);
    Decision delayed=call(g,fresh,Slot.A,103,1,1,2001);
    eq(Code.ACCEPT,delayed.code);
    eq(Code.EXPIRED,g.result(fresh,delayed.ticket,Slot.A,103,1,Op.PROBE_STATUS,1,2100));
    g.revoke(Slot.B);
    eq(Code.REVOKED,call(g,b,Slot.B,201,2,1,1005).code);
    g.revokeAll();
    eq(Code.REVOKED,call(g,fresh,Slot.A,103,2,1,2010).code);
    B3SlotCommandGate race=new B3SlotCommandGate();
    Lease live=race.activate(Slot.A,90,3000,4000);
    CountDownLatch start=new CountDownLatch(1),done=new CountDownLatch(2);
    AtomicInteger accepted=new AtomicInteger(),denied=new AtomicInteger(),bad=new AtomicInteger();
    for(int i=0;i<2;i++)new Thread(()->{
      try{
        start.await();
        Code c=call(race,live,Slot.A,90,1,1,3001).code;
        if(c==Code.ACCEPT)accepted.incrementAndGet();
        else if(c==Code.REPLAY)denied.incrementAndGet();
        else bad.incrementAndGet();
      }catch(Exception e){bad.incrementAndGet();}
      finally{done.countDown();}
    }).start();
    start.countDown();done.await();
    ok(accepted.get()==1&&denied.get()==1&&bad.get()==0);
    Lease parallel=race.activate(Slot.B,91,3000,4000);
    eq(Code.ACCEPT,call(race,parallel,Slot.B,91,1,0,3001).code);
    boolean refused=false;
    try{race.activate(Slot.B,91,3002,B3SlotCommandGate.MAX_LEASE_MS+1);}
    catch(IllegalArgumentException expected){refused=true;}
    ok(refused);
    eq(Code.IN_FLIGHT,call(race,parallel,Slot.B,91,2,1,3004).code);
    if(checks<30)throw new AssertionError("NOT_ENOUGH_NEGATIVE_ASSERTIONS");
    System.out.println("B3_NEGATIVE_ASSERTIONS="+checks);
    System.out.println("B3_HOST_GATE_REPLAY_WRONG_SLOT_REVOKE=PASS");
    System.out.println("B3_CONCURRENT_DUPLICATE_DENIAL=PASS");
    System.out.println("B3_ACTUAL_ANDROID_BINDER_CALLING_UID=NOT_ATTESTED");
    System.out.println("B3_ORIGINAL_BROWSERBRIDGE_ROUTING=NOT_WIRED");
    System.out.println("B3_SAME_UID_SECURITY=NOT_ATTESTED");
    System.out.println("B3_ACCOUNT_USER_DATA_ACCESSED=NO");
    System.out.println("B3_AVF_WORK_PROFILE=NOT_ATTESTED");
    System.out.println("B3_V139=STRUCTURAL_BLOCKED");
  }
}
