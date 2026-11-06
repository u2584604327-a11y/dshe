package com.dsh.b3;

/** Host-owned policy prototype ONLY. Not an Android Binder/OS identity proof. */
public final class B3SlotCommandGate {
  public enum Slot { A, B }
  public enum Op { PROBE_STATUS, READ_SYNTHETIC, ARBITRARY_JS, FILE_ACCESS, COOKIE_EXPORT }
  public enum Code { ACCEPT, NO_ACTIVE, WRONG_SLOT, WRONG_EPOCH, EXPIRED, REVOKED,
    REPLAY, OUT_OF_ORDER, IN_FLIGHT, ACTION_DENIED, SIZE_DENIED,
    WRONG_TICKET, RESULT_REPLAY, WRONG_RESULT_SLOT, RESULT_SIZE_DENIED }
  public static final int MAX_COMMAND_BYTES=256, MAX_RESULT_BYTES=512;
  public static final long MAX_LEASE_MS=15000L;
  public static final class Lease {
    private final Slot slot;
    private final long epoch,deadline;
    private boolean revoked;
    private long next=1;
    private Ticket pending;
    private Lease(Slot slot,long epoch,long deadline){
      this.slot=slot;this.epoch=epoch;this.deadline=deadline;
    }
  }
  public static final class Ticket {
    private final Lease lease;
    private final long seq;
    private boolean consumed;
    private Ticket(Lease lease,long seq){this.lease=lease;this.seq=seq;}
  }
  public static final class Decision {
    public final Code code;
    public final Ticket ticket;
    private Decision(Code code,Ticket ticket){this.code=code;this.ticket=ticket;}
  }
  private final java.util.EnumMap<Slot,Lease> active=
      new java.util.EnumMap<>(Slot.class);
  private static Decision deny(Code code){return new Decision(code,null);}
  /** Host must verify its own account-selection authority BEFORE calling. */
  public synchronized Lease activate(Slot slot,long epoch,long now,long ttl){
    if(slot==null||epoch<=0||now<0||ttl<=0||ttl>MAX_LEASE_MS||
        now>Long.MAX_VALUE-ttl)
      throw new IllegalArgumentException("B3_INVALID_HOST_ACTIVATION");
    Lease old=active.get(slot);
    if(old!=null){old.revoked=true;old.pending=null;}
    Lease current=new Lease(slot,epoch,now+ttl);
    active.put(slot,current);
    return current;
  }
  public synchronized void revoke(Slot slot){
    if(slot==null)return;
    Lease old=active.remove(slot);
    if(old!=null){old.revoked=true;old.pending=null;}
  }
  public synchronized void revokeAll(){
    for(Slot s:Slot.values())revoke(s);
  }
  private Code state(Lease lease,Slot slot,long epoch,long now){
    if(lease==null||slot==null)return Code.NO_ACTIVE;
    if(lease.slot!=slot)return Code.WRONG_SLOT;
    if(lease.revoked)return Code.REVOKED;
    if(active.get(slot)!=lease)return Code.NO_ACTIVE;
    if(lease.epoch!=epoch)return Code.WRONG_EPOCH;
    if(now<0||now>=lease.deadline)return Code.EXPIRED;
    return Code.ACCEPT;
  }
  public synchronized Decision command(Lease lease,Slot slot,long epoch,
      long seq,Op op,int trustedMeasuredBytes,long now){
    Code s=state(lease,slot,epoch,now);
    if(s!=Code.ACCEPT)return deny(s);
    if(seq<lease.next)return deny(Code.REPLAY);
    if(seq!=lease.next)return deny(Code.OUT_OF_ORDER);
    if(lease.pending!=null)return deny(Code.IN_FLIGHT);
    if(op!=Op.PROBE_STATUS&&op!=Op.READ_SYNTHETIC)
      return deny(Code.ACTION_DENIED);
    if(trustedMeasuredBytes<0||trustedMeasuredBytes>MAX_COMMAND_BYTES)
      return deny(Code.SIZE_DENIED);
    if(lease.next==Long.MAX_VALUE)return deny(Code.OUT_OF_ORDER);
    Ticket t=new Ticket(lease,seq);
    lease.pending=t;
    lease.next++;
    return new Decision(Code.ACCEPT,t);
  }
  public synchronized Code result(Lease lease,Ticket ticket,Slot slot,
      long epoch,long seq,int trustedMeasuredBytes,long now){
    Code s=state(lease,slot,epoch,now);
    if(s==Code.WRONG_SLOT)return Code.WRONG_RESULT_SLOT;
    if(s!=Code.ACCEPT)return s;
    if(ticket==null||ticket.lease!=lease)return Code.WRONG_TICKET;
    if(ticket.consumed)return Code.RESULT_REPLAY;
    if(lease.pending!=ticket||ticket.seq!=seq)return Code.WRONG_TICKET;
    if(trustedMeasuredBytes<0||trustedMeasuredBytes>MAX_RESULT_BYTES)
      return Code.RESULT_SIZE_DENIED;
    ticket.consumed=true;
    lease.pending=null;
    return Code.ACCEPT;
  }
}
