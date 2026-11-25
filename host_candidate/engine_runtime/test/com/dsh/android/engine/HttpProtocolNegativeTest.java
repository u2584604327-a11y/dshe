package com.dsh.android.engine;
import java.io.*;import java.net.*;import java.nio.*;import java.nio.charset.StandardCharsets;
import java.nio.file.*;import java.security.*;import java.util.*;import java.util.concurrent.*;
import javax.crypto.Mac;import javax.crypto.spec.SecretKeySpec;
public final class HttpProtocolNegativeTest {
 static int checks;static void yes(boolean b,String n){checks++;if(!b)throw new AssertionError(n);}
 static byte[] zeros=new byte[32];
 static void hostRejects(String node,String peer,String mode,String expected)throws Exception{
  Process child=new ProcessBuilder(node,"--permission","--allow-fs-read="+peer,peer,mode).start();
  HttpProcessTransport transport=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
  int port=transport.port();Socket held=null;
  try{
   if(mode.equals("RESERVED_CREDIT")){yes(transport.awaitListening(3,TimeUnit.SECONDS),"listener_for_credit");held=new Socket("127.0.0.1",port);}
   yes(child.waitFor(5,TimeUnit.SECONDS),"bad_peer_revoked_"+mode);
   yes(transport.failure().startsWith(expected),"bad_peer_reason_"+mode+"="+transport.failure());
   try(Socket ignored=new Socket("127.0.0.1",port)){throw new AssertionError("revoked_port");}catch(ConnectException correct){checks++;}
  }finally{if(held!=null)held.close();transport.close();}
 }
 static byte[] frame(int type,int seq,int id,byte[] data,int declared,String mode)throws Exception{
  byte[] header=ByteBuffer.allocate(21).putInt(0x44484631).put((byte)type).putLong(seq).putInt(id).putInt(declared).array();
  Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(zeros,"HmacSHA256"));
  mac.update((byte)(mode.equals("REFLECT")?'N':'H'));mac.update(zeros);mac.update(ByteBuffer.allocate(8).putLong(mode.equals("OLD_EPOCH")?2:1).array());mac.update(header);
  byte[] signature=mac.doFinal(data);if(mode.equals("BAD_MAC"))signature[0]^=1;
  return ByteBuffer.allocate(53+data.length).put(header).put(signature).put(data).array();
 }
 static void nodeRejects(String node,String fixture,String source,String mode,String expected)throws Exception{
  Process child=new ProcessBuilder(node,"--permission","--allow-fs-read="+fixture,"--allow-fs-read="+source,fixture,source).start();
  try{
   DataOutputStream out=new DataOutputStream(child.getOutputStream());out.writeBytes("DSHHTTP1");out.write(zeros);out.write(zeros);out.writeLong(1);out.writeInt(0);out.writeInt(10000);out.flush();
   DataInputStream in=new DataInputStream(child.getInputStream());byte[] head=new byte[53];in.readFully(head);yes(head[4]==16,"node_original_http_listen");in.readFully(new byte[4]);
   byte[] attack;
   if(mode.equals("OVERSIZE"))attack=frame(7,1,0,new byte[0],16385,mode);
   else if(mode.equals("REMOTE_BIND"))attack=frame(1,1,1,new byte[]{8,8,8,8,0,0,0,80},8,mode);
   else if(mode.equals("CREDIT"))attack=frame(8,1,0,new byte[]{0,0,0,1},4,mode);
   else attack=frame(7,1,0,new byte[0],0,mode);
   out.write(attack);if(mode.equals("REPLAY"))out.write(attack);out.flush();
   yes(child.waitFor(5,TimeUnit.SECONDS),"bad_host_node_exited_"+mode);
   yes(child.exitValue()==125,"bad_host_node_exit_"+mode);
   byte[] stderr=new byte[1024];int n=child.getErrorStream().read(stderr);
   String fixed=n<0?"":new String(stderr,0,n,StandardCharsets.US_ASCII);
   yes(fixed.contains("DSH_RUNTIME_TRANSPORT_DENY="+expected),"bad_host_reason_"+mode);
  }finally{child.destroyForcibly();child.waitFor();}
 }
 public static void main(String[] a)throws Exception{
  for(String mode:new String[]{"BAD_MAC","OLD_SESSION","REPLAY","OVERSIZE","UNSOLICITED","DUP_LISTEN","CREDIT","RESERVED_CREDIT"})
   hostRejects(a[0],a[1],mode,mode.equals("BAD_MAC")||mode.equals("OLD_SESSION")?"FRAME_AUTH":
       mode.equals("REPLAY")||mode.equals("OVERSIZE")?"FRAME_SHAPE":mode.equals("UNSOLICITED")?"CONNECTION_ID":
       mode.equals("DUP_LISTEN")?"LISTEN_REPLAY":"CREDIT_OVERFLOW");
  for(String mode:new String[]{"BAD_MAC","OLD_EPOCH","REFLECT","REPLAY","OVERSIZE","REMOTE_BIND","CREDIT"})
   nodeRejects(a[0],a[2],a[3],mode,mode.equals("REMOTE_BIND")?"E_DSH_IPC_OPEN":mode.equals("CREDIT")?"E_DSH_IPC_CREDIT":
       mode.equals("REPLAY")||mode.equals("OVERSIZE")?"E_DSH_IPC_FRAME":"E_DSH_IPC_AUTH");
  System.out.println("HTTP_PROCESS_PROTOCOL_REPLAY_GENERATION_AUTH_AND_CREDIT_NEGATIVES=PASS checks="+checks);
 }
}
