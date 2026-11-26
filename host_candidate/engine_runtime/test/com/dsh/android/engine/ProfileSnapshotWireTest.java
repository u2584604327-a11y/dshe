package com.dsh.android.engine;
import java.io.*;import java.net.*;import java.nio.*;import java.security.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;
import java.nio.file.attribute.*;import java.util.*;import java.util.concurrent.*;
/** Real host Node stdio/HMAC and real host durable storage. Synthetic payloads;
 * no Android Binder owner, original profile, original coroutine or READY claim. */
public final class ProfileSnapshotWireTest {
 static int checks;static String node,adapter,peer,attack;static final String OWNER=String.join("",Collections.nCopies(64,"a"));
 static void yes(boolean v,String code){checks++;if(!v)throw new AssertionError(code);}
 static Process start(String script,String... args)throws Exception{
  List<String> cmd=new ArrayList<>(Arrays.asList(node,"--permission","--allow-fs-read="+Paths.get(script).getParent().getParent(),"--allow-fs-read="+adapter,script));
  cmd.addAll(Arrays.asList(args));ProcessBuilder b=new ProcessBuilder(cmd);b.environment().clear();return b.start();
 }
 static Path root()throws Exception{Path root=Files.createTempDirectory("dsh-wire-owner-");Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));return root;}
 static void clean(Path root)throws Exception{for(String name:new String[]{"snapshot.bin","owner.lock"})Files.deleteIfExists(root.resolve(name));Files.delete(root);}
 static void drain(InputStream in){Thread t=new Thread(()->{try{byte[] bytes=new byte[1024];while(in.read(bytes)!=-1){}}catch(IOException ignored){}});t.setDaemon(true);t.start();}
 static void generation(Path root,int initial,int commits)throws Exception{
  Process child=start(peer,adapter,Integer.toString(initial));
  HttpProtocolNegativeTest.DrainedExit supervised=new HttpProtocolNegativeTest.DrainedExit(child);
  HttpProcessTransport process=new HttpProcessTransport(supervised,OWNER,System.nanoTime(),0,false,new DurableSessionSnapshot(root,OWNER));
  drain(process.getInputStream());drain(process.getErrorStream());
  try{
   yes(process.awaitListening(5,TimeUnit.SECONDS),"snapshot_init_before_actual_listen_"+process.failure());
   for(int i=1;i<=commits;i++){
    HttpURLConnection connection=(HttpURLConnection)new URL("http://127.0.0.1:"+process.port()+"/commit").openConnection();
    connection.setConnectTimeout(3000);connection.setReadTimeout(5000);
    try{yes(connection.getResponseCode()==200,"real_http_during_sync_commit");try(InputStream in=connection.getInputStream()){
     ByteArrayOutputStream bytes=new ByteArrayOutputStream();int b;while((b=in.read())!=-1)bytes.write(b);
     yes(bytes.toString("US-ASCII").equals(Integer.toString(initial+i)),"response_after_durable_ack");
    }}finally{connection.disconnect();}
   }
   process.destroy();yes(process.waitFor(5,TimeUnit.SECONDS),"main_style_exit_releases_exact_producer");
   yes(process.exitValue()==0&&process.failure().equals("NONE/NONE"),"actual_exit_without_false_protocol_failure_"+process.failure());
  }finally{process.close();yes(process.awaitClosed(5,TimeUnit.SECONDS),"owner_handles_closed_before_restart");}
  try(DurableSessionSnapshot restored=new DurableSessionSnapshot(root,OWNER)){
   byte[] data=new byte[96*1024];for(int i=0;i<data.length;i++)data[i]=(byte)(i+initial+commits);
   yes(restored.read().version==initial+commits,"acknowledged_version_on_disk");
   yes(Arrays.equals(restored.read().bytes,DurableSessionSnapshotTest.snapshot("/dsh-home/record",data)),"acknowledged_exact_bytes_on_disk");
  }
 }
 static void deny(Path root,String mode,String expected)throws Exception{
  DurableSessionSnapshot store=mode.equals("UNGRANTED")?null:new DurableSessionSnapshot(root,OWNER);
  Process child=start(attack,mode);HttpProcessTransport process=new HttpProcessTransport(child,OWNER,System.nanoTime(),0,false,store);
  drain(process.getInputStream());drain(process.getErrorStream());
  try{yes(child.waitFor(6,TimeUnit.SECONDS),"attack_revoked_"+mode);yes(process.failure().startsWith(expected+"/"),"attack_refusal_"+mode+"="+process.failure());}
  finally{process.close();yes(process.awaitClosed(5,TimeUnit.SECONDS),"denied_owner_handles_released");}
  try(DurableSessionSnapshot intact=new DurableSessionSnapshot(root,OWNER)){yes(intact.read().version==0,"negative_did_not_commit_"+mode);}
 }
 static void badAck(String mode,String expected)throws Exception{
  Path root=root();byte[] initial;try(DurableSessionSnapshot store=new DurableSessionSnapshot(root,OWNER)){initial=store.read().bytes;}finally{clean(root);}
  Process child=start(peer,adapter,"0","COMMIT_NOW");
  try{
   DataOutputStream out=new DataOutputStream(child.getOutputStream());out.writeBytes("DSHHTTP1");out.write(new byte[64]);out.writeLong(1);out.writeInt(0);out.writeInt(10000);
   byte[] meta=ByteBuffer.allocate(44).putLong(0).putInt(initial.length).put(MessageDigest.getInstance("SHA-256").digest(initial)).array();
   out.write(HttpProtocolNegativeTest.frame(11,1,0,meta,meta.length,"NORMAL"));
   out.write(HttpProtocolNegativeTest.frame(12,2,0,initial,initial.length,"NORMAL"));
   out.write(HttpProtocolNegativeTest.frame(13,3,0,new byte[0],0,"NORMAL"));out.flush();
   DataInputStream in=new DataInputStream(child.getInputStream());int frames=0;
   for(;;){byte[] header=new byte[53];in.readFully(header);int length=ByteBuffer.wrap(header,17,4).getInt();yes(length>=0&&length<=16384,"outgoing_frame_bound");in.readFully(new byte[length]);if(header[4]==28)break;if(++frames>10)throw new AssertionError("commit_frame_bound");}
   byte[] ack=ByteBuffer.allocate(9).putLong(mode.equals("VERSION")?2:1).put((byte)0).array();
   out.write(HttpProtocolNegativeTest.frame(14,mode.equals("REPLAY")?3:4,mode.equals("ID")?2:1,ack,9,mode));out.flush();
   yes(child.waitFor(5,TimeUnit.SECONDS),"malicious_ack_child_exit_"+mode);yes(child.exitValue()==125,"malicious_ack_no_success_"+mode);
   ByteArrayOutputStream diagnostic=new ByteArrayOutputStream();byte[] block=new byte[512];int n;while((n=child.getErrorStream().read(block))!=-1){if(diagnostic.size()+n>4096)throw new AssertionError("diagnostic_bound");diagnostic.write(block,0,n);}
   yes(diagnostic.toString("US-ASCII").contains("DSH_RUNTIME_TRANSPORT_DENY="+expected),"malicious_ack_reason_"+mode);
  }finally{child.destroyForcibly();child.waitFor();}
 }
 public static void main(String[] args)throws Exception{
  node=args[0];adapter=args[1];peer=args[2];attack=args[3];Path root=root(),other=root();
  try{
   generation(root,0,2);generation(root,2,1);generation(other,0,1);
   for(String[] test:new String[][]{{"UNGRANTED","STORE_WIRE_NOT_AUTHORIZED"},{"STALE","STORE_STALE_VERSION"},{"PATH","SNAPSHOT_PATH"},{"HASH","STORE_WIRE_SEAL"},{"REPLAY","STORE_WIRE_BEGIN"},{"OVERRUN","STORE_WIRE_DATA"},{"TRUNCATED","STORE_WIRE_COMMIT"}}){Path negative=root();try{deny(negative,test[0],test[1]);}finally{clean(negative);}}
   for(String[] test:new String[][]{{"VERSION","E_DSH_STORE_COMMIT_REJECTED"},{"ID","E_DSH_STORE_ACK"},{"REPLAY","E_DSH_IPC_FRAME"},{"BAD_MAC","E_DSH_IPC_AUTH"},{"OLD_EPOCH","E_DSH_IPC_AUTH"}})badAck(test[0],test[1]);
   System.out.println("HOST_SNAPSHOT_STDIO_SYNC_COMMIT_DURABLE_RESTART_AND_NEGATIVES=PASS checks="+checks);
   System.out.println("SNAPSHOT_ORIGINAL_PROFILE_ANDROID_BINDER_AND_PRODUCTION_OWNER=NOT_TESTED");
  }finally{clean(root);clean(other);}
 }
}
