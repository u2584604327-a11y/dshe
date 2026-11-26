package com.dsh.android.engine;
import java.io.*;import java.nio.file.*;import java.nio.file.attribute.*;import java.util.*;import java.util.concurrent.*;
/** Real host filesystem/force/rename/lock and restart. Not an Android claim. */
public final class DurableSessionSnapshotTest {
  private static final String OWNER=String.join("",Collections.nCopies(64,"a"));
  private static int checks;
  private static void yes(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
  private interface Checked{void run()throws Exception;}
  private static void denied(Checked code,String reason)throws Exception{try{code.run();}catch(IOException failure){yes(failure.getMessage().equals(reason),"wrong_refusal_"+reason);return;}throw new AssertionError("accepted_"+reason);}
  static byte[] snapshot(String name,byte[] value)throws Exception{
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);out.writeBytes("DSHFS001");out.writeInt(3);
    for(String path:new String[]{"/dsh-home","/dsh-workspace",name}){byte[] encoded=path.getBytes("UTF-8");out.writeShort(encoded.length);out.write(encoded);boolean dir=!path.equals(name);out.writeByte(dir?1:0);out.writeShort(dir?0700:0600);out.writeLong(1);out.writeInt(dir?0:value.length);if(!dir)out.write(value);}return bytes.toByteArray();
  }
  public static void main(String[] args)throws Exception{
    if(args.length==2&&args[0].equals("--halt")){
      DurableSessionSnapshot store=new DurableSessionSnapshot(Paths.get(args[1]),OWNER);
      store.commit(0,snapshot("/dsh-home/record",new byte[]{4,5,6}));
      Runtime.getRuntime().halt(17);return;
    }
    boolean android=args.length==2&&args[0].equals("--android");
    if(android){
      yes(((Integer)Class.forName("android.os.Process").getMethod("myUid").invoke(null))==2000,"actual_shell_uid");
      yes(Class.forName("android.os.Build$VERSION").getField("SDK_INT").getInt(null)==35,"actual_android35");
    }
    Path root=android?Files.createTempDirectory(Paths.get(args[1]),"dsh-durable-owner-"):Files.createTempDirectory("dsh-durable-owner-");Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));
    byte[] first=snapshot("/dsh-home/record",new byte[]{1,2,3}),second=snapshot("/dsh-home/record",new byte[]{4,5,6});
    try{
      try(DurableSessionSnapshot store=new DurableSessionSnapshot(root,OWNER)){
        yes(store.read().version==0,"empty_version");
        denied(()->new DurableSessionSnapshot(root,OWNER),"STORE_OWNER_BUSY");
        yes(store.commit(0,first)==1,"file_force_rename_directory_force");
        first[0]^=1;yes(store.read().bytes[0]=='D',"input_is_copied");first[0]^=1;
        DurableSessionSnapshot.State exposed=store.read();exposed.bytes[0]=0;yes(store.read().bytes[0]=='D',"output_is_copied");
        denied(()->store.commit(0,second),"STORE_STALE_VERSION");
        denied(()->store.commit(1,snapshot("/data/private",new byte[0])),"SNAPSHOT_PATH");
        denied(()->store.commit(1,snapshot("/dsh-home/../foreign",new byte[0])),"SNAPSHOT_PATH");
        denied(()->store.commit(1,snapshot("/dsh-home/nested/record",new byte[0])),"SNAPSHOT_PARENT");
        byte[] trailing=Arrays.copyOf(second,second.length+1);denied(()->store.commit(1,trailing),"SNAPSHOT_ROOTS_OR_TRAILING");
        yes(store.read().version==1&&Arrays.equals(store.read().bytes,first),"negative_commits_preserve_old_snapshot");
        yes(store.commit(1,second)==2,"atomic_replace_existing_snapshot");
      }
      try(DurableSessionSnapshot reopened=new DurableSessionSnapshot(root,OWNER)){
        yes(reopened.read().version==2&&Arrays.equals(reopened.read().bytes,second),"restart_retains_version_and_bytes");
      }
      denied(()->new DurableSessionSnapshot(root,OWNER.replace('a','b')),"STORE_ENVELOPE");
      byte[] disk=Files.readAllBytes(root.resolve("snapshot.bin"));disk[disk.length-1]^=1;Files.write(root.resolve("snapshot.bin"),disk);
      denied(()->new DurableSessionSnapshot(root,OWNER),"STORE_CORRUPT");disk[disk.length-1]^=1;Files.write(root.resolve("snapshot.bin"),disk);
      Path link=root.resolve("root-link");Files.createSymbolicLink(link,root);
      denied(()->new DurableSessionSnapshot(link,OWNER),"STORE_PRIVATE_ROOT");Files.delete(link);
      Path escaped=root.resolve("unrelated");Files.write(escaped,new byte[]{9,8,7});
      Files.delete(root.resolve("snapshot.bin"));Files.createSymbolicLink(root.resolve("snapshot.bin"),escaped);
      denied(()->new DurableSessionSnapshot(root,OWNER),"STORE_STATE_TYPE");yes(Arrays.equals(Files.readAllBytes(escaped),new byte[]{9,8,7}),"no_symlink_target_touch");
      Files.delete(root.resolve("snapshot.bin"));Files.delete(escaped);
      ProcessBuilder command=android?
          new ProcessBuilder("/system/bin/app_process","/",DurableSessionSnapshotTest.class.getName(),"--halt",root.toString()):
          new ProcessBuilder(Paths.get(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),DurableSessionSnapshotTest.class.getName(),"--halt",root.toString());
      Process child=command.start();
      boolean stopped=child.waitFor(8,TimeUnit.SECONDS);
      if(!stopped){child.destroyForcibly();child.waitFor(2,TimeUnit.SECONDS);}
      yes(stopped&&child.exitValue()==17,"child_terminated_without_close");
      try(DurableSessionSnapshot restarted=new DurableSessionSnapshot(root,OWNER)){
        yes(restarted.read().version==1&&Arrays.equals(restarted.read().bytes,second),"forced_commit_survives_process_halt_and_releases_lock");
      }
      System.out.println("OWNER_SNAPSHOT_REAL_FILE_FORCE_ATOMIC_REPLACE_DIRECTORY_FORCE_AND_PROCESS_RESTART="+(android?"PASS_ANDROID35_SHELL_UID":"PASS_HOST")+" checks="+checks);
      System.out.println("OWNER_SNAPSHOT_ISOLATED_NODE_WIRE_AND_PRODUCTION_OWNER=NOT_TESTED");
    }finally{for(String name:new String[]{"snapshot.bin","owner.lock"})Files.deleteIfExists(root.resolve(name));Files.delete(root);}
  }
}
