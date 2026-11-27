package com.dsh.android.engine;
import java.io.*;import java.nio.file.*;import java.util.concurrent.*;
/** Real original JS and host durability; not Android or main coroutine proof. */
public final class OriginalProfileStorageTest {
 public static void main(String[] args)throws Exception{
  Path root=ProfileSnapshotWireTest.root();long previous=0;
  try{
   for(int generation=0;generation<2;generation++){
    ProcessBuilder builder=new ProcessBuilder(args[0],"--no-warnings","--permission","--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home","--input-type=module","--eval",new String(Files.readAllBytes(Paths.get(args[1])),"UTF-8"));
    builder.directory(new File("/"));builder.environment().clear();builder.environment().put("HOME","/dsh-home");builder.environment().put("DSH_HOME","/dsh-home");builder.environment().put("DSH_STORAGE_TEST_GENERATION",Integer.toString(generation));
    Process raw=builder.start();HttpProcessTransport process=null;
    try{
     try(InputStream source=Files.newInputStream(Paths.get(args[2]))){byte[] block=new byte[65536];int n;while((n=source.read(block))!=-1)raw.getOutputStream().write(block,0,n);raw.getOutputStream().flush();}
     process=new HttpProcessTransport(raw,ProfileSnapshotWireTest.OWNER,generation+1,0,false,new DurableSessionSnapshot(root,ProfileSnapshotWireTest.OWNER));
     if(!process.waitFor(25,TimeUnit.SECONDS))throw new AssertionError("original_storage_deadline");
     BufferedReader out=new BufferedReader(new InputStreamReader(process.getInputStream(),"US-ASCII"));String line=out.readLine();
     ByteArrayOutputStream error=new ByteArrayOutputStream();byte[] block=new byte[512];int n;while((n=process.getErrorStream().read(block))!=-1){if(error.size()+n>4096)throw new AssertionError("diagnostic_bound");error.write(block,0,n);}
     if(process.exitValue()!=0||!process.failure().equals("NONE/NONE")||line==null||!line.matches("ORIGINAL_JSON_SINGLE_PER_RECORD_ATOMIC_FILE_AND_DIRECTORY_SYNC=PASS modules=[1-9][0-9]*"))throw new AssertionError("original_storage_denied="+process.failure()+" diagnostic="+error.toString("US-ASCII"));
     System.out.println(line+" generation="+generation);
    }finally{if(process!=null){process.close();if(!process.awaitClosed(5,TimeUnit.SECONDS))throw new AssertionError("owner_release_deadline");}else raw.destroyForcibly();}
    try(DurableSessionSnapshot store=new DurableSessionSnapshot(root,ProfileSnapshotWireTest.OWNER)){if(store.read().version<=previous)throw new AssertionError("actual_disk_version_did_not_advance");previous=store.read().version;}
   }
   System.out.println("ORIGINAL_JSON_BACKEND_DURABLE_RESTART=PASS_HOST");
   System.out.println("ORIGINAL_MAIN_COROUTINE_ANDROID_AND_HTTP_READY=NOT_TESTED");
  }finally{ProfileSnapshotWireTest.clean(root);}
 }
}
