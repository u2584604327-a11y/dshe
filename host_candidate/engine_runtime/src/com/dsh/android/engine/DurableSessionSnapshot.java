package com.dsh.android.engine;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;

/** An already-authorized host owner's flat, durable snapshot capability.
 * No Binder issuer, launcher, account selection or caller-supplied host path.
 * The trusted supervisor must provide a canonical private root and owner ID.
 * Untrusted virtual paths exist only inside the validated snapshot payload.
 */
final class DurableSessionSnapshot implements AutoCloseable {
  private static final Path STATE=Paths.get("snapshot.bin"),LOCK=Paths.get("owner.lock");
  private static final byte[] MAGIC={'D','S','H','S','T','0','0','1'};
  // A second descriptor close can release this VM's POSIX locks on an inode.
  // Reserve the directory identity BEFORE opening another lock descriptor.
  private static final Set<Object> OPEN_ROOTS=new HashSet<>();
  private final Object rootKey;
  private final SecureDirectoryStream<Path> directory;
  private final FileChannel lockChannel;
  private final FileLock lock;
  private final byte[] owner;
  private byte[] current;
  private long version;
  private boolean closed,poisoned;
  static final class State {
    final long version;final byte[] bytes;
    State(long version,byte[] bytes){this.version=version;this.bytes=bytes.clone();}
  }
  DurableSessionSnapshot(Path trustedPrivateRoot,String trustedOwner)throws IOException{
    if(trustedPrivateRoot==null||trustedOwner==null||!trustedOwner.matches("[0-9a-f]{64}"))throw new IOException("STORE_TRUSTED_OWNER");
    Path root=trustedPrivateRoot.toAbsolutePath().normalize();
    if(Files.isSymbolicLink(root)||!root.equals(root.toRealPath())||!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||
        !Files.getPosixFilePermissions(root,LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rwx------")))throw new IOException("STORE_PRIVATE_ROOT");
    owner=new byte[32];for(int i=0;i<owner.length;i++)owner[i]=(byte)Integer.parseInt(trustedOwner.substring(2*i,2*i+2),16);
    DirectoryStream<Path> opened=Files.newDirectoryStream(root);
    if(!(opened instanceof SecureDirectoryStream)){opened.close();throw new IOException("STORE_SECURE_DIRECTORY_UNAVAILABLE");}
    directory=(SecureDirectoryStream<Path>)opened;
    Object key;
    try{key=directory.getFileAttributeView(BasicFileAttributeView.class).readAttributes().fileKey();}
    catch(IOException failure){directory.close();throw failure;}
    if(key==null){directory.close();throw new IOException("STORE_FILE_KEY_UNAVAILABLE");}
    synchronized(OPEN_ROOTS){if(!OPEN_ROOTS.add(key)){directory.close();throw new IOException("STORE_OWNER_BUSY");}}
    rootKey=key;
    FileChannel channel=null;FileLock acquired=null;
    try{
      try{BasicFileAttributes attr=directory.getFileAttributeView(LOCK,BasicFileAttributeView.class,LinkOption.NOFOLLOW_LINKS).readAttributes();if(!attr.isRegularFile()||attr.size()!=0)throw new IOException("STORE_LOCK_TYPE");}catch(NoSuchFileException absent){}
      SeekableByteChannel candidate=directory.newByteChannel(LOCK,new HashSet<OpenOption>(Arrays.asList(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      if(!(candidate instanceof FileChannel)){candidate.close();throw new IOException("STORE_FORCE_UNAVAILABLE");}
      channel=(FileChannel)candidate;
      try{acquired=channel.tryLock();}catch(OverlappingFileLockException busy){throw new IOException("STORE_OWNER_BUSY");}
      if(acquired==null)throw new IOException("STORE_OWNER_BUSY");
      readExisting();
    }catch(IOException|RuntimeException failure){
      try{if(acquired!=null)acquired.release();}finally{try{if(channel!=null)channel.close();}finally{try{directory.close();}finally{synchronized(OPEN_ROOTS){OPEN_ROOTS.remove(rootKey);}}}}
      throw failure;
    }
    lockChannel=channel;lock=acquired;
  }
  private static byte[] hash(byte[] bytes)throws IOException{try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException impossible){throw new IOException("STORE_SHA_UNAVAILABLE");}}
  private void readExisting()throws IOException{
    try{
      BasicFileAttributes attr=directory.getFileAttributeView(STATE,BasicFileAttributeView.class,LinkOption.NOFOLLOW_LINKS).readAttributes();
      if(!attr.isRegularFile())throw new IOException("STORE_STATE_TYPE");
    }catch(NoSuchFileException absent){current=null;version=0;return;}
    try(SeekableByteChannel channel=directory.newByteChannel(STATE,new HashSet<OpenOption>(Arrays.asList(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)))){
      long size=channel.size();if(size<84||size>84L+SessionSnapshotCodec.MAX_BYTES)throw new IOException("STORE_ENVELOPE_SIZE");
      ByteBuffer bytes=ByteBuffer.allocate((int)size);while(bytes.hasRemaining())if(channel.read(bytes)<0)throw new EOFException("STORE_TRUNCATED");
      bytes.flip();byte[] magic=new byte[8],identity=new byte[32],digest=new byte[32];bytes.get(magic);bytes.get(identity);
      long storedVersion=bytes.getLong();int length=bytes.getInt();bytes.get(digest);
      if(!Arrays.equals(magic,MAGIC)||!MessageDigest.isEqual(owner,identity)||storedVersion<=0||length!=bytes.remaining())throw new IOException("STORE_ENVELOPE");
      byte[] payload=new byte[length];bytes.get(payload);if(!MessageDigest.isEqual(digest,hash(payload)))throw new IOException("STORE_CORRUPT");
      SessionSnapshotCodec.validate(payload);current=payload;version=storedVersion;
    }catch(NoSuchFileException absent){current=null;version=0;}
  }
  synchronized State read()throws IOException{alive();return new State(version,current==null?empty():current);}
  private static byte[] empty()throws IOException{
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);out.writeBytes("DSHFS001");out.writeInt(2);
    for(String name:new String[]{"/dsh-home","/dsh-workspace"}){byte[] encoded=name.getBytes("UTF-8");out.writeShort(encoded.length);out.write(encoded);out.writeByte(1);out.writeShort(0700);out.writeLong(0);out.writeInt(0);}return bytes.toByteArray();
  }
  synchronized long commit(long expectedVersion,byte[] input)throws IOException{
    alive();if(expectedVersion!=version||version==Long.MAX_VALUE)throw new IOException("STORE_STALE_VERSION");
    if(input==null||input.length>SessionSnapshotCodec.MAX_BYTES)throw new IOException("STORE_PAYLOAD_BOUND");
    byte[] payload=input.clone();SessionSnapshotCodec.validate(payload);byte[] digest=hash(payload);long next=version+1;
    ByteBuffer encoded=ByteBuffer.allocate(84+payload.length).put(MAGIC).put(owner).putLong(next).putInt(payload.length).put(digest).put(payload);encoded.flip();
    Path temporary=Paths.get("tmp-"+UUID.randomUUID());boolean renamed=false,created=false;
    try{
      try(SeekableByteChannel candidate=directory.newByteChannel(temporary,new HashSet<OpenOption>(Arrays.asList(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))){
        created=true;if(!(candidate instanceof FileChannel))throw new IOException("STORE_FORCE_UNAVAILABLE");
        while(encoded.hasRemaining())((FileChannel)candidate).write(encoded);
        ((FileChannel)candidate).force(true);
      }
      directory.move(temporary,directory,STATE);renamed=true;
      try(SeekableByteChannel candidate=directory.newByteChannel(Paths.get("."),new HashSet<OpenOption>(Arrays.asList(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)))){
        if(!(candidate instanceof FileChannel))throw new IOException("STORE_DIRECTORY_FORCE_UNAVAILABLE");
        ((FileChannel)candidate).force(true);
      }
      if(current!=null)Arrays.fill(current,(byte)0);current=payload;version=next;return next;
    }catch(IOException|RuntimeException failure){
      if(renamed){poisoned=true;throw new IOException("STORE_COMMIT_INDETERMINATE",failure);}
      Arrays.fill(payload,(byte)0);throw failure;
    }finally{if(created&&!renamed)try{directory.deleteFile(temporary);}catch(NoSuchFileException ignored){}}
  }
  private void alive()throws IOException{if(closed||poisoned)throw new IOException(poisoned?"STORE_INDETERMINATE_REOPEN_REQUIRED":"STORE_CLOSED");}
  @Override public synchronized void close()throws IOException{
    if(closed)return;closed=true;if(current!=null)Arrays.fill(current,(byte)0);Arrays.fill(owner,(byte)0);
    try{lock.release();}finally{try{lockChannel.close();}finally{try{directory.close();}finally{synchronized(OPEN_ROOTS){OPEN_ROOTS.remove(rootKey);}}}}
  }
}
