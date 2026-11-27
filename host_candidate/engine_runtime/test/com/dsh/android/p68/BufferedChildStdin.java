package com.dsh.android.p68;

import java.io.*;
import java.nio.channels.*;
import java.util.concurrent.TimeUnit;

/** Host integration only: the real production stdin pump, a real OS pipe,
 * and an explicitly buffered real child stdin. No Binder/Android attestation. */
public final class BufferedChildStdin extends Process {
  private final Process child;
  private final Pipe pipe;
  private final OutputStream upstream;
  private BufferedChildStdin(Process child)throws IOException{
    this.child=child;pipe=Pipe.open();upstream=Channels.newOutputStream(pipe.sink());
    P68AndroidBinderIntake.forwardStdin(Channels.newInputStream(pipe.source()),
        new BufferedOutputStream(child.getOutputStream(),8192),child::destroyForcibly);
  }
  public static Process wrap(Process child)throws IOException{
    try{return new BufferedChildStdin(child);}catch(IOException failure){child.destroyForcibly();throw failure;}
  }
  @Override public OutputStream getOutputStream(){return upstream;}
  @Override public InputStream getInputStream(){return child.getInputStream();}
  @Override public InputStream getErrorStream(){return child.getErrorStream();}
  @Override public boolean isAlive(){return child.isAlive();}
  @Override public int waitFor()throws InterruptedException{return child.waitFor();}
  @Override public boolean waitFor(long timeout,TimeUnit unit)throws InterruptedException{return child.waitFor(timeout,unit);}
  @Override public int exitValue(){return child.exitValue();}
  @Override public void destroy(){child.destroy();release();}
  @Override public Process destroyForcibly(){child.destroyForcibly();release();return this;}
  private void release(){try{upstream.close();}catch(IOException ignored){}try{pipe.source().close();}catch(IOException ignored){}}
}
