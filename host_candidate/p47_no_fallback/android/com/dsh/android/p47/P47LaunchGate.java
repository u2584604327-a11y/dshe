package com.dsh.android.p47;
import java.io.File;
import com.dsh.android.p149.P149OriginalBuilderWitness;
import com.dsh.android.p150.P150OriginalCoroutineObserver;
import java.io.IOException;
import java.lang.ProcessBuilder;
import java.util.List;
import java.util.Map;

/**
 * P47 fail-closed original EngineManager spawn seam.
 *
 * A real authenticated Android isolated Binder supervisor is NOT installed
 * yet. This method must NOT execute ProcessBuilder.start(), fork, shell,
 * reflectively invoke start, enable an env override, or silently fallback.
 *
 * Production DSH shipping remains prohibited until a real isolated
 * supervisor, lease/identity checks and runtime parity are implemented.
 */
public final class P47LaunchGate {
  private P47LaunchGate(){}

  /** Sensitive command args, cwd and environment values NEVER leave memory. */
  public static final class Shape {
    public final int argvCount;
    public final boolean hasDirectory;
    public final int environmentEntries;
    public final boolean stderrMerged;
    private Shape(int argvCount, boolean hasDirectory,
                  int environmentEntries, boolean stderrMerged) {
      this.argvCount=argvCount;
      this.hasDirectory=hasDirectory;
      this.environmentEntries=environmentEntries;
      this.stderrMerged=stderrMerged;
    }
  }

  public static Shape categorize(ProcessBuilder builder) {
    if(builder==null)throw new IllegalArgumentException("P47_NULL_BUILDER");
    List<String> argv=builder.command();
    Map<String,String> environment=builder.environment();
    File directory=builder.directory();
    return new Shape(argv==null ? 0 : argv.size(),
        directory!=null,environment==null ? 0 : environment.size(),
        builder.redirectErrorStream());
  }

  /**
   * Bridge target in original classes.dex: fail-closed is the ONLY path in
   * P47. An IOException is intentional and must be surfaced to original
   * EngineManager, NEVER replaced by a host Process.
   */
  public static Process startOrDeny(ProcessBuilder builder) throws IOException {
    Shape shape=categorize(builder);
    if(shape.argvCount<1 || shape.argvCount>128)
      throw new IOException("P47_INVALID_ORIGINAL_LAUNCH_SHAPE");
    P150OriginalCoroutineObserver.recordFromP47();
    P149OriginalBuilderWitness.observeWithoutLaunch(builder,3);
    throw new IOException("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK");
  }

  /** P182: original v138 probe/config mode is selected by the exact DEX
   * callsite, never by an untrusted Bundle, command flag or env override.
   * Both modes remain strictly DENY; no Broker/Node is executed.
   */
  private static Process secondaryDeny(ProcessBuilder builder,int mode)
      throws IOException {
    Shape shape=categorize(builder);
    if (shape.argvCount<1 || shape.argvCount>128)
      throw new IOException("P47_INVALID_ORIGINAL_LAUNCH_SHAPE");
    if (shape.stderrMerged!=(mode==1))
      throw new IOException("P182_ORIGINAL_MODE_STDERR_DRIFT");
    if (builder.redirectInput()!=ProcessBuilder.Redirect.PIPE ||
        builder.redirectOutput()!=ProcessBuilder.Redirect.PIPE ||
        builder.redirectError()!=ProcessBuilder.Redirect.PIPE)
      throw new IOException("P182_ORIGINAL_MODE_STDIO_REDIRECT_DENIED");
    P149OriginalBuilderWitness.observeWithoutLaunch(builder,mode);
    throw new IOException("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK");
  }

  public static Process probeOrDeny(ProcessBuilder builder) throws IOException {
    return secondaryDeny(builder,1);
  }
  public static Process configOrDeny(ProcessBuilder builder) throws IOException {
    return secondaryDeny(builder,2);
  }
}
