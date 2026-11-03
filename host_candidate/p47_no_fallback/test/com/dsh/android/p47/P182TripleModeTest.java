package com.dsh.android.p47;
import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder;

/** Bounded JVM negatives: typed original mode must never execute host Node. */
public final class P182TripleModeTest {
  private interface Attempt { void go() throws IOException; }
  private static int checks;
  private static void expect(String message,Attempt run) throws Exception {
    try {
      run.go();
      throw new AssertionError("P182_UNEXPECTED_LAUNCH");
    } catch(IOException denied) {
      if(!message.equals(denied.getMessage()))
        throw new AssertionError("P182_WRONG_DENIAL:"+denied.getMessage());
      checks++;
    }
  }
  private static ProcessBuilder builder(boolean merge) {
    return new ProcessBuilder("nonexistent-p182-binary","--fixture")
        .directory(new File(".")).redirectErrorStream(merge);
  }
  public static void main(String[] args) throws Exception {
    String blocked="P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK";
    expect(blocked,()->P47LaunchGate.probeOrDeny(builder(true)));
    expect(blocked,()->P47LaunchGate.configOrDeny(builder(false)));
    expect("P182_ORIGINAL_MODE_STDERR_DRIFT",
        ()->P47LaunchGate.probeOrDeny(builder(false)));
    expect("P182_ORIGINAL_MODE_STDERR_DRIFT",
        ()->P47LaunchGate.configOrDeny(builder(true)));
    ProcessBuilder redirected=builder(true);
    redirected.redirectOutput(new File("p182-must-not-create"));
    expect("P182_ORIGINAL_MODE_STDIO_REDIRECT_DENIED",
        ()->P47LaunchGate.probeOrDeny(redirected));
    if(new File("p182-must-not-create").exists())
      throw new AssertionError("P182_HOST_FILE_CREATED");
    System.out.println("P182_JVM_TYPED_PROBE_CONFIG_DENY_AND_STDIO_GUARD=PASS checks="+checks);
    System.out.println("P182_REAL_NODE_P37_READY=NOT_WIRED");
  }
}
