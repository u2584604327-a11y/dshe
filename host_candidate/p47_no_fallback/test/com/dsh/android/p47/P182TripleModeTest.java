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
    // P183: primary original coroutine must not bypass PIPE/merge constraints.
    int before=checks;
    expect(blocked,()->P47LaunchGate.startOrDeny(builder(true)));
    expect("P183_PRIMARY_STDERR_DRIFT",
        ()->P47LaunchGate.startOrDeny(builder(false)));
    for(int channel=0;channel<3;channel++) {
      ProcessBuilder main=builder(true);
      File output=new File("p183-main-output-must-not-create");
      if(channel==0)main.redirectInput(new File("p183-input-missing"));
      else if(channel==1)main.redirectOutput(output);
      else main.redirectError(output);
      expect("P183_PRIMARY_STDIO_REDIRECT_DENIED",
          ()->P47LaunchGate.startOrDeny(main));
      if(output.exists())throw new AssertionError("P183_HOST_FILE_CREATED");
    }
    ProcessBuilder missingCwd=builder(true);
    missingCwd.directory(null);
    expect("P183_ORIGINAL_WORKDIR_REQUIRED",
        ()->P47LaunchGate.startOrDeny(missingCwd));
    ProcessBuilder probeMissingCwd=builder(true);
    probeMissingCwd.directory(null);
    expect("P183_ORIGINAL_WORKDIR_REQUIRED",
        ()->P47LaunchGate.probeOrDeny(probeMissingCwd));
    ProcessBuilder configMissingCwd=builder(false);
    configMissingCwd.directory(null);
    expect("P183_ORIGINAL_WORKDIR_REQUIRED",
        ()->P47LaunchGate.configOrDeny(configMissingCwd));
    System.out.println("P183_JVM_PRIMARY_STREAM_AND_WORKDIR_NEGATIVES=PASS checks="+(checks-before));
    System.out.println("P182_REAL_NODE_P37_READY=NOT_WIRED");
  }
}
