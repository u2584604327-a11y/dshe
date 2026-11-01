package com.dsh.android.p147;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import com.dsh.android.p146.P146DirectImports;
public final class P147SyntheticTest {
  private static void yes(boolean v){if(!v)throw new AssertionError("P147_ASSERTION");}
  private static byte[] b(String s){return s.getBytes(StandardCharsets.UTF_8);}
  private static void deny(Runnable f){try{f.run();throw new AssertionError("P147_FAIL_OPEN");}
      catch(SecurityException expected){}}
  public static void main(String[] x)throws Exception{
    final String ss="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    P147ScopedCandidateLease a=new P147ScopedCandidateLease(ss,
      "node_modules/@deepseek-ai/dsh/lib/cli.js");
    yes(a.begin("node_modules/@deepseek-ai/dsh/lib/cli.js",false,3));
    a.accept(b("abc"),0,3);a.endMember();
    yes(!a.ready());
    try{a.sealOriginal(null);throw new AssertionError("P147_UNVERIFIED_ROOT_ACCEPTED");}
    catch(IOException expected){}
    deny(()->a.takeOnce(ss));
    a.close();
    deny(()->new P147ScopedCandidateLease(ss,"node_modules/@deepseek-ai/dsh/../../secrets.js"));
    deny(()->new P147ScopedCandidateLease(ss,"node_modules/@deepseek-ai/dsh/lib/a.node"));
    deny(()->new P147ScopedCandidateLease(ss,"node_modules/@deepseek-ai/dsh/lib/a\\b.js"));
    P147ScopedCandidateLease oversize=new P147ScopedCandidateLease(ss,
      "node_modules/@deepseek-ai/dsh/lib/cli.js");
    try{oversize.begin("node_modules/@deepseek-ai/dsh/lib/cli.js",false,
        P147ScopedCandidateLease.MAX_SOURCE_BYTES+1L);
      throw new AssertionError("P147_CAP_FAIL_OPEN");}catch(IOException expected){}
    oversize.close();
    yes(P146DirectImports.firstExistingSource(b("require('./cli')"),
      path->path.equals("node_modules/@deepseek-ai/dsh/lib/cli.js"))
      .equals("node_modules/@deepseek-ai/dsh/lib/cli.js"));
    yes(P146DirectImports.firstExistingSource(b("require('../../../../secrets')"),
      path->true)==null);
    yes(P146DirectImports.firstExistingSource(b("require(variable)"),
      path->true)==null);
    System.out.println("P147_SCOPED_SOURCE_SYNTHETIC_DENY_CASES=PASS");
  }
}
