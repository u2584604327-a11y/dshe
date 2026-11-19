package com.dsh.android.p146;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
public final class P146SyntheticTest {
  static byte[] b(String x){return x.getBytes(StandardCharsets.UTF_8);}
  static void yes(boolean x){if(!x)throw new AssertionError("P146_ASSERTION");}
  public static void main(String[] args)throws Exception{
    Set<String> names=new HashSet<>(Arrays.asList(
      "node_modules/@deepseek-ai/dsh/lib/cli.js",
      "node_modules/@deepseek-ai/dsh/extra/index.js"));
    P146DirectImports.Summary a=P146DirectImports.classify(
      b("require('./cli');import '../extra';from '../extra';import('./absent')"),
      names::contains);
    yes(a.hints==4&&a.inside==4&&a.found==3&&a.missing==1&&a.consistent());
    P146DirectImports.Summary attack=P146DirectImports.classify(
      b("require('../../../../secrets'); require('./safe?x');"),
      names::contains);
    yes(attack.hints==2&&attack.outside==2&&attack.found==0);
    yes(P146DirectImports.classify(b("require(variable)"),names::contains).hints==0);
    try {P146DirectImports.classify(new byte[]{(byte)0xc3,(byte)0x28},names::contains);
      throw new AssertionError("P146_UTF8_FAILOPEN");
    }catch(IOException ok){yes(ok.getMessage().contains("UTF8"));}
    try {P146DirectImports.classify(b("ok"),null);
      throw new AssertionError("P146_NULL_FAILOPEN");
    }catch(IOException ok){yes(ok.getMessage().contains("REQUIRED"));}
    StringBuilder big=new StringBuilder();
    for(int i=0;i<97;i++)big.append("require('./cli');");
    try {P146DirectImports.classify(b(big.toString()),names::contains);
      throw new AssertionError("P146_HINT_CAP_FAILOPEN");
    }catch(IOException ok){yes(ok.getMessage().contains("MAX_HINTS"));}
    System.out.println("P146_STATIC_IMPORT_HINT_SYNTHETIC_NEGATIVES=PASS");
  }
}