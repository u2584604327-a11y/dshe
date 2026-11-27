package com.dsh.android.p152;
public final class P152CauseClassifierTest {
  private static void yes(boolean ok){if(!ok)throw new AssertionError("P152_CATEGORY_FAILURE");}
  public static void main(String[] ignored){
    yes("aarch64".equals(P152CauseClassifier.assetArch("arm64-v8a")));
    yes("x86_64".equals(P152CauseClassifier.assetArch("x86_64")));
    yes("unsupported".equals(P152CauseClassifier.assetArch("../../credential")));
    String missing=P152CauseClassifier.classify("x86_64",false,true,false,false,false,false,false);
    yes(missing.startsWith("X86_64_BOOTSTRAP_ASSET_ABSENT_NODE_ASSET_PRESENT_PREFIX_ABSENT"));
    yes(missing.endsWith("_NODE_MARKER_ABSENT"));
    yes(missing.indexOf('/')<0 && missing.indexOf(':')<0);
    String present=P152CauseClassifier.classify("arm64-v8a",true,true,true,true,true,true,true);
    yes(present.startsWith("ARM64_BOOTSTRAP_ASSET_PRESENT_NODE_ASSET_PRESENT_PREFIX_PRESENT"));
    yes(present.endsWith("_NODE_MARKER_PRESENT"));
    String unknown=P152CauseClassifier.classify("/private/secret",false,false,false,false,false,false,false);
    yes(unknown.startsWith("UNKNOWN_") && !unknown.contains("secret"));
    System.out.println("P152_ASSET_PREFIX_NODE_METADATA_ENUM_NEGATIVES=PASS");
    System.out.println("P152_NODE_START_OR_VERSION_EXECUTED=NO");
  }
}
