package com.dsh.android.p152;
public final class P152CauseClassifier {
  private P152CauseClassifier(){}
  public static String assetArch(String abi) {
    if("arm64-v8a".equals(abi))return "aarch64";
    if("armeabi-v7a".equals(abi))return "arm";
    if("x86_64".equals(abi))return "x86_64";
    if("x86".equals(abi))return "i686";
    return "unsupported";
  }
  public static String classify(String abi,boolean bootstrapAsset,boolean nodeAsset,
      boolean prefixPresent,boolean bootstrapMarker,boolean nodePresent,
      boolean nodeMarker,boolean nodeNonempty) {
    String arch;
    if("arm64-v8a".equals(abi))arch="ARM64";
    else if("x86_64".equals(abi))arch="X86_64";
    else if("armeabi-v7a".equals(abi))arch="ARM32";
    else if("x86".equals(abi))arch="X86";
    else arch="UNKNOWN";
    return arch
      +(bootstrapAsset?"_BOOTSTRAP_ASSET_PRESENT":"_BOOTSTRAP_ASSET_ABSENT")
      +(nodeAsset?"_NODE_ASSET_PRESENT":"_NODE_ASSET_ABSENT")
      +(prefixPresent?"_PREFIX_PRESENT":"_PREFIX_ABSENT")
      +(bootstrapMarker?"_BOOT_MARKER_PRESENT":"_BOOT_MARKER_ABSENT")
      +(nodePresent?"_NODE_FILE_PRESENT":"_NODE_FILE_ABSENT")
      +(nodeNonempty?"_NODE_FILE_NONEMPTY":"_NODE_FILE_EMPTY_OR_ABSENT")
      +(nodeMarker?"_NODE_MARKER_PRESENT":"_NODE_MARKER_ABSENT");
  }
}
