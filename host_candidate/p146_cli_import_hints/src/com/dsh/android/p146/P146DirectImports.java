package com.dsh.android.p146;
import com.dsh.android.p77.P77TarAudit;
import com.dsh.android.p145.P145ExactBootEntry;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Source-only, conservative static relative import hints. NOT a Node resolver. */
public final class P146DirectImports {
  private static final String ROOT="node_modules/@deepseek-ai/dsh/";
  private static final int MAX_HINTS=96;
  private static final Pattern HINT=Pattern.compile(
      "(?:\\brequire\\s*\\(\\s*|\\bimport\\s*\\(\\s*|\\bfrom\\s+|\\bimport\\s+)" +
      "(['\"])(\\.{1,2}/[^'\"\\r\\n]{1,256})\\1");
  public interface Index { boolean hasMember(String canonical); }
  public static final class Summary {
    public final int hints,inside,found,missing,outside;
    Summary(int h,int i,int f,int m,int o) {
      hints=h;inside=i;found=f;missing=m;outside=o;
    }
    public boolean consistent() {
      return hints<=MAX_HINTS && inside+outside==hints && found+missing==inside;
    }
  }
  private P146DirectImports(){}
  private static String scoped(String relative) {
    if(relative==null || relative.indexOf('\\')>=0 ||
       relative.indexOf('?')>=0 || relative.indexOf('#')>=0)return null;
    String base=P145ExactBootEntry.ENTRY;
    base=base.substring(0,base.lastIndexOf('/'));
    ArrayList<String> parts=new ArrayList<>();
    for(String s:base.split("/"))parts.add(s);
    for(String s:relative.split("/",-1)) {
      if(s.isEmpty())return null;
      if(s.equals("."))continue;
      if(s.equals("..")) {
        if(parts.size()<=3)return null;
        parts.remove(parts.size()-1);
      }else{
        for(int j=0;j<s.length();j++)if(s.charAt(j)<32 || s.charAt(j)==127 ||
                                         s.charAt(j)==':')return null;
        parts.add(s);
      }
    }
    String candidate=String.join("/",parts);
    return candidate.startsWith(ROOT)?candidate:null;
  }
  public static Summary classify(byte[] entry,Index index)throws IOException{
    if(entry==null || entry.length==0 ||
       entry.length>P145ExactBootEntry.MAX_ENTRY_BYTES || index==null)
      throw new IOException("P146_BOUNDED_ORIGINAL_ENTRY_REQUIRED");
    String text;
    try {
      text=StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(entry)).toString();
    }catch(CharacterCodingException bad){throw new IOException("P146_BAD_UTF8",bad);}
    Matcher m=HINT.matcher(text);
    int hints=0,inside=0,found=0,missing=0,outside=0;
    while(m.find()){
      if(++hints>MAX_HINTS)throw new IOException("P146_MAX_HINTS_EXCEEDED");
      String candidate=scoped(m.group(2));
      if(candidate==null){outside++;continue;}
      inside++;
      // Presence hints only, not actual Node exports/ESM conditional resolution.
      if(index.hasMember(candidate)||index.hasMember(candidate+".js")||
         index.hasMember(candidate+".cjs")||index.hasMember(candidate+".mjs")||
         index.hasMember(candidate+".json")||index.hasMember(candidate+"/index.js"))
        found++;
      else missing++;
    }
    Summary summary=new Summary(hints,inside,found,missing,outside);
    if(!summary.consistent())throw new IOException("P146_COUNT_INCONSISTENT");
    return summary;
  }
  /**
   * Private best-effort first in-package literal candidate, never a real Node
   * resolver. The returned canonical name stays in the isolated UID only.
   */
  public static String firstExistingSource(byte[] entry,Index index)throws IOException {
    // Reuse P146's strict UTF-8, size and matched-hint budget fail-closed gate.
    classify(entry,index);
    String source=StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(entry)).toString();
    Matcher m=HINT.matcher(source);
    while(m.find()){
      String base=scoped(m.group(2));
      if(base==null)continue;
      String[] names={base,base+".js",base+".cjs",base+".mjs",
                      base+".json",base+"/index.js"};
      for(String candidate:names){
        if((candidate.endsWith(".js")||candidate.endsWith(".cjs")||
            candidate.endsWith(".mjs")||candidate.endsWith(".json")) &&
           candidate.length()<=512 && index.hasMember(candidate))
          return candidate;
      }
    }
    return null;
  }
  public static Summary classifyOriginal(byte[] entry,P77TarAudit.Result root)
      throws IOException {
    if(root==null||!root.isExactOriginal())
      throw new IOException("P146_EXACT_ORIGINAL_TAR_REQUIRED");
    return classify(entry,root::hasOriginalMember);
  }
}