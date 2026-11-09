package com.dsh.b4probe;
import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.os.UserManager;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;
import java.io.*;
import java.nio.charset.StandardCharsets;
public final class UserProbe extends Activity {
  private static final String NAME="b4_synthetic.bin";
  /** Positive same-user queries exclude missing-provider and unreadable-provider
   *  false positives. Only a real SecurityException from cross-user query counts. */
  private void verifySyntheticProvider(int self,int other,String role) {
    String authority=SyntheticRoleProvider.AUTHORITY;
    String path="/"+SyntheticRoleProvider.PATH;
    Uri own=Uri.parse("content://"+self+"@"+authority+path);
    Uri foreign=Uri.parse("content://"+other+"@"+authority+path);
    if(!String.valueOf(self).equals(own.getUserInfo()) ||
        !String.valueOf(other).equals(foreign.getUserInfo()) ||
        own.equals(foreign))
      throw new IllegalStateException("B4_EXPLICIT_USER_URI_INVALID");
    try(Cursor cursor=getContentResolver().query(own,new String[]{"role"},
        null,null,null)){
      if(cursor==null || !cursor.moveToFirst() || cursor.getCount()!=1 ||
          !"role".equals(cursor.getColumnName(0)) ||
          !role.equals(cursor.getString(0)))
        throw new IllegalStateException("B4_SAME_USER_PROVIDER_UNATTESTED");
    }
    Log.i("B4_PROBE","B4_ANDROID35_"+role+"_PROVIDER_SELF_QUERY=PASS");
    boolean osDenied=false;
    try(Cursor cursor=getContentResolver().query(foreign,new String[]{"role"},
        null,null,null)){
      // A null/empty result is not a permission proof. An accessible
      // foreign cursor is also a failure. Both must stop the test.
    }catch(SecurityException blocked){
      // Android framework/transport rejected an explicitly other-user URI.
      osDenied=true;
    }
    if(!osDenied)throw new IllegalStateException("B4_FOREIGN_PROVIDER_NO_OS_DENIAL");
    Log.i("B4_PROBE","B4_ANDROID35_"+role+"_PROVIDER_FOREIGN_SECURITY_DENIED=PASS");
  }
  private void deny(){Log.i("B4_PROBE","B4_ANDROID35_DENIED=DENY");finish();}
  @Override public void onCreate(Bundle saved) {
    super.onCreate(saved);
    if(saved!=null){deny();return;}
    try {
      UserManager um=(UserManager)getSystemService(USER_SERVICE);
      if(um==null||!um.isUserUnlocked())throw new SecurityException("LOCKED");
      boolean work=um.isManagedProfile();
      int self=Process.myUid()/100000; // AOSP test-only per-user UID range
      int other=getIntent().getIntExtra("other",-1);
      if((work&&self==0)||(!work&&self!=0)||
         (work&&other!=0)||(!work&&other<1)||self==other)
        throw new SecurityException("WRONG_USER");
      String role=work?"WORK":"PARENT";
      String secret="B4_FAKE_"+role;
      String phase=getIntent().getStringExtra("phase");
      SharedPreferences prefs=getSharedPreferences("b4_synthetic_only",MODE_PRIVATE);
      File own=new File(getFilesDir(),NAME);
      if("seed".equals(phase)){
        if(prefs.contains("marker")||own.exists())throw new SecurityException("PRESEEDED");
        if(!prefs.edit().putString("marker",secret).commit())
          throw new SecurityException("PREF_WRITE");
        try(FileOutputStream out=new FileOutputStream(own)){
          out.write(secret.getBytes(StandardCharsets.US_ASCII));
          out.getFD().sync();
        }
      }else if("verify".equals(phase)){
        if(!secret.equals(prefs.getString("marker",null))||!own.isFile())
          throw new SecurityException("MISSING");
        byte[] buf=new byte[64];int count;
        try(FileInputStream in=new FileInputStream(own)){
          count=in.read(buf);
          if(in.read()!=-1)throw new SecurityException("OVERSIZE");
        }
        if(count!=secret.length()||
          !secret.equals(new String(buf,0,count,StandardCharsets.US_ASCII)))
          throw new SecurityException("MISMATCH");
        File foreign=new File("/data/user/"+other+"/com.dsh.b4probe/files/"+NAME);
        // Distinguish an actual kernel permission denial from a missing path.
        // ENOENT is inconclusive and must fail closed, never count as isolation PASS.
        try {
          android.system.Os.close(android.system.Os.open(
              foreign.getAbsolutePath(), android.system.OsConstants.O_RDONLY, 0));
          throw new SecurityException("FOREIGN_READABLE");
        } catch(android.system.ErrnoException denied) {
          if(denied.errno==android.system.OsConstants.EACCES ||
             denied.errno==android.system.OsConstants.EPERM) {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_OPEN_ERRNO=PERMISSION_DENIED");
          } else if(denied.errno==android.system.OsConstants.ENOENT) {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_OPEN_ERRNO=ENOENT_INCONCLUSIVE");
            throw new SecurityException("FOREIGN_PATH_MISSING");
          } else {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_OPEN_ERRNO=OTHER_INCONCLUSIVE");
            throw new SecurityException("FOREIGN_OPEN_UNEXPECTED_ERRNO");
          }
        }
        // A denied read is insufficient: prove the other OS user's synthetic
        // file cannot even be opened for writing. No O_CREAT, O_TRUNC, or write.
        try {
          android.system.Os.close(android.system.Os.open(
              foreign.getAbsolutePath(), android.system.OsConstants.O_WRONLY, 0));
          throw new SecurityException("FOREIGN_WRITABLE");
        } catch(android.system.ErrnoException denied) {
          if(denied.errno==android.system.OsConstants.EACCES ||
             denied.errno==android.system.OsConstants.EPERM) {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_WRITE_OPEN_ERRNO=PERMISSION_DENIED");
          } else if(denied.errno==android.system.OsConstants.ENOENT) {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_WRITE_OPEN_ERRNO=ENOENT_INCONCLUSIVE");
            throw new SecurityException("FOREIGN_WRITE_PATH_MISSING");
          } else {
            Log.i("B4_PROBE","B4_ANDROID35_FOREIGN_WRITE_OPEN_ERRNO=OTHER_INCONCLUSIVE");
            throw new SecurityException("FOREIGN_WRITE_UNEXPECTED_ERRNO");
          }
        }
      }else if("uri".equals(phase)){
        verifySyntheticProvider(self,other,role);
      }else throw new SecurityException("INVALID_PHASE");
      Log.i("B4_PROBE","B4_ANDROID35_"+role+"_"+phase.toUpperCase(java.util.Locale.US)+"=PASS");
    }catch(Exception failed){deny();return;}
    finish();
  }
}
