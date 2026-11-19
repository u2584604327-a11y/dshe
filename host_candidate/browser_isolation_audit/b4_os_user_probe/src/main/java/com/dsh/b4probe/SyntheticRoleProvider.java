package com.dsh.b4probe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.UserManager;

/** Disposable Android35 probe only: returns a fixed synthetic role, never user data. */
public final class SyntheticRoleProvider extends ContentProvider {
  public static final String AUTHORITY="com.dsh.b4probe.synthetic";
  public static final String PATH="role";

  private void check(Uri uri) {
    if(uri==null || !PATH.equals(uri.getLastPathSegment()) ||
        !AUTHORITY.equals(uri.getAuthority()))
      throw new IllegalArgumentException("INVALID_SYNTHETIC_URI");
  }

  @Override public boolean onCreate(){return true;}

  @Override public Cursor query(Uri uri,String[] projection,String selection,
      String[] selectionArgs,String sortOrder) {
    check(uri);
    UserManager manager=(UserManager)getContext().getSystemService(Context.USER_SERVICE);
    if(manager==null || !manager.isUserUnlocked())
      throw new IllegalStateException("B4_PROVIDER_USER_LOCKED");
    String role=manager.isManagedProfile()?"WORK":"PARENT";
    MatrixCursor result=new MatrixCursor(new String[]{"role"},1);
    result.addRow(new Object[]{role});
    return result;
  }

  @Override public String getType(Uri uri) {
    check(uri);
    return "vnd.android.cursor.item/vnd.com.dsh.b4probe.synthetic.role";
  }

  @Override public Uri insert(Uri uri,ContentValues values){
    throw new SecurityException("B4_SYNTHETIC_PROVIDER_READ_ONLY");
  }
  @Override public int delete(Uri uri,String selection,String[] selectionArgs){
    throw new SecurityException("B4_SYNTHETIC_PROVIDER_READ_ONLY");
  }
  @Override public int update(Uri uri,ContentValues values,String selection,
      String[] selectionArgs){
    throw new SecurityException("B4_SYNTHETIC_PROVIDER_READ_ONLY");
  }
}
