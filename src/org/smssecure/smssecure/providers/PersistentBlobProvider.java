package org.smssecure.smssecure.providers;

import android.content.ContentUris;
import android.content.Context;
import android.content.UriMatcher;
import android.net.Uri;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.util.Log;

import org.smssecure.smssecure.crypto.DecryptingPartInputStream;
import org.smssecure.smssecure.crypto.EncryptingPartOutputStream;
import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.recipients.Recipients;
import org.smssecure.smssecure.util.Util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PersistentBlobProvider {
  private static final String     TAG           = PersistentBlobProvider.class.getSimpleName();
  private static final String     URI_STRING    = "content://org.smssecure.smssecure/capture";
  public  static final Uri        CONTENT_URI   = Uri.parse(URI_STRING);
  public  static final String     AUTHORITY     = "org.smssecure.smssecure";
  public  static final String     EXPECTED_PATH = "capture/*/#";
  private static final int        MATCH         = 1;
  private static final UriMatcher MATCHER       = new UriMatcher(UriMatcher.NO_MATCH) {{
    addURI(AUTHORITY, EXPECTED_PATH, MATCH);
  }};

  private static volatile PersistentBlobProvider instance;

  public static PersistentBlobProvider getInstance(Context context) {
    if (instance == null) {
      synchronized (PersistentBlobProvider.class) {
        if (instance == null) {
          instance = new PersistentBlobProvider(context);
        }
      }
    }
    return instance;
  }

  private final Context context;
  private final Map<Long, byte[]> cache = new HashMap<>();

  private PersistentBlobProvider(Context context) {
    this.context = context.getApplicationContext();
  }

  public Uri create(@NonNull MasterSecret masterSecret,
                    @NonNull Recipients recipients,
                    @NonNull byte[] imageBytes)
  {
    final long id = System.currentTimeMillis();
    cache.put(id, imageBytes);
    return create(masterSecret, new ByteArrayInputStream(imageBytes), id);
  }

  public Uri create(@NonNull MasterSecret masterSecret,
                    @NonNull InputStream input)
  {
    return create(masterSecret, input, System.currentTimeMillis());
  }

  private Uri create(MasterSecret masterSecret, InputStream input, long id) {
    persistToDisk(masterSecret, id, input);
    final Uri uniqueUri = Uri.withAppendedPath(CONTENT_URI, String.valueOf(System.currentTimeMillis()));
    return ContentUris.withAppendedId(uniqueUri, id);
  }

  private void persistToDisk(final MasterSecret masterSecret, final long id,
                             final InputStream input)
  {
    new AsyncTask<Void, Void, Void>() {
      @Override protected Void doInBackground(Void... params) {
        try {
          final OutputStream output = new EncryptingPartOutputStream(getFile(id), masterSecret);
          Util.copy(input, output);
        } catch (IOException e) {
          Log.w(TAG, e);
        }
        return null;
      }

      @Override protected void onPostExecute(Void aVoid) {
        cache.remove(id);
      }
    }.execute();
  }

  public Uri createForExternal() throws IOException {
    return Uri.fromFile(new File(getExternalDir(context), String.valueOf(System.currentTimeMillis()) + ".jpg"))
              .buildUpon()
              .build();
  }

  public boolean delete(@NonNull Uri uri) {
    switch (MATCHER.match(uri)) {
    case MATCH: return getFile(ContentUris.parseId(uri)).delete();
    default:    return new File(uri.getPath()).delete();
    }
  }

  public @NonNull InputStream getStream(MasterSecret masterSecret, long id) throws IOException {
    final byte[] cached = cache.get(id);
    return cached != null ? new ByteArrayInputStream(cached)
                          : new DecryptingPartInputStream(getFile(id), masterSecret);
  }

  private File getFile(long id) {
    return new File(context.getDir("captures", Context.MODE_PRIVATE), id + ".jpg");
  }

  private static @NonNull File getExternalDir(Context context) throws IOException {
    final File externalDir = context.getExternalFilesDir(null);
    if (externalDir == null) throw new IOException("no external files directory");
    return externalDir;
  }

  public static boolean isAuthority(@NonNull Context context, @NonNull Uri uri) {
    try {
      return MATCHER.match(uri) == MATCH || uri.getPath().startsWith(getExternalDir(context).getAbsolutePath());
    } catch (IOException ioe) {
      return false;
    }
  }
}
