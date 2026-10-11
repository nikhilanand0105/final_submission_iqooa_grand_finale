package dev.saathi.personal.provider;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Zero-dependency, lightweight ContentProvider for Scoped Storage on iQOO 15 (Android 16).
 * Replaces heavy AndroidX FileProvider dependency while granting read URI permissions safely.
 */
public class SaathiFileProvider extends ContentProvider {

    public static final String AUTHORITY = "dev.saathi.personal.fileprovider";

    @Override
    public boolean onCreate() {
        return true;
    }

    private File resolveFile(Uri uri) {
        if (uri == null) return null;
        String segment = uri.getLastPathSegment();
        if (segment == null) return null;

        // 1. Check in cacheDir
        File cacheFile = new File(getContext().getCacheDir(), segment);
        if (cacheFile.exists()) return cacheFile;

        // 2. Check in Downloads
        File downloadDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS);
        File downloadFile = new File(downloadDir, segment);
        if (downloadFile.exists()) return downloadFile;

        File sdcardDownload = new File("/sdcard/Download", segment);
        if (sdcardDownload.exists()) return sdcardDownload;

        return cacheFile;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = resolveFile(uri);
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("File not found: " + uri);
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        if (projection == null) {
            projection = new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};
        }
        MatrixCursor cursor = new MatrixCursor(projection);
        File file = resolveFile(uri);
        if (file != null && file.exists()) {
            Object[] row = new Object[projection.length];
            for (int i = 0; i < projection.length; i++) {
                if (OpenableColumns.DISPLAY_NAME.equals(projection[i])) {
                    row[i] = file.getName();
                } else if (OpenableColumns.SIZE.equals(projection[i])) {
                    row[i] = file.length();
                }
            }
            cursor.addRow(row);
        }
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "application/vnd.android.package-archive";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
