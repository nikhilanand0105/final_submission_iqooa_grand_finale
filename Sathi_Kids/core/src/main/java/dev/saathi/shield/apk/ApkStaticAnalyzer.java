package dev.saathi.shield.apk;

import dev.saathi.util.CancellationToken;

import java.io.File;
import java.io.InputStream;

/** Static (non-executing) analysis of an APK selected by the user. */
public interface ApkStaticAnalyzer {

    /** Reports real progress while the file is read. Called on the analysis thread. */
    interface ProgressListener {
        void onProgress(String stage, long bytesDone, long bytesTotal);
    }

    /**
     * Analyses a stream (e.g. from ContentResolver). The stream is copied into {@code workDir} (app-private storage)
     * with a size limit so the ZIP central directory can be read; the copy is deleted afterwards.
     */
    ApkAnalysisResult analyze(InputStream in, String fileName, long declaredSize, File workDir,
                              CancellationToken token, ProgressListener progress);

    ApkAnalysisResult analyze(File file, CancellationToken token, ProgressListener progress);

    String getVersion();
}
