package dev.saathi.kids.storage;

import android.content.Context;
import android.util.Log;

import dev.saathi.learn.LessonCatalog;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Loads the bundled, versioned lesson content from assets. Works offline. */
public final class LessonRepository {

    public static final String ASSET = "lessons/lessons_v1.json";

    private final LessonCatalog catalog;
    private final String error;

    public LessonRepository(Context ctx) {
        LessonCatalog c = null;
        String e = null;
        try (InputStream in = ctx.getAssets().open(ASSET)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16 * 1024];
            int r;
            while ((r = in.read(buf)) != -1) out.write(buf, 0, r);
            c = LessonCatalog.parse(new String(out.toByteArray(), StandardCharsets.UTF_8));
        } catch (LessonCatalog.ContentException ex) {
            e = "Lesson content is damaged: " + ex.getMessage();
            Log.e("LessonRepository", e);
        } catch (Exception ex) {
            e = "Lesson content could not be opened";
            Log.e("LessonRepository", e, ex);
        }
        catalog = c;
        error = e;
    }

    /** Null if the bundled content failed to load; see {@link #getError()}. */
    public LessonCatalog getCatalog() {
        return catalog;
    }

    public String getError() {
        return error;
    }
}
