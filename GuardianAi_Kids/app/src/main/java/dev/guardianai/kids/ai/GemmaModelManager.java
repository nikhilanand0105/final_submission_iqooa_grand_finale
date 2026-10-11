package dev.guardianai.kids.ai;

import android.app.ActivityManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.google.ai.edge.litertlm.Backend;
import com.google.ai.edge.litertlm.Content;
import com.google.ai.edge.litertlm.Contents;
import com.google.ai.edge.litertlm.Conversation;
import com.google.ai.edge.litertlm.ConversationConfig;
import com.google.ai.edge.litertlm.Engine;
import com.google.ai.edge.litertlm.EngineConfig;
import com.google.ai.edge.litertlm.Message;
import com.google.ai.edge.litertlm.MessageCallback;
import com.google.ai.edge.litertlm.SamplerConfig;

import dev.guardianai.ai.explain.LanguageModel;
import dev.guardianai.ai.explain.ModelState;
import dev.guardianai.kids.BuildConfig;
import dev.guardianai.util.CancellationToken;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Adapter between GuardianAi's {@link LanguageModel} boundary and the LiteRT-LM Android runtime
 * (com.google.ai.edge.litertlm:litertlm-android). Loads a Gemma-family .litertlm model from app-specific
 * storage only, off the main thread, with an optional SHA-256 integrity check, and releases it under memory
 * pressure. If no model file is present the state is UNAVAILABLE and callers use rules-based guidance.
 */
public final class GemmaModelManager implements LanguageModel {

    private static final String TAG = "GemmaModelManager";
    private static final long GENERATION_TIMEOUT_MS = 60_000;
    private static final int MAX_OUTPUT_CHARS = 4000;
    private static volatile GemmaModelManager instance;

    private final Context app;
    private final ExecutorService loader = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final Object genLock = new Object();

    private volatile ModelState state = ModelState.UNAVAILABLE;
    private volatile String lastError = "";
    private volatile String modelId = "";
    private volatile long lastLoadMs = -1, lastGenerationMs = -1, lastOutputChars = -1;
    private volatile String backendUsed = "";
    private volatile String integrity = "";
    private Engine engine;

    public static GemmaModelManager get(Context ctx) {
        if (instance == null) {
            synchronized (GemmaModelManager.class) {
                if (instance == null) instance = new GemmaModelManager(ctx.getApplicationContext());
            }
        }
        return instance;
    }

    private GemmaModelManager(Context app) {
        this.app = app;
        refreshAvailability();
    }

    public void addListener(Runnable r) { listeners.add(r); }
    public void removeListener(Runnable r) { listeners.remove(r); }

    private void setState(ModelState s, String err) {
        state = s;
        if (err != null) lastError = err;
        main.post(() -> { for (Runnable r : listeners) r.run(); });
    }

    @Override public ModelState getState() { return state; }
    @Override public String getModelId() { return modelId; }
    public String getLastError() { return lastError; }
    public String getBackendUsed() { return backendUsed; }
    public String getIntegrityNote() { return integrity; }
    public long getLastLoadMs() { return lastLoadMs; }
    public long getLastGenerationMs() { return lastGenerationMs; }
    public long getLastOutputChars() { return lastOutputChars; }

    /** Directories searched for the model: internal files/models and the app-specific external files/models. */
    public File[] modelDirs() {
        File ext = app.getExternalFilesDir("models");
        return new File[]{new File(app.getFilesDir(), "models"), ext};
    }

    /** The configured model file if present in app-specific storage; otherwise the single .litertlm found there. */
    public File findModelFile() {
        String name = BuildConfig.GEMMA_MODEL_FILE;
        for (File dir : modelDirs()) {
            if (dir == null || !dir.isDirectory()) continue;
            if (!name.isEmpty()) {
                File f = new File(dir, name);
                if (f.isFile() && f.length() > 0) return f;
            } else {
                File[] fs = dir.listFiles((d, n) -> n.endsWith(".litertlm"));
                if (fs != null && fs.length == 1 && fs[0].length() > 0) return fs[0];
            }
        }
        return null;
    }

    public void refreshAvailability() {
        if (state == ModelState.READY || state == ModelState.GENERATING || state == ModelState.INITIALIZING) return;
        File f = findModelFile();
        if (f == null) {
            modelId = "";
            setState(ModelState.UNAVAILABLE, "No .litertlm model file in " + modelDirs()[0] + " or the app's external files/models folder");
        } else {
            modelId = f.getName();
            if (state == ModelState.UNAVAILABLE) setState(ModelState.CLOSED, "");
        }
    }

    /** Loads the model on a background thread. Safe to call repeatedly. */
    public void loadAsync() {
        if (state == ModelState.READY || state == ModelState.INITIALIZING || state == ModelState.GENERATING) return;
        File f = findModelFile();
        if (f == null) {
            refreshAvailability();
            return;
        }
        setState(ModelState.INITIALIZING, "");
        loader.execute(() -> load(f));
    }

    private void load(File f) {
        long t0 = System.currentTimeMillis();
        try {
            ActivityManager am = (ActivityManager) app.getSystemService(Context.ACTIVITY_SERVICE);
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mi);
            long needed = Math.max(1_500L * 1024 * 1024, (long) (f.length() * 1.2));
            if (mi.lowMemory || mi.availMem < needed) {
                setState(ModelState.RESOURCE_CONSTRAINED, "Free memory " + (mi.availMem >> 20) + " MB is below the ~" + (needed >> 20)
                        + " MB needed for " + f.getName());
                return;
            }
            String expected = BuildConfig.GEMMA_MODEL_SHA256;
            if (!expected.isEmpty()) {
                String actual = sha256Cached(f);
                if (!expected.equals(actual)) {
                    integrity = "Checksum mismatch";
                    setState(ModelState.FAILED, "Model file checksum does not match the expected SHA-256; it was not loaded");
                    return;
                }
                integrity = "SHA-256 verified";
            } else {
                integrity = "Not verified (no expected SHA-256 configured)";
            }
            Engine e;
            try {
                e = new Engine(new EngineConfig(f.getAbsolutePath(), new Backend.GPU(), null, null, null, null, app.getCacheDir().getPath()));
                e.initialize();
                backendUsed = "GPU";
            } catch (Throwable gpu) {
                Log.w(TAG, "GPU backend unavailable, using CPU: " + gpu.getClass().getSimpleName());
                e = new Engine(new EngineConfig(f.getAbsolutePath(), new Backend.CPU(), null, null, null, null, app.getCacheDir().getPath()));
                e.initialize();
                backendUsed = "CPU";
            }
            synchronized (genLock) {
                engine = e;
            }
            modelId = f.getName();
            lastLoadMs = System.currentTimeMillis() - t0;
            setState(ModelState.READY, "");
        } catch (OutOfMemoryError oom) {
            setState(ModelState.RESOURCE_CONSTRAINED, "Ran out of memory while loading the model");
        } catch (Throwable t) {
            Log.e(TAG, "Model load failed", t);
            setState(ModelState.FAILED, "Model failed to load: " + t.getClass().getSimpleName());
        }
    }

    @Override
    public String generate(String systemInstruction, String userMessage, CancellationToken token) throws ModelException {
        synchronized (genLock) {
            if (state != ModelState.READY || engine == null) throw new ModelException("Model not ready", false, false);
            setState(ModelState.GENERATING, null);
            long t0 = System.currentTimeMillis();
            Conversation conv = null;
            try {
                ConversationConfig cfg = new ConversationConfig(Contents.Companion.of(systemInstruction),
                        Collections.<Message>emptyList(), Collections.emptyList(), new SamplerConfig(40, 0.9, 0.3, 0));
                conv = engine.createConversation(cfg);
                final StringBuilder out = new StringBuilder();
                final Throwable[] failure = {null};
                final CountDownLatch done = new CountDownLatch(1);
                final Conversation c = conv;
                conv.sendMessageAsync(userMessage, new MessageCallback() {
                    @Override public void onMessage(Message m) {
                        synchronized (out) {
                            out.append(text(m));
                            if (out.length() > MAX_OUTPUT_CHARS) c.cancelProcess();
                        }
                    }
                    @Override public void onDone() { done.countDown(); }
                    @Override public void onError(Throwable t) { failure[0] = t; done.countDown(); }
                });
                long deadline = t0 + GENERATION_TIMEOUT_MS;
                while (!done.await(200, TimeUnit.MILLISECONDS)) {
                    if (token != null && token.isCancelled()) {
                        conv.cancelProcess();
                        throw new ModelException("Cancelled", false, true);
                    }
                    if (System.currentTimeMillis() > deadline) {
                        conv.cancelProcess();
                        throw new ModelException("Timed out", true, false);
                    }
                }
                synchronized (out) {
                    if (failure[0] != null && out.length() <= MAX_OUTPUT_CHARS) {
                        throw new ModelException("Inference error: " + failure[0].getClass().getSimpleName(), false, false);
                    }
                    lastGenerationMs = System.currentTimeMillis() - t0;
                    lastOutputChars = out.length();
                    return out.toString();
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new ModelException("Interrupted", false, true);
            } catch (ModelException me) {
                throw me;
            } catch (Throwable t) {
                Log.e(TAG, "Generation failed", t);
                throw new ModelException("Inference error: " + t.getClass().getSimpleName(), false, false);
            } finally {
                if (conv != null) {
                    try {
                        conv.close();
                    } catch (Throwable ignored) {
                        // closing a cancelled conversation may throw; nothing else to release
                    }
                }
                if (state == ModelState.GENERATING) setState(engine != null ? ModelState.READY : ModelState.CLOSED, null);
            }
        }
    }

    private static String text(Message m) {
        if (m == null || m.getContents() == null) return "";
        StringBuilder b = new StringBuilder();
        for (Content c : m.getContents().getContents()) if (c instanceof Content.Text) b.append(((Content.Text) c).getText());
        return b.toString();
    }

    /** Frees the native model. Waits for any running generation to finish first. */
    public void release() {
        loader.execute(() -> {
            synchronized (genLock) {
                if (engine != null) {
                    try {
                        engine.close();
                    } catch (Throwable t) {
                        Log.w(TAG, "close failed", t);
                    }
                    engine = null;
                }
            }
            if (state == ModelState.READY || state == ModelState.GENERATING) setState(ModelState.CLOSED, "Released to save memory");
            else refreshAvailability();
        });
    }

    /**
     * Releases the model under real memory pressure: TRIM_MEMORY_RUNNING_CRITICAL (15, pre-API 34) or when the process
     * is in the background LRU list (40+). It is kept when the UI is merely hidden (20), so background notification
     * checks don't have to reload it each time; idle unloading is handled by the safety processor.
     */
    public void onTrimMemory(int level) {
        if ((level == 15 || level >= 40) && engine != null) release();
    }

    /** SHA-256 of the model, cached by path+size+mtime so multi-GB files are hashed once. */
    private String sha256Cached(File f) throws Exception {
        SharedPreferences p = app.getSharedPreferences("guardianai_model_integrity", Context.MODE_PRIVATE);
        String key = f.getAbsolutePath() + "|" + f.length() + "|" + f.lastModified();
        String cached = p.getString(key, null);
        if (cached != null) return cached;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[1 << 20];
        try (InputStream in = new FileInputStream(f)) {
            int r;
            while ((r = in.read(buf)) != -1) md.update(buf, 0, r);
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : md.digest()) hex.append(String.format("%02x", b));
        p.edit().clear().putString(key, hex.toString()).apply();
        return hex.toString();
    }
}
