package dev.guardianai.personal.data.executor;

import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Global executor pools for disk I/O and UI main thread callbacks.
 * Pure native Android SDK without third-party reactive dependencies.
 */
public class AppExecutors {

    private static final Object LOCK = new Object();
    private static AppExecutors instance;

    private final Executor diskIO;
    private final Executor mainThread;

    public AppExecutors(Executor diskIO, Executor mainThread) {
        this.diskIO = diskIO;
        this.mainThread = mainThread;
    }

    public static AppExecutors getInstance() {
        if (instance == null) {
            synchronized (LOCK) {
                if (instance == null) {
                    ThreadFactory dbThreadFactory = r -> {
                        Thread t = new Thread(r, "guardianai-db-worker");
                        t.setDaemon(true);
                        return t;
                    };
                    instance = new AppExecutors(
                            Executors.newSingleThreadExecutor(dbThreadFactory),
                            new MainThreadExecutor()
                    );
                }
            }
        }
        return instance;
    }

    public static AppExecutors get() {
        return getInstance();
    }

    public Executor diskIO() {
        return diskIO;
    }

    public Executor mainThread() {
        return mainThread;
    }

    private static class MainThreadExecutor implements Executor {
        private final Handler mainThreadHandler = new Handler(Looper.getMainLooper());

        @Override
        public void execute(Runnable command) {
            mainThreadHandler.post(command);
        }
    }
}
