package dev.guardianai.util;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe cancellation token to allow interrupting long-running file analysis tasks.
 */
public class CancellationToken {

    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get() || Thread.currentThread().isInterrupted();
    }
}
