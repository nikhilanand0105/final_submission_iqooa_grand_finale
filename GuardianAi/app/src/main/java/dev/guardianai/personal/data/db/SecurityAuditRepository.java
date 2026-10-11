package dev.guardianai.personal.data.db;

import android.content.Context;

import dev.guardianai.personal.data.executor.AppExecutors;

import java.util.List;
import java.util.Objects;

/**
 * Repository mediating between SQLite database operations and consumer components.
 * Exposes asynchronous callback-driven APIs for UI controllers and synchronous variants for unit tests.
 */
public class SecurityAuditRepository {

    public interface Callback<T> {
        void onResult(T result);
    }

    private static volatile SecurityAuditRepository instance;

    private final GuardianAiDatabaseHelper dbHelper;
    private final AppExecutors executors;

    public SecurityAuditRepository(GuardianAiDatabaseHelper dbHelper, AppExecutors executors) {
        this.dbHelper = Objects.requireNonNull(dbHelper, "dbHelper cannot be null");
        this.executors = Objects.requireNonNull(executors, "executors cannot be null");
    }

    public static SecurityAuditRepository getInstance(Context context) {
        if (instance == null) {
            synchronized (SecurityAuditRepository.class) {
                if (instance == null) {
                    Context appCtx = context.getApplicationContext();
                    GuardianAiDatabaseHelper helper = new GuardianAiDatabaseHelper(appCtx);
                    AppExecutors execs = AppExecutors.getInstance();
                    instance = new SecurityAuditRepository(helper, execs);
                }
            }
        }
        return instance;
    }

    public static SecurityAuditRepository getInstance(GuardianAiDatabaseHelper helper, AppExecutors execs) {
        if (instance == null) {
            synchronized (SecurityAuditRepository.class) {
                if (instance == null) {
                    instance = new SecurityAuditRepository(helper, execs);
                }
            }
        }
        return instance;
    }

    // ==========================================
    // Asynchronous API (Dispatched to Disk I/O, Callback on Main Thread)
    // ==========================================

    public void insertScan(ScanRecord scan, List<FindingRecord> findings, Callback<Void> callback) {
        executors.diskIO().execute(() -> {
            dbHelper.insertScan(scan, findings);
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(null));
            }
        });
    }

    public void getAllScans(Callback<List<ScanRecord>> callback) {
        executors.diskIO().execute(() -> {
            List<ScanRecord> records = dbHelper.getAllScans();
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(records));
            }
        });
    }

    public void getScansByType(String type, Callback<List<ScanRecord>> callback) {
        executors.diskIO().execute(() -> {
            List<ScanRecord> records = dbHelper.getScansByType(type);
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(records));
            }
        });
    }

    public void getRecentScans(int limit, Callback<List<ScanRecord>> callback) {
        executors.diskIO().execute(() -> {
            List<ScanRecord> records = dbHelper.getRecentScans(limit);
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(records));
            }
        });
    }

    public void getFindingsForScan(String scanId, Callback<List<FindingRecord>> callback) {
        executors.diskIO().execute(() -> {
            List<FindingRecord> findings = dbHelper.getFindingsForScan(scanId);
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(findings));
            }
        });
    }

    public void getScanStats(Callback<ScanStats> callback) {
        executors.diskIO().execute(() -> {
            ScanStats stats = dbHelper.getScanStats();
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(stats));
            }
        });
    }

    public void deleteScan(String scanId, Callback<Boolean> callback) {
        executors.diskIO().execute(() -> {
            boolean success = dbHelper.deleteScan(scanId);
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(success));
            }
        });
    }

    public void clearAllScans(Callback<Void> callback) {
        executors.diskIO().execute(() -> {
            dbHelper.clearAllScans();
            if (callback != null) {
                executors.mainThread().execute(() -> callback.onResult(null));
            }
        });
    }

    // ==========================================
    // Synchronous API (For Unit Testing & Direct Thread Operations)
    // ==========================================

    public void insertScanSync(ScanRecord scan, List<FindingRecord> findings) {
        dbHelper.insertScan(scan, findings);
    }

    public List<ScanRecord> getAllScansSync() {
        return dbHelper.getAllScans();
    }

    public List<ScanRecord> getScansByTypeSync(String type) {
        return dbHelper.getScansByType(type);
    }

    public List<ScanRecord> getRecentScansSync(int limit) {
        return dbHelper.getRecentScans(limit);
    }

    public List<FindingRecord> getFindingsForScanSync(String scanId) {
        return dbHelper.getFindingsForScan(scanId);
    }

    public ScanStats getScanStatsSync() {
        return dbHelper.getScanStats();
    }

    public boolean deleteScanSync(String scanId) {
        return dbHelper.deleteScan(scanId);
    }

    public void clearAllScansSync() {
        dbHelper.clearAllScans();
    }
}
