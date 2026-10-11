package dev.saathi.personal.data;

import org.junit.Before;
import org.junit.Test;

import dev.saathi.personal.data.db.FindingRecord;
import dev.saathi.personal.data.db.SaathiDatabaseHelper;
import dev.saathi.personal.data.db.ScanRecord;
import dev.saathi.personal.data.db.ScanStats;
import dev.saathi.personal.data.db.SecurityAuditRepository;
import dev.saathi.personal.data.executor.AppExecutors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

public class SecurityAuditRepositoryTest {

    private FakeDatabaseHelper fakeDbHelper;
    private SecurityAuditRepository repository;

    @Before
    public void setUp() {
        fakeDbHelper = new FakeDatabaseHelper();
        // Direct synchronous executor for both disk and main thread in tests
        Executor directExecutor = Runnable::run;
        AppExecutors executors = new AppExecutors(directExecutor, directExecutor);
        repository = new SecurityAuditRepository(fakeDbHelper, executors);
    }

    @Test
    public void testInsertAndGetScansSync() {
        ScanRecord scan = new ScanRecord(
                "scan-101",
                "APK",
                System.currentTimeMillis(),
                "COMPLETED",
                "Clean APK verified",
                "app.apk",
                "1.0.0",
                true,
                "SAFE",
                "INFO",
                "Install allowed"
        );
        FindingRecord finding = new FindingRecord("f-1", "scan-101", "SIGNATURE", "INFO", "Valid certificate", "None");

        repository.insertScanSync(scan, List.of(finding));

        List<ScanRecord> allScans = repository.getAllScansSync();
        assertEquals(1, allScans.size());
        assertEquals("scan-101", allScans.get(0).getId());

        List<FindingRecord> findings = repository.getFindingsForScanSync("scan-101");
        assertEquals(1, findings.size());
        assertEquals("f-1", findings.get(0).getId());
    }

    @Test
    public void testGetScansByTypeSync() {
        ScanRecord s1 = new ScanRecord("s1", "APK", 1000L, "COMPLETED", "sum", "app.apk", "1.0.0", true, "SAFE", "INFO", "act");
        ScanRecord s2 = new ScanRecord("s2", "LINK", 2000L, "COMPLETED", "sum", "http://test", "1.0.0", true, "SAFE", "INFO", "act");
        ScanRecord s3 = new ScanRecord("s3", "MESSAGE", 3000L, "COMPLETED", "sum", "msg", "1.0.0", true, "SAFE", "INFO", "act");

        repository.insertScanSync(s1, null);
        repository.insertScanSync(s2, null);
        repository.insertScanSync(s3, null);

        List<ScanRecord> apks = repository.getScansByTypeSync("APK");
        assertEquals(1, apks.size());
        assertEquals("s1", apks.get(0).getId());

        List<ScanRecord> links = repository.getScansByTypeSync("LINK");
        assertEquals(1, links.size());
        assertEquals("s2", links.get(0).getId());
    }

    @Test
    public void testGetRecentScansSync() {
        for (int i = 1; i <= 5; i++) {
            ScanRecord s = new ScanRecord("s" + i, "APK", i * 1000L, "COMPLETED", "sum", "app" + i + ".apk", "1.0.0", true, "SAFE", "INFO", "act");
            repository.insertScanSync(s, null);
        }

        List<ScanRecord> recent3 = repository.getRecentScansSync(3);
        assertEquals(3, recent3.size());
    }

    @Test
    public void testDeleteScanSync() {
        ScanRecord s1 = new ScanRecord("del-1", "APK", 1000L, "COMPLETED", "sum", "app.apk", "1.0.0", true, "SAFE", "INFO", "act");
        repository.insertScanSync(s1, null);

        assertEquals(1, repository.getAllScansSync().size());
        boolean deleted = repository.deleteScanSync("del-1");
        assertTrue(deleted);
        assertEquals(0, repository.getAllScansSync().size());
    }

    @Test
    public void testClearAllScansSync() {
        ScanRecord s1 = new ScanRecord("c1", "APK", 1000L, "COMPLETED", "sum", "app1.apk", "1.0.0", true, "SAFE", "INFO", "act");
        ScanRecord s2 = new ScanRecord("c2", "LINK", 2000L, "COMPLETED", "sum", "app2.apk", "1.0.0", true, "SAFE", "INFO", "act");
        repository.insertScanSync(s1, null);
        repository.insertScanSync(s2, null);

        assertEquals(2, repository.getAllScansSync().size());
        repository.clearAllScansSync();
        assertEquals(0, repository.getAllScansSync().size());
    }

    @Test
    public void testAsyncCallbacks() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(3);
        AtomicReference<List<ScanRecord>> scansRef = new AtomicReference<>();
        AtomicReference<ScanStats> statsRef = new AtomicReference<>();
        AtomicBoolean clearFinished = new AtomicBoolean(false);

        ScanRecord s1 = new ScanRecord("async-1", "APK", 1000L, "COMPLETED", "sum", "test.apk", "1.0.0", true, "SAFE", "INFO", "act");

        repository.insertScan(s1, null, r -> {
            repository.getAllScans(scans -> {
                scansRef.set(scans);
                latch.countDown();
            });

            repository.getScanStats(stats -> {
                statsRef.set(stats);
                latch.countDown();
            });

            repository.clearAllScans(v -> {
                clearFinished.set(true);
                latch.countDown();
            });
        });

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        assertNotNull(scansRef.get());
        assertEquals(1, scansRef.get().size());
        assertNotNull(statsRef.get());
        assertTrue(clearFinished.get());
    }

    /**
     * Test stub of SaathiDatabaseHelper simulating in-memory storage.
     */
    private static class FakeDatabaseHelper extends SaathiDatabaseHelper {
        private final List<ScanRecord> scans = new ArrayList<>();
        private final List<FindingRecord> findings = new ArrayList<>();

        FakeDatabaseHelper() {
            super(null, "fake_test.db");
        }

        @Override
        public synchronized void insertScan(ScanRecord scan, List<FindingRecord> newFindings) {
            scans.removeIf(s -> s.getId().equals(scan.getId()));
            scans.add(0, scan);
            if (newFindings != null) {
                findings.addAll(newFindings);
            }
        }

        @Override
        public synchronized List<ScanRecord> getAllScans() {
            return new ArrayList<>(scans);
        }

        @Override
        public synchronized List<ScanRecord> getScansByType(String operationType) {
            List<ScanRecord> result = new ArrayList<>();
            for (ScanRecord s : scans) {
                if (s.getOperationType().equalsIgnoreCase(operationType)) {
                    result.add(s);
                }
            }
            return result;
        }

        @Override
        public synchronized List<ScanRecord> getRecentScans(int limit) {
            int take = Math.min(limit, scans.size());
            return new ArrayList<>(scans.subList(0, take));
        }

        @Override
        public synchronized List<FindingRecord> getFindingsForScan(String scanId) {
            List<FindingRecord> result = new ArrayList<>();
            for (FindingRecord f : findings) {
                if (f.getScanId().equals(scanId)) {
                    result.add(f);
                }
            }
            return result;
        }

        @Override
        public synchronized ScanStats getScanStats() {
            int total = scans.size();
            int safe = 0;
            int susp = 0;
            int mal = 0;
            for (ScanRecord s : scans) {
                if ("SAFE".equalsIgnoreCase(s.getVerdict())) safe++;
                else if ("SUSPICIOUS".equalsIgnoreCase(s.getVerdict())) susp++;
                else if ("KNOWN_MALICIOUS".equalsIgnoreCase(s.getVerdict())) mal++;
            }
            int unknown = Math.max(0, total - (safe + susp + mal));
            return new ScanStats(total, safe, susp, mal, unknown);
        }

        @Override
        public synchronized boolean deleteScan(String scanId) {
            boolean removed = scans.removeIf(s -> s.getId().equals(scanId));
            findings.removeIf(f -> f.getScanId().equals(scanId));
            return removed;
        }

        @Override
        public synchronized void clearAllScans() {
            scans.clear();
            findings.clear();
        }
    }
}
