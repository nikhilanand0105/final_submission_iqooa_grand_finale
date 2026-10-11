package dev.saathi.storage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2 Unit Tests covering Saathi Kids local data foundation and persistence requirements:
 * 1. Empty states initialization (no fictional records inserted)
 * 2. Trusted-adult CRUD and validation
 * 3. Lesson completion and timestamp tracking
 * 4. User preference updates (language, contrast, typography, onboarding, family link)
 * 5. Check history audit records (with data minimization: no raw messages or URLs)
 * 6. Emergency help request lifecycle records
 * 7. Persistence after process restart simulation
 */
public class SaathiKidsStorageTest {

    private KidsPersistenceStore store;

    @BeforeEach
    public void setUp() {
        store = new KidsPersistenceStore();
    }

    @Test
    public void testEmptyStates() {
        // Genuine empty state: no sample adults, no fake activity
        assertTrue(store.getTrustedAdults().isEmpty(), "Fresh store must have empty trusted adults");
        assertEquals(0, store.getCompletedLessonCount(), "Fresh store must have 0 completed lessons");
        assertEquals(0, store.getCheckCount(), "Fresh store must have 0 check history records");
        assertTrue(store.getHelpRequests().isEmpty(), "Fresh store must have empty help requests");
        assertFalse(store.getBooleanPreference("onboarding_completed", false), "Onboarding defaults to false");
        assertFalse(store.getBooleanPreference("family_paired", false), "Family pairing defaults to false");
        assertEquals("en", store.getPreference("language_code", "en"), "Language defaults to English");
    }

    @Test
    public void testTrustedAdultCrud() {
        // 1. Validation: invalid adult without name is rejected
        KidsPersistenceStore.TrustedAdultRecord invalid = new KidsPersistenceStore.TrustedAdultRecord(
                "adult_invalid", "", "", "", false, 0, System.currentTimeMillis(), System.currentTimeMillis()
        );
        assertFalse(store.addTrustedAdult(invalid), "Adult with blank name must be rejected");
        assertEquals(0, store.getTrustedAdults().size());

        // 2. Add adult
        long now = System.currentTimeMillis();
        KidsPersistenceStore.TrustedAdultRecord adult1 = new KidsPersistenceStore.TrustedAdultRecord(
                "adult_mom", "Mom", "Mother", "+91 9876543210", true, 0, now, now
        );
        assertTrue(store.addTrustedAdult(adult1));
        assertEquals(1, store.getTrustedAdults().size());

        // 3. Add second adult with display order
        KidsPersistenceStore.TrustedAdultRecord adult2 = new KidsPersistenceStore.TrustedAdultRecord(
                "adult_dad", "Dad", "Father", "+91 9876543211", false, 1, now + 10, now + 10
        );
        assertTrue(store.addTrustedAdult(adult2));
        List<KidsPersistenceStore.TrustedAdultRecord> adults = store.getTrustedAdults();
        assertEquals(2, adults.size());
        assertEquals("Mom", adults.get(0).name);
        assertEquals("Dad", adults.get(1).name);

        // 4. Update adult
        KidsPersistenceStore.TrustedAdultRecord updatedMom = new KidsPersistenceStore.TrustedAdultRecord(
                "adult_mom", "Maa", "Mother", "+91 9876543210", true, 0, now, now + 20
        );
        assertTrue(store.addTrustedAdult(updatedMom));
        assertEquals(2, store.getTrustedAdults().size());
        assertEquals("Maa", store.getTrustedAdults().get(0).name);

        // 5. Delete adult
        assertTrue(store.removeTrustedAdult("adult_dad"));
        assertEquals(1, store.getTrustedAdults().size());
        assertEquals("adult_mom", store.getTrustedAdults().get(0).id);

        // 6. Clear all
        store.clearTrustedAdults();
        assertTrue(store.getTrustedAdults().isEmpty());
    }

    @Test
    public void testLessonCompletionTracking() {
        assertFalse(store.isLessonCompleted("lesson_prizes"));
        assertEquals(0L, store.getLessonCompletedTimestamp("lesson_prizes"));

        long completeTime = System.currentTimeMillis();
        store.markLessonCompleted("lesson_prizes", completeTime);

        assertTrue(store.isLessonCompleted("lesson_prizes"));
        assertEquals(completeTime, store.getLessonCompletedTimestamp("lesson_prizes"));
        assertEquals(1, store.getCompletedLessonCount());

        // Complete another lesson
        store.markLessonCompleted("lesson_passwords", completeTime + 100);
        assertEquals(2, store.getCompletedLessonCount());

        // Reset
        store.resetLessonProgress();
        assertEquals(0, store.getCompletedLessonCount());
        assertFalse(store.isLessonCompleted("lesson_prizes"));
    }

    @Test
    public void testPreferenceUpdates() {
        // Language preference
        store.setPreference("language_code", "hi");
        assertEquals("hi", store.getPreference("language_code", "en"));

        // Large typography accessibility toggle
        store.setBooleanPreference("large_typography", true);
        assertTrue(store.getBooleanPreference("large_typography", false));

        // High contrast accessibility toggle
        store.setBooleanPreference("high_contrast", true);
        assertTrue(store.getBooleanPreference("high_contrast", false));

        // Onboarding completion
        store.setBooleanPreference("onboarding_completed", true);
        assertTrue(store.getBooleanPreference("onboarding_completed", false));

        // Family pairing
        store.setBooleanPreference("family_paired", true);
        assertTrue(store.getBooleanPreference("family_paired", false));
    }

    @Test
    public void testCheckHistoryInsertionQueryAndDeletion() {
        long t1 = System.currentTimeMillis();
        KidsPersistenceStore.CheckAuditRecord r1 = new KidsPersistenceStore.CheckAuditRecord(
                "chk_1", "MESSAGE", t1, "SAATHI_SENSE_LINGUISTIC", "WARNING_SIGNS",
                "Asking for sensitive personal information", "Secrecy demand; OTP request", "EVALUATED"
        );
        store.recordCheck(r1);

        long t2 = t1 + 500;
        KidsPersistenceStore.CheckAuditRecord r2 = new KidsPersistenceStore.CheckAuditRecord(
                "chk_2", "LINK", t2, "PHISHING_URL_HEURISTICS", "LOOKS_OKAY",
                "Normal web address structure", "", "EVALUATED"
        );
        store.recordCheck(r2);

        assertEquals(2, store.getCheckCount());
        List<KidsPersistenceStore.CheckAuditRecord> history = store.getCheckHistory();
        // Query results sorted newest first
        assertEquals("chk_2", history.get(0).recordId);
        assertEquals("chk_1", history.get(1).recordId);

        // Delete single check
        assertTrue(store.deleteCheck("chk_1"));
        assertEquals(1, store.getCheckCount());
        assertEquals("chk_2", store.getCheckHistory().get(0).recordId);

        // Clear all
        store.clearCheckHistory();
        assertEquals(0, store.getCheckCount());
    }

    @Test
    public void testHelpRequestLifecycle() {
        long now = System.currentTimeMillis();
        KidsPersistenceStore.HelpAuditRecord req = new KidsPersistenceStore.HelpAuditRecord(
                "help_101", "Mom", "+91 9876543210", "Someone is pressuring me",
                "LOGGED_LOCAL", "ON_DEVICE_SIMULATION", now, now
        );
        store.recordHelpRequest(req);

        List<KidsPersistenceStore.HelpAuditRecord> requests = store.getHelpRequests();
        assertEquals(1, requests.size());
        assertEquals("help_101", requests.get(0).requestId);
        assertEquals("Mom", requests.get(0).recipientName);
        assertEquals("Someone is pressuring me", requests.get(0).reasonCategory);
        assertEquals("LOGGED_LOCAL", requests.get(0).lifecycleState);
        assertEquals("ON_DEVICE_SIMULATION", requests.get(0).deliveryMetadata);

        store.clearHelpRequests();
        assertTrue(store.getHelpRequests().isEmpty());
    }

    @Test
    public void testPersistenceAfterProcessRestart() throws IOException {
        // 1. Setup rich state in Store 1
        store.setPreference("language_code", "hi");
        store.setBooleanPreference("large_typography", true);
        store.setBooleanPreference("high_contrast", true);
        store.setBooleanPreference("onboarding_completed", true);

        long now = System.currentTimeMillis();
        store.markLessonCompleted("lesson_prizes", now);
        store.markLessonCompleted("lesson_links", now + 10);

        store.addTrustedAdult(new KidsPersistenceStore.TrustedAdultRecord(
                "adult_mom", "Maa", "Mother", "+91 9999900000", true, 0, now, now
        ));
        store.addTrustedAdult(new KidsPersistenceStore.TrustedAdultRecord(
                "adult_papa", "Papa", "Father", "+91 8888800000", false, 1, now + 5, now + 5
        ));

        store.recordCheck(new KidsPersistenceStore.CheckAuditRecord(
                "chk_1", "FILE", now, "FILE_SECURITY_CHECK", "WARNING_SIGNS",
                "Unknown APK download", "Unverified APK", "EVALUATED"
        ));

        store.recordHelpRequest(new KidsPersistenceStore.HelpAuditRecord(
                "sos_1", "Maa", "+91 9999900000", "Someone is being mean",
                "LOGGED_LOCAL", "ON_DEVICE_SIMULATION", now, now
        ));

        // 2. Export serialized snapshot (simulating write to disk)
        byte[] snapshot = store.exportSnapshot();
        assertNotNull(snapshot);
        assertTrue(snapshot.length > 0);

        // 3. Process restart: instantiate a new fresh store and restore from snapshot
        KidsPersistenceStore restoredStore = new KidsPersistenceStore();
        restoredStore.importSnapshot(snapshot);

        // 4. Verify all state survived process restart exactly
        assertEquals("hi", restoredStore.getPreference("language_code", "en"));
        assertTrue(restoredStore.getBooleanPreference("large_typography", false));
        assertTrue(restoredStore.getBooleanPreference("high_contrast", false));
        assertTrue(restoredStore.getBooleanPreference("onboarding_completed", false));

        assertEquals(2, restoredStore.getCompletedLessonCount());
        assertTrue(restoredStore.isLessonCompleted("lesson_prizes"));
        assertTrue(restoredStore.isLessonCompleted("lesson_links"));

        assertEquals(2, restoredStore.getTrustedAdults().size());
        assertEquals("Maa", restoredStore.getTrustedAdults().get(0).name);
        assertEquals("Papa", restoredStore.getTrustedAdults().get(1).name);

        assertEquals(1, restoredStore.getCheckCount());
        assertEquals("chk_1", restoredStore.getCheckHistory().get(0).recordId);
        assertEquals("FILE", restoredStore.getCheckHistory().get(0).checkType);

        assertEquals(1, restoredStore.getHelpRequests().size());
        assertEquals("sos_1", restoredStore.getHelpRequests().get(0).requestId);
        assertEquals("Maa", restoredStore.getHelpRequests().get(0).recipientName);
    }
}
