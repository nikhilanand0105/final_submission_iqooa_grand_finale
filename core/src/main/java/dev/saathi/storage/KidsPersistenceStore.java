package dev.saathi.storage;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Robust, cross-platform persistence engine for Saathi Kids local storage.
 * Handles app preferences, lesson completion, trusted adults, check audit history,
 * and help request records with serialization for surviving process restarts.
 */
public class KidsPersistenceStore {

    // Preferences
    private final Map<String, String> preferences = new ConcurrentHashMap<>();

    // Lesson progress: lessonId -> completedTimestamp
    private final Map<String, Long> lessonProgress = new ConcurrentHashMap<>();

    // Trusted adults: id -> TrustedHelperRecord
    private final Map<String, TrustedAdultRecord> trustedAdults = new ConcurrentHashMap<>();

    // Check history: recordId -> CheckAuditRecord
    private final Map<String, CheckAuditRecord> checkHistory = new ConcurrentHashMap<>();

    // Help requests
    private final List<HelpAuditRecord> helpRequests = Collections.synchronizedList(new ArrayList<>());

    public static class TrustedAdultRecord implements Serializable {
        public final String id;
        public final String name;
        public final String relationship;
        public final String phoneNumber;
        public final boolean isPrimary;
        public final int displayOrder;
        public final long createdTimestamp;
        public final long updatedTimestamp;

        public TrustedAdultRecord(
                String id, String name, String relationship, String phoneNumber,
                boolean isPrimary, int displayOrder, long createdTimestamp, long updatedTimestamp) {
            this.id = id;
            this.name = name != null ? name.trim() : "";
            this.relationship = relationship != null ? relationship.trim() : "";
            this.phoneNumber = phoneNumber != null ? phoneNumber.trim() : "";
            this.isPrimary = isPrimary;
            this.displayOrder = displayOrder;
            this.createdTimestamp = createdTimestamp;
            this.updatedTimestamp = updatedTimestamp;
        }

        public boolean isValid() {
            return !name.isEmpty() && (!relationship.isEmpty() || !phoneNumber.isEmpty());
        }
    }

    public static class CheckAuditRecord implements Serializable {
        public final String recordId;
        public final String checkType; // "MESSAGE", "LINK", "FILE"
        public final long timestamp;
        public final String engineIdentifier;
        public final String resultCategory;
        public final String summary;
        public final String indicatorsSummary;
        public final String status;

        public CheckAuditRecord(
                String recordId, String checkType, long timestamp, String engineIdentifier,
                String resultCategory, String summary, String indicatorsSummary, String status) {
            this.recordId = recordId;
            this.checkType = checkType;
            this.timestamp = timestamp;
            this.engineIdentifier = engineIdentifier;
            this.resultCategory = resultCategory;
            this.summary = summary;
            this.indicatorsSummary = indicatorsSummary != null ? indicatorsSummary : "";
            this.status = status;
        }
    }

    public static class HelpAuditRecord implements Serializable {
        public final String requestId;
        public final String recipientName;
        public final String recipientContact;
        public final String reasonCategory;
        public final String lifecycleState;
        public final String deliveryMetadata;
        public final long createdTimestamp;
        public final long updatedTimestamp;

        public HelpAuditRecord(
                String requestId, String recipientName, String recipientContact,
                String reasonCategory, String lifecycleState, String deliveryMetadata,
                long createdTimestamp, long updatedTimestamp) {
            this.requestId = requestId;
            this.recipientName = recipientName;
            this.recipientContact = recipientContact;
            this.reasonCategory = reasonCategory;
            this.lifecycleState = lifecycleState;
            this.deliveryMetadata = deliveryMetadata;
            this.createdTimestamp = createdTimestamp;
            this.updatedTimestamp = updatedTimestamp;
        }
    }

    public KidsPersistenceStore() {}

    // --- Preferences ---
    public void setPreference(String key, String value) {
        if (key != null) {
            if (value != null) preferences.put(key, value);
            else preferences.remove(key);
        }
    }

    public String getPreference(String key, String defaultValue) {
        return preferences.getOrDefault(key, defaultValue);
    }

    public boolean getBooleanPreference(String key, boolean defaultValue) {
        String val = preferences.get(key);
        return val != null ? Boolean.parseBoolean(val) : defaultValue;
    }

    public void setBooleanPreference(String key, boolean value) {
        preferences.put(key, Boolean.toString(value));
    }

    // --- Lesson Progress ---
    public void markLessonCompleted(String lessonId, long timestamp) {
        if (lessonId != null) {
            lessonProgress.put(lessonId, timestamp);
        }
    }

    public boolean isLessonCompleted(String lessonId) {
        return lessonProgress.containsKey(lessonId);
    }

    public long getLessonCompletedTimestamp(String lessonId) {
        return lessonProgress.getOrDefault(lessonId, 0L);
    }

    public int getCompletedLessonCount() {
        return lessonProgress.size();
    }

    public void resetLessonProgress() {
        lessonProgress.clear();
    }

    // --- Trusted Adults CRUD ---
    public boolean addTrustedAdult(TrustedAdultRecord adult) {
        if (adult == null || !adult.isValid()) {
            return false;
        }
        trustedAdults.put(adult.id, adult);
        return true;
    }

    public List<TrustedAdultRecord> getTrustedAdults() {
        return trustedAdults.values().stream()
                .sorted(Comparator.comparingInt((TrustedAdultRecord a) -> a.displayOrder)
                        .thenComparingLong(a -> a.createdTimestamp))
                .collect(Collectors.toList());
    }

    public boolean removeTrustedAdult(String id) {
        return trustedAdults.remove(id) != null;
    }

    public void clearTrustedAdults() {
        trustedAdults.clear();
    }

    // --- Check History ---
    public void recordCheck(CheckAuditRecord record) {
        if (record != null) {
            checkHistory.put(record.recordId, record);
        }
    }

    public List<CheckAuditRecord> getCheckHistory() {
        return checkHistory.values().stream()
                .sorted((a, b) -> Long.compare(b.timestamp, a.timestamp))
                .collect(Collectors.toList());
    }

    public int getCheckCount() {
        return checkHistory.size();
    }

    public boolean deleteCheck(String recordId) {
        return checkHistory.remove(recordId) != null;
    }

    public void clearCheckHistory() {
        checkHistory.clear();
    }

    // --- Help Requests ---
    public void recordHelpRequest(HelpAuditRecord request) {
        if (request != null) {
            helpRequests.add(0, request);
        }
    }

    public List<HelpAuditRecord> getHelpRequests() {
        return new ArrayList<>(helpRequests);
    }

    public void clearHelpRequests() {
        helpRequests.clear();
    }

    // --- Serialization for Process Restart Simulation ---
    public byte[] exportSnapshot() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // 1. Preferences
        dos.writeInt(preferences.size());
        for (Map.Entry<String, String> e : preferences.entrySet()) {
            dos.writeUTF(e.getKey());
            dos.writeUTF(e.getValue());
        }

        // 2. Lesson progress
        dos.writeInt(lessonProgress.size());
        for (Map.Entry<String, Long> e : lessonProgress.entrySet()) {
            dos.writeUTF(e.getKey());
            dos.writeLong(e.getValue());
        }

        // 3. Trusted Adults
        dos.writeInt(trustedAdults.size());
        for (TrustedAdultRecord a : trustedAdults.values()) {
            dos.writeUTF(a.id);
            dos.writeUTF(a.name);
            dos.writeUTF(a.relationship);
            dos.writeUTF(a.phoneNumber);
            dos.writeBoolean(a.isPrimary);
            dos.writeInt(a.displayOrder);
            dos.writeLong(a.createdTimestamp);
            dos.writeLong(a.updatedTimestamp);
        }

        // 4. Check History (NO raw user message/URL/file!)
        dos.writeInt(checkHistory.size());
        for (CheckAuditRecord c : checkHistory.values()) {
            dos.writeUTF(c.recordId);
            dos.writeUTF(c.checkType);
            dos.writeLong(c.timestamp);
            dos.writeUTF(c.engineIdentifier);
            dos.writeUTF(c.resultCategory);
            dos.writeUTF(c.summary);
            dos.writeUTF(c.indicatorsSummary);
            dos.writeUTF(c.status);
        }

        // 5. Help Requests
        dos.writeInt(helpRequests.size());
        for (HelpAuditRecord h : helpRequests) {
            dos.writeUTF(h.requestId);
            dos.writeUTF(h.recipientName);
            dos.writeUTF(h.recipientContact);
            dos.writeUTF(h.reasonCategory);
            dos.writeUTF(h.lifecycleState);
            dos.writeUTF(h.deliveryMetadata);
            dos.writeLong(h.createdTimestamp);
            dos.writeLong(h.updatedTimestamp);
        }

        dos.flush();
        return baos.toByteArray();
    }

    public void importSnapshot(byte[] snapshotBytes) throws IOException {
        if (snapshotBytes == null || snapshotBytes.length == 0) return;

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(snapshotBytes));

        // 1. Preferences
        preferences.clear();
        int prefSize = dis.readInt();
        for (int i = 0; i < prefSize; i++) {
            preferences.put(dis.readUTF(), dis.readUTF());
        }

        // 2. Lesson progress
        lessonProgress.clear();
        int lessonSize = dis.readInt();
        for (int i = 0; i < lessonSize; i++) {
            lessonProgress.put(dis.readUTF(), dis.readLong());
        }

        // 3. Trusted Adults
        trustedAdults.clear();
        int adultsSize = dis.readInt();
        for (int i = 0; i < adultsSize; i++) {
            String id = dis.readUTF();
            String name = dis.readUTF();
            String rel = dis.readUTF();
            String phone = dis.readUTF();
            boolean isPrim = dis.readBoolean();
            int order = dis.readInt();
            long created = dis.readLong();
            long updated = dis.readLong();
            trustedAdults.put(id, new TrustedAdultRecord(id, name, rel, phone, isPrim, order, created, updated));
        }

        // 4. Check History
        checkHistory.clear();
        int checkSize = dis.readInt();
        for (int i = 0; i < checkSize; i++) {
            String id = dis.readUTF();
            String type = dis.readUTF();
            long ts = dis.readLong();
            String engine = dis.readUTF();
            String cat = dis.readUTF();
            String sum = dis.readUTF();
            String ind = dis.readUTF();
            String stat = dis.readUTF();
            checkHistory.put(id, new CheckAuditRecord(id, type, ts, engine, cat, sum, ind, stat));
        }

        // 5. Help Requests
        helpRequests.clear();
        int helpSize = dis.readInt();
        for (int i = 0; i < helpSize; i++) {
            String id = dis.readUTF();
            String name = dis.readUTF();
            String contact = dis.readUTF();
            String reason = dis.readUTF();
            String state = dis.readUTF();
            String meta = dis.readUTF();
            long created = dis.readLong();
            long updated = dis.readLong();
            helpRequests.add(new HelpAuditRecord(id, name, contact, reason, state, meta, created, updated));
        }
    }
}
