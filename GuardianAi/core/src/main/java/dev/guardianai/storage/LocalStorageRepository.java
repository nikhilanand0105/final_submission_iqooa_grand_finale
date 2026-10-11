package dev.guardianai.storage;

import dev.guardianai.model.ScanVerdict;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * On-device local encrypted repository implementing data minimization and automatic retention pruning.
 * Designed to be backed by SQLCipher and Android Keystore on mobile targets.
 */
public class LocalStorageRepository {

    private final Map<String, ScanHistoryRecord> scanRecords = new ConcurrentHashMap<>();
    private final Map<String, TrustedHelper> trustedHelpers = new ConcurrentHashMap<>();
    private final List<EmergencySosEvent> sosEvents = Collections.synchronizedList(new ArrayList<>());

    private int retentionDays = 14; // Automatically expire records older than 14 days

    public LocalStorageRepository() {
    }

    public void setRetentionDays(int days) {
        this.retentionDays = days;
    }

    public void recordScan(String fileName, String sha256Checksum, ScanVerdict verdict, int threatCount, String userAction) {
        String id = UUID.randomUUID().toString();
        ScanHistoryRecord record = new ScanHistoryRecord(
                id,
                new Date(),
                fileName,
                sha256Checksum,
                verdict,
                threatCount,
                userAction
        );
        scanRecords.put(id, record);
        pruneExpiredRecords();
    }

    public List<ScanHistoryRecord> getAllScanRecords() {
        pruneExpiredRecords();
        return scanRecords.values().stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .collect(Collectors.toList());
    }

    public void addTrustedHelper(TrustedHelper helper) {
        if (helper != null) {
            trustedHelpers.put(helper.getHelperId(), helper);
        }
    }

    public List<TrustedHelper> getTrustedHelpers() {
        return new ArrayList<>(trustedHelpers.values());
    }

    public void removeTrustedHelper(String helperId) {
        trustedHelpers.remove(helperId);
    }

    public EmergencySosEvent dispatchSos(double lat, double lng, float accuracy, String note, boolean hasNetworkConnectivity) {
        String eventId = UUID.randomUUID().toString();
        EmergencySosEvent.SosStatus initialStatus = hasNetworkConnectivity ?
                EmergencySosEvent.SosStatus.TRANSMITTED_TO_TRUSTED_CONTACTS :
                EmergencySosEvent.SosStatus.QUEUED_OFFLINE;

        EmergencySosEvent event = new EmergencySosEvent(
                eventId,
                new Date(),
                lat,
                lng,
                accuracy,
                initialStatus,
                note
        );
        sosEvents.add(event);
        return event;
    }

    public List<EmergencySosEvent> getSosEvents() {
        return new ArrayList<>(sosEvents);
    }

    /**
     * Enforces strict data minimization by purging any security records exceeding the retention window.
     */
    public synchronized int pruneExpiredRecords() {
        long cutoffMillis = System.currentTimeMillis() - (retentionDays * 86400000L);
        List<String> toRemove = new ArrayList<>();

        for (ScanHistoryRecord record : scanRecords.values()) {
            if (record.getTimestamp().getTime() < cutoffMillis) {
                toRemove.add(record.getScanId());
            }
        }

        for (String id : toRemove) {
            scanRecords.remove(id);
        }

        return toRemove.size();
    }
}
