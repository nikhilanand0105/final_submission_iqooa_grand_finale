package dev.saathi.shield.network;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local-first Network Firewall and Data-Transfer Monitoring engine.
 * Applies destination-based blocking rules and monitors background data transfers against baselines
 * while transparently reporting VPN conflicts and encrypted payload limitations.
 */
public class LocalFirewallEngine {

    public enum FirewallStatus {
        ACTIVE,
        DISABLED_BY_USER,
        VPN_CONFLICT,
        LIMITED_BY_OS_RESTRICTIONS
    }

    public static class BlockedConnectionRecord {
        public final Date timestamp;
        public final String destinationHost;
        public final int port;
        public final String reason;

        public BlockedConnectionRecord(Date timestamp, String destinationHost, int port, String reason) {
            this.timestamp = timestamp;
            this.destinationHost = destinationHost;
            this.port = port;
            this.reason = reason;
        }
    }

    private FirewallStatus currentStatus = FirewallStatus.ACTIVE;
    private final Set<String> blockedDestinations = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final List<BlockedConnectionRecord> blockedLogs = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Long> appDataTransferBaselines = new ConcurrentHashMap<>(); // pkgName -> bytes transferred

    public LocalFirewallEngine() {
        // Known C2 and malicious destination blocks
        blockedDestinations.add("malicious-c2-trojan.com");
        blockedDestinations.add("free-bgmi-uc-rewards.biz");
        blockedDestinations.add("phishing-sbi-portal.xyz");
    }

    public FirewallStatus getStatus() {
        return currentStatus;
    }

    public void setStatus(FirewallStatus status) {
        this.currentStatus = status;
    }

    public void blockDestination(String host) {
        if (host != null) {
            blockedDestinations.add(host.toLowerCase());
        }
    }

    public boolean shouldBlockConnection(String host, int port) {
        if (currentStatus != FirewallStatus.ACTIVE || host == null) {
            return false;
        }

        String lower = host.toLowerCase();
        for (String blocked : blockedDestinations) {
            if (lower.equals(blocked) || lower.endsWith("." + blocked)) {
                blockedLogs.add(new BlockedConnectionRecord(new Date(), host, port, "Matched blocked destination rule: " + blocked));
                return true;
            }
        }

        return false;
    }

    /**
     * Flags anomalous background data transfers compared against typical application baselines.
     * Differentiates suspicious volume from confirmed data theft since payload is TLS encrypted.
     */
    public boolean checkAnomalousBackgroundTransfer(String packageName, long bytesTransferred) {
        long baseline = appDataTransferBaselines.getOrDefault(packageName, 10_000_000L); // 10MB baseline default

        // Record updated baseline
        appDataTransferBaselines.put(packageName, bytesTransferred);

        // If background transfer exceeds 5x baseline and is over 50MB, flag as anomalous
        return bytesTransferred > (baseline * 5) && bytesTransferred > 50_000_000L;
    }

    public List<BlockedConnectionRecord> getBlockedLogs() {
        return new ArrayList<>(blockedLogs);
    }

    public String getStatusExplanation() {
        switch (currentStatus) {
            case ACTIVE:
                return "Local DNS Firewall is active. Traffic is inspected locally on-device without external proxy relaying.";
            case VPN_CONFLICT:
                return "Protection restricted: Another active VPN or private DNS is in use on this device.";
            case LIMITED_BY_OS_RESTRICTIONS:
                return "Operating system background battery optimization is restricting continuous metadata observation.";
            case DISABLED_BY_USER:
            default:
                return "Network firewall is currently disabled.";
        }
    }
}
