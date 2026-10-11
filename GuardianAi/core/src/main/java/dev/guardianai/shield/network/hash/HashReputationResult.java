package dev.guardianai.shield.network.hash;

import dev.guardianai.shield.network.url.ReputationState;

import java.util.Objects;

/**
 * Encapsulates the response from an online SHA-256 APK hash reputation lookup service.
 * <p>
 * Transmits ONLY the cryptographic hash — never the APK payload or binary code.
 */
public class HashReputationResult {

    private final ReputationState state;
    private final String providerName;
    private final String sha256Hex;
    private final int maliciousDetections;
    private final int totalEngines;
    private final String threatDetails;
    private final String statusMessage;
    private final long timestamp;
    private final long responseTimeMs;

    public HashReputationResult(
            ReputationState state,
            String providerName,
            String sha256Hex,
            int maliciousDetections,
            int totalEngines,
            String threatDetails,
            String statusMessage,
            long timestamp,
            long responseTimeMs) {
        this.state = Objects.requireNonNull(state, "state cannot be null");
        this.providerName = providerName != null ? providerName : "None";
        this.sha256Hex = sha256Hex != null ? sha256Hex.toLowerCase() : "";
        this.maliciousDetections = Math.max(0, maliciousDetections);
        this.totalEngines = Math.max(0, totalEngines);
        this.threatDetails = threatDetails != null ? threatDetails : "";
        this.statusMessage = statusMessage != null ? statusMessage : "";
        this.timestamp = timestamp > 0 ? timestamp : System.currentTimeMillis();
        this.responseTimeMs = responseTimeMs;
    }

    public static HashReputationResult notChecked(String reason) {
        return new HashReputationResult(
                ReputationState.NOT_CHECKED,
                "None",
                "",
                0,
                0,
                "",
                reason != null ? reason : "Live hash reputation was not checked.",
                System.currentTimeMillis(),
                0
        );
    }

    public static HashReputationResult threatMatch(
            String providerName,
            String sha256Hex,
            int malicious,
            int total,
            String details,
            long responseTimeMs) {
        String detailMsg = details != null && !details.isBlank() ? ": " + details : "";
        return new HashReputationResult(
                ReputationState.THREAT_MATCH,
                providerName,
                sha256Hex,
                malicious,
                total,
                details,
                "Malicious hash match confirmed by " + providerName + " (" + malicious + "/" + total + " detections" + detailMsg + ").",
                System.currentTimeMillis(),
                responseTimeMs
        );
    }

    public static HashReputationResult noKnownThreatMatch(
            String providerName,
            String sha256Hex,
            int totalEngines,
            long responseTimeMs) {
        return new HashReputationResult(
                ReputationState.NO_KNOWN_THREAT_MATCH,
                providerName,
                sha256Hex,
                0,
                totalEngines,
                "",
                "No known threat match identified for hash in " + providerName + " database.",
                System.currentTimeMillis(),
                responseTimeMs
        );
    }

    public static HashReputationResult providerUnavailable(
            String providerName,
            String sha256Hex,
            String reason,
            long responseTimeMs) {
        return new HashReputationResult(
                ReputationState.PROVIDER_UNAVAILABLE,
                providerName,
                sha256Hex,
                0,
                0,
                "",
                "Threat intelligence provider " + providerName + " unavailable: " + reason,
                System.currentTimeMillis(),
                responseTimeMs
        );
    }

    public static HashReputationResult timeoutOrNetworkError(
            String providerName,
            String sha256Hex,
            String reason,
            long responseTimeMs) {
        return new HashReputationResult(
                ReputationState.TIMEOUT_NETWORK_ERROR,
                providerName,
                sha256Hex,
                0,
                0,
                "",
                "Network timeout or connection error reaching " + providerName + ": " + reason + " (Status unverified).",
                System.currentTimeMillis(),
                responseTimeMs
        );
    }

    public static HashReputationResult invalidInput(
            String providerName,
            String sha256Hex,
            String reason) {
        return new HashReputationResult(
                ReputationState.INVALID_INPUT,
                providerName,
                sha256Hex,
                0,
                0,
                "",
                "SHA-256 hash could not be validated by " + providerName + ": " + reason,
                System.currentTimeMillis(),
                0
        );
    }

    public ReputationState getState() {
        return state;
    }

    public String getProviderName() {
        return providerName;
    }

    public String getSha256Hex() {
        return sha256Hex;
    }

    public int getMaliciousDetections() {
        return maliciousDetections;
    }

    public int getTotalEngines() {
        return totalEngines;
    }

    public String getThreatDetails() {
        return threatDetails;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public boolean isLiveCheckAttempted() {
        return state != ReputationState.NOT_CHECKED;
    }

    @Override
    public String toString() {
        return String.format("[%s] Provider: %s, SHA-256: %s, Detections: %d/%d, Message: %s (%d ms)",
                state, providerName, sha256Hex, maliciousDetections, totalEngines, statusMessage, responseTimeMs);
    }
}
