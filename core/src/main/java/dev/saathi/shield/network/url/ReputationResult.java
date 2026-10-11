package dev.saathi.shield.network.url;

import java.util.Objects;

/**
 * Encapsulates the response from a threat reputation provider.
 */
public class ReputationResult {

    private final ReputationState state;
    private final String providerName;
    private final String threatDetails;
    private final String statusMessage;
    private final long responseTimeMs;

    public ReputationResult(
            ReputationState state,
            String providerName,
            String threatDetails,
            String statusMessage,
            long responseTimeMs) {
        this.state = Objects.requireNonNull(state, "state cannot be null");
        this.providerName = providerName != null ? providerName : "None";
        this.threatDetails = threatDetails != null ? threatDetails : "";
        this.statusMessage = statusMessage != null ? statusMessage : "";
        this.responseTimeMs = responseTimeMs;
    }

    public static ReputationResult notChecked(String reason) {
        return new ReputationResult(
                ReputationState.NOT_CHECKED,
                "None",
                "",
                reason != null ? reason : "Live reputation was not checked.",
                0
        );
    }

    public static ReputationResult threatMatch(String providerName, String threatDetails, long responseTimeMs) {
        return new ReputationResult(
                ReputationState.THREAT_MATCH,
                providerName,
                threatDetails,
                "Threat match confirmed by " + providerName + ": " + threatDetails,
                responseTimeMs
        );
    }

    public static ReputationResult noKnownThreatMatch(String providerName, long responseTimeMs) {
        return new ReputationResult(
                ReputationState.NO_KNOWN_THREAT_MATCH,
                providerName,
                "",
                "No known threat match identified in " + providerName + " database.",
                responseTimeMs
        );
    }

    public static ReputationResult providerUnavailable(String providerName, String reason, long responseTimeMs) {
        return new ReputationResult(
                ReputationState.PROVIDER_UNAVAILABLE,
                providerName,
                "",
                "Reputation provider " + providerName + " is currently unavailable: " + reason,
                responseTimeMs
        );
    }

    public static ReputationResult timeoutOrNetworkError(String providerName, String reason, long responseTimeMs) {
        return new ReputationResult(
                ReputationState.TIMEOUT_NETWORK_ERROR,
                providerName,
                "",
                "Network timeout or connection error reaching " + providerName + ": " + reason + " (Status unverified).",
                responseTimeMs
        );
    }

    public static ReputationResult invalidInput(String providerName, String reason) {
        return new ReputationResult(
                ReputationState.INVALID_INPUT,
                providerName,
                "",
                "Web address could not be validated by " + providerName + ": " + reason,
                0
        );
    }

    public ReputationState getState() {
        return state;
    }

    public String getProviderName() {
        return providerName;
    }

    public String getThreatDetails() {
        return threatDetails;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public boolean isLiveCheckAttempted() {
        return state != ReputationState.NOT_CHECKED;
    }

    @Override
    public String toString() {
        return String.format("[%s] Provider: %s, Message: %s (%d ms)", state, providerName, statusMessage, responseTimeMs);
    }
}
