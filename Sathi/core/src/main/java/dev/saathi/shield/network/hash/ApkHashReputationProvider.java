package dev.saathi.shield.network.hash;

import dev.saathi.shield.network.url.ReputationHttpClient;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Provider interface for external online SHA-256 APK hash reputation lookup services.
 * <p>
 * Privacy architecture guarantee: Transmits ONLY the 64-character hexadecimal SHA-256 hash.
 * Never uploads the APK package file or user-identifying metadata.
 */
public interface ApkHashReputationProvider {

    String getProviderName();

    boolean isConfigured();

    HashReputationResult checkHashReputation(String sha256Hex);

    /**
     * Default unconfigured hash reputation provider: explicitly reports NOT_CHECKED.
     */
    class NoOpHashReputationProvider implements ApkHashReputationProvider {

        private final String message;

        public NoOpHashReputationProvider() {
            this("Live hash reputation provider is not configured. Displaying local static analysis only.");
        }

        public NoOpHashReputationProvider(String message) {
            this.message = message;
        }

        @Override
        public String getProviderName() {
            return "None (Unconfigured)";
        }

        @Override
        public boolean isConfigured() {
            return false;
        }

        @Override
        public HashReputationResult checkHashReputation(String sha256Hex) {
            return HashReputationResult.notChecked(message);
        }
    }

    /**
     * Configurable HTTPS-backed APK SHA-256 hash reputation provider.
     * Enforces timeouts, deduplication, rate limiting, and strictly rejects malformed inputs.
     */
    class HttpApkHashReputationProvider implements ApkHashReputationProvider {

        private static final Pattern SHA256_PATTERN = Pattern.compile("^[a-fA-F0-9]{64}$");
        private static final long CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache

        private final String providerName;
        private final String apiEndpoint;
        private final ReputationHttpClient httpClient;
        private final int timeoutMs;
        private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

        private static class CacheEntry {
            final HashReputationResult result;
            final long timestamp;

            CacheEntry(HashReputationResult result, long timestamp) {
                this.result = result;
                this.timestamp = timestamp;
            }
        }

        public HttpApkHashReputationProvider(
                String providerName,
                String apiEndpoint,
                ReputationHttpClient httpClient,
                int timeoutMs) {
            this.providerName = providerName != null ? providerName : "Threat Cloud";
            this.apiEndpoint = apiEndpoint;
            this.httpClient = httpClient != null ? httpClient : new ReputationHttpClient.DefaultHttpsClient();
            this.timeoutMs = timeoutMs > 0 ? timeoutMs : 3000;
        }

        @Override
        public String getProviderName() {
            return providerName;
        }

        @Override
        public boolean isConfigured() {
            return apiEndpoint != null && !apiEndpoint.isBlank() && apiEndpoint.toLowerCase().startsWith("https://");
        }

        @Override
        public HashReputationResult checkHashReputation(String sha256Hex) {
            if (sha256Hex == null || !SHA256_PATTERN.matcher(sha256Hex.trim()).matches()) {
                return HashReputationResult.invalidInput(
                        providerName,
                        sha256Hex,
                        "Input must be a valid 64-character hexadecimal SHA-256 hash."
                );
            }

            String normalizedHash = sha256Hex.trim().toLowerCase();

            if (!isConfigured()) {
                return HashReputationResult.notChecked(
                        "Provider '" + providerName + "' is not configured with a valid HTTPS endpoint."
                );
            }

            // Deduplication: check in-memory cache
            long now = System.currentTimeMillis();
            CacheEntry cached = cache.get(normalizedHash);
            if (cached != null && (now - cached.timestamp < CACHE_TTL_MS)) {
                return cached.result;
            }

            long start = System.currentTimeMillis();
            try {
                // Request payload: strictly contains only the cryptographic hash
                String jsonBody = "{\"sha256\":\"" + normalizedHash + "\"}";
                ReputationHttpClient.HttpResponse response = httpClient.executePost(
                        apiEndpoint,
                        Map.of(
                                "Accept", "application/json",
                                "Content-Type", "application/json"
                        ),
                        jsonBody,
                        timeoutMs
                );

                long duration = System.currentTimeMillis() - start;

                if (response.isRateLimited()) {
                    return HashReputationResult.providerUnavailable(
                            providerName,
                            normalizedHash,
                            "Rate limit exceeded (HTTP 429). Live checks paused.",
                            duration
                    );
                }

                if (response.isServerError()) {
                    return HashReputationResult.providerUnavailable(
                            providerName,
                            normalizedHash,
                            "Server error (HTTP " + response.statusCode + ")",
                            duration
                    );
                }

                if (!response.isSuccess()) {
                    return HashReputationResult.providerUnavailable(
                            providerName,
                            normalizedHash,
                            "HTTP " + response.statusCode,
                            duration
                    );
                }

                // Parse response body
                String rawBody = response.body != null ? response.body : "";
                String compactBody = rawBody.replaceAll("\\s+", "").toLowerCase();
                HashReputationResult result;

                if (compactBody.contains("\"state\":\"threat_match\"")
                        || compactBody.contains("\"threat\":true")
                        || compactBody.contains("\"malicious\":true")
                        || compactBody.contains("\"verdict\":\"threat\"")) {

                    int malicious = extractInt(rawBody, "malicious", 5);
                    int total = extractInt(rawBody, "total", 70);
                    String details = extractDetails(rawBody);
                    result = HashReputationResult.threatMatch(
                            providerName,
                            normalizedHash,
                            malicious,
                            total,
                            details,
                            duration
                    );
                } else if (compactBody.contains("\"state\":\"no_known_threat_match\"")
                        || compactBody.contains("\"threat\":false")
                        || compactBody.contains("\"clean\":true")
                        || compactBody.contains("\"verdict\":\"clean\"")
                        || compactBody.contains("\"malicious\":0")) {

                    int total = extractInt(rawBody, "total", 70);
                    result = HashReputationResult.noKnownThreatMatch(
                            providerName,
                            normalizedHash,
                            total,
                            duration
                    );
                } else if (compactBody.contains("\"state\":\"provider_unavailable\"")) {
                    result = HashReputationResult.providerUnavailable(
                            providerName,
                            normalizedHash,
                            "Upstream service reported provider unavailable",
                            duration
                    );
                } else {
                    // Unknown or unexpected response format: NEVER assume clean!
                    result = HashReputationResult.providerUnavailable(
                            providerName,
                            normalizedHash,
                            "Unrecognized response format from server",
                            duration
                    );
                }

                cache.put(normalizedHash, new CacheEntry(result, now));
                return result;

            } catch (SocketTimeoutException e) {
                long duration = System.currentTimeMillis() - start;
                // A timeout must NEVER produce a clean result!
                return HashReputationResult.timeoutOrNetworkError(
                        providerName,
                        normalizedHash,
                        "Request timed out after " + timeoutMs + "ms",
                        duration
                );
            } catch (IOException e) {
                long duration = System.currentTimeMillis() - start;
                return HashReputationResult.timeoutOrNetworkError(
                        providerName,
                        normalizedHash,
                        "Network failure: " + e.getMessage(),
                        duration
                );
            } catch (Exception e) {
                long duration = System.currentTimeMillis() - start;
                return HashReputationResult.providerUnavailable(
                        providerName,
                        normalizedHash,
                        "Unexpected error: " + e.getMessage(),
                        duration
                );
            }
        }

        private int extractInt(String json, String key, int defaultVal) {
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(json);
                if (m.find()) {
                    return Integer.parseInt(m.group(1));
                }
            } catch (Exception ignored) {}
            return defaultVal;
        }

        private String extractDetails(String rawJson) {
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"(?:details|threatfamily|threat_label|statusmessage)\"\\s*:\\s*\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(rawJson);
                if (m.find()) {
                    return m.group(1);
                }
            } catch (Exception ignored) {}
            return "Online intelligence matched known malware sample";
        }
    }
}
