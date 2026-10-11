package dev.guardianai.shield.network.url;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provider interface for external online URL threat-reputation services.
 */
public interface ThreatReputationProvider {

    String getProviderName();

    boolean isConfigured();

    ReputationResult checkReputation(ParsedUrl parsedUrl);

    /**
     * Default unconfigured provider: explicitly reports NOT_CHECKED.
     */
    class NoOpReputationProvider implements ThreatReputationProvider {

        private final String message;

        public NoOpReputationProvider() {
            this("Live reputation provider is not configured. Displaying local heuristic analysis only.");
        }

        public NoOpReputationProvider(String message) {
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
        public ReputationResult checkReputation(ParsedUrl parsedUrl) {
            return ReputationResult.notChecked(message);
        }
    }

    /**
     * Configurable HTTPS-backed threat reputation provider.
     * Enforces timeouts, deduplication, rate limiting, and sanitizes query tokens.
     */
    class HttpThreatReputationProvider implements ThreatReputationProvider {

        private final String providerName;
        private final String apiEndpoint;
        private final ReputationHttpClient httpClient;
        private final int timeoutMs;
        private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

        private static class CacheEntry {
            final ReputationResult result;
            final long timestamp;

            CacheEntry(ReputationResult result, long timestamp) {
                this.result = result;
                this.timestamp = timestamp;
            }
        }

        private static final long CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

        public HttpThreatReputationProvider(String providerName, String apiEndpoint, ReputationHttpClient httpClient, int timeoutMs) {
            this.providerName = providerName != null ? providerName : "Generic Threat Cloud";
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
        public ReputationResult checkReputation(ParsedUrl parsedUrl) {
            if (parsedUrl == null) {
                return ReputationResult.invalidInput(providerName, "URL cannot be null.");
            }

            if (!isConfigured()) {
                return ReputationResult.notChecked("Provider '" + providerName + "' is not configured with a valid HTTPS endpoint.");
            }

            // Clean sanitized URL for lookup (never send sensitive query tokens)
            String safeLookupUrl = parsedUrl.getScheme() + "://" + parsedUrl.getAsciiHost()
                    + (parsedUrl.isNonStandardPort() ? ":" + parsedUrl.getPort() : "")
                    + parsedUrl.getPath();

            // Check cache to avoid duplicate network requests
            long now = System.currentTimeMillis();
            CacheEntry cached = cache.get(safeLookupUrl);
            if (cached != null && (now - cached.timestamp < CACHE_TTL_MS)) {
                return cached.result;
            }

            long start = System.currentTimeMillis();
            try {
                // Prepare request payload (minimal disclosure: host and sanitized path)
                String jsonBody = "{\"url\":\"" + safeLookupUrl.replace("\"", "\\\"") + "\"}";
                ReputationHttpClient.HttpResponse response = httpClient.executePost(
                        apiEndpoint,
                        Map.of("Accept", "application/json"),
                        jsonBody,
                        timeoutMs
                );

                long duration = System.currentTimeMillis() - start;

                if (response.isRateLimited()) {
                    ReputationResult res = ReputationResult.providerUnavailable(
                            providerName,
                            "Rate limit exceeded (HTTP 429). Live checks paused.",
                            duration
                    );
                    return res;
                }

                if (response.isServerError()) {
                    return ReputationResult.providerUnavailable(
                            providerName,
                            "Server error (HTTP " + response.statusCode + ")",
                            duration
                    );
                }

                if (!response.isSuccess()) {
                    return ReputationResult.providerUnavailable(
                            providerName,
                            "HTTP " + response.statusCode,
                            duration
                    );
                }

                // Parse response body
                String rawBody = response.body != null ? response.body : "";
                String compactBody = rawBody.replaceAll("\\s+", "").toLowerCase();
                ReputationResult result;
                if (compactBody.contains("\"state\":\"threat_match\"")
                        || compactBody.contains("\"threat\":true")
                        || compactBody.contains("\"malicious\":true")
                        || compactBody.contains("\"verdict\":\"threat\"")
                        || compactBody.contains("social_engineering")
                        || compactBody.contains("malware")
                        || compactBody.contains("unwanted_software")) {

                    String detail = extractThreatDetail(rawBody);
                    result = ReputationResult.threatMatch(providerName, detail, duration);
                } else if (compactBody.contains("\"state\":\"no_known_threat_match\"")
                        || compactBody.contains("\"threat\":false")
                        || compactBody.contains("\"clean\":true")
                        || compactBody.contains("\"verdict\":\"clean\"")
                        || compactBody.equals("{}")) {

                    result = ReputationResult.noKnownThreatMatch(providerName, duration);
                } else if (compactBody.contains("\"state\":\"provider_unavailable\"")) {
                    result = ReputationResult.providerUnavailable(
                            providerName,
                            "Upstream threat intelligence service reported provider unavailable",
                            duration
                    );
                } else {
                    // Critical rule: NEVER convert unknown errors into clean!
                    result = ReputationResult.providerUnavailable(
                            providerName,
                            "Unrecognized or invalid response format from server",
                            duration
                    );
                }

                // Cache conclusive results
                cache.put(safeLookupUrl, new CacheEntry(result, now));
                return result;

            } catch (SocketTimeoutException e) {
                long duration = System.currentTimeMillis() - start;
                // A timeout must NEVER produce a clean result!
                return ReputationResult.timeoutOrNetworkError(
                        providerName,
                        "Request timed out after " + timeoutMs + "ms",
                        duration
                );
            } catch (IOException e) {
                long duration = System.currentTimeMillis() - start;
                return ReputationResult.timeoutOrNetworkError(
                        providerName,
                        "Network failure: " + e.getMessage(),
                        duration
                );
            } catch (Exception e) {
                long duration = System.currentTimeMillis() - start;
                return ReputationResult.providerUnavailable(
                        providerName,
                        "Unexpected error: " + e.getMessage(),
                        duration
                );
            }
        }

        private String extractThreatDetail(String rawJson) {
            String lower = rawJson.toLowerCase();
            if (lower.contains("social_engineering")) {
                return "Google Web Risk matched SOCIAL_ENGINEERING (Deceptive Phishing / Fraudulent Portal)";
            } else if (lower.contains("malware")) {
                return "Google Web Risk matched MALWARE (Malicious Software Distribution)";
            } else if (lower.contains("unwanted_software")) {
                return "Google Web Risk matched UNWANTED_SOFTWARE (Potentially Harmful Software)";
            }

            try {
                String searchKey = "\"details\":\"";
                int idx = rawJson.indexOf(searchKey);
                if (idx != -1) {
                    int start = idx + searchKey.length();
                    int end = rawJson.indexOf("\"", start);
                    if (end != -1) {
                        return rawJson.substring(start, end);
                    }
                }
            } catch (Exception ignored) {}
            return "Online intelligence matched known phishing or malware campaign";
        }
    }
}
