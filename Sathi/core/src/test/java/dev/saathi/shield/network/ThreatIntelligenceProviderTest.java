package dev.saathi.shield.network;

import dev.saathi.engine.SaathiApkIntelligence;
import dev.saathi.model.ApkAnalysisReport;
import dev.saathi.model.ScanVerdict;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;
import dev.saathi.shield.network.hash.ApkHashReputationProvider;
import dev.saathi.shield.network.hash.HashReputationResult;
import dev.saathi.shield.network.url.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 8 Automated Test Suite: Real Threat-Intelligence Providers.
 * <p>
 * Tests mocked provider clients for:
 * - Successful threat matches
 * - No known threat matches
 * - Timeouts and network connection errors
 * - Invalid responses and malformed payloads
 * - Quotas and rate limiting (429)
 * - Authentication failures (401/403)
 * - Input validation & privacy boundary enforcement
 * - Unconfigured fallback behaviors
 */
public class ThreatIntelligenceProviderTest {

    private static final String TEST_URL = "https://example-phishing-portal.com/login?token=secret123&action=verify";
    private static final String TEST_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // =========================================================================
    // 1. URL THREAT REPUTATION (Google Web Risk / Cloud Threat Intelligence)
    // =========================================================================
    @Nested
    @DisplayName("URL Threat Reputation Provider (Google Web Risk)")
    class UrlThreatReputationTests {

        @Test
        @DisplayName("1.1 Web Risk Social Engineering match returns THREAT_MATCH with proper category")
        void testWebRiskSocialEngineeringMatch() throws Exception {
            ReputationHttpClient mockClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(200, "{\"threat\":{\"threatTypes\":[\"SOCIAL_ENGINEERING\"]}}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    mockClient,
                    3000
            );

            ParsedUrl parsed = UrlParser.parse(TEST_URL);
            ReputationResult result = provider.checkReputation(parsed);

            assertEquals(ReputationState.THREAT_MATCH, result.getState());
            assertEquals("Google Web Risk", result.getProviderName());
            assertTrue(result.getThreatDetails().contains("SOCIAL_ENGINEERING"));
            assertTrue(result.getStatusMessage().contains("Threat match confirmed"));
        }

        @Test
        @DisplayName("1.2 Web Risk empty JSON response returns NO_KNOWN_THREAT_MATCH")
        void testWebRiskEmptyJsonCleanResponse() throws Exception {
            ReputationHttpClient mockClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    mockClient,
                    3000
            );

            ParsedUrl parsed = UrlParser.parse("https://safe-banking.gov.in/portal");
            ReputationResult result = provider.checkReputation(parsed);

            assertEquals(ReputationState.NO_KNOWN_THREAT_MATCH, result.getState());
            assertEquals("Google Web Risk", result.getProviderName());
            assertTrue(result.getStatusMessage().contains("No known threat match"));
        }

        @Test
        @DisplayName("1.3 Network timeout produces TIMEOUT_NETWORK_ERROR and elevates verdict to CAUTION")
        void testWebRiskTimeoutHandling() throws Exception {
            ReputationHttpClient timeoutClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) throws IOException {
                    throw new SocketTimeoutException("Read timed out after 3000ms");
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) throws IOException {
                    throw new SocketTimeoutException("Read timed out");
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    timeoutClient,
                    3000
            );

            UrlSafetyPipeline pipeline = new UrlSafetyPipeline(new LocalUrlAnalyzer(), provider);
            UrlAnalysisResult analysis = pipeline.analyze("https://clean-syntax-site.org/index.html");

            assertEquals(ReputationState.TIMEOUT_NETWORK_ERROR, analysis.getReputationResult().getState());
            // Never convert timeout to clean!
            assertNotEquals(ScanVerdict.NO_KNOWN_THREAT_DETECTED, analysis.getCombinedVerdict());
            assertEquals(ScanVerdict.CAUTION, analysis.getCombinedVerdict());
            assertTrue(analysis.getPlainAdvice().contains("timeout"));
        }

        @Test
        @DisplayName("1.4 HTTP 429 quota/rate limit returns PROVIDER_UNAVAILABLE")
        void testWebRiskRateLimitHandling() throws Exception {
            ReputationHttpClient rateLimitedClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(429, "{\"error\":{\"code\":429,\"message\":\"Quota exceeded\"}}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(429, "{}", Map.of());
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    rateLimitedClient,
                    3000
            );

            ParsedUrl parsed = UrlParser.parse(TEST_URL);
            ReputationResult result = provider.checkReputation(parsed);

            assertEquals(ReputationState.PROVIDER_UNAVAILABLE, result.getState());
            assertTrue(result.getStatusMessage().contains("Rate limit exceeded") || result.getStatusMessage().contains("429"));
        }

        @Test
        @DisplayName("1.5 HTTP 401/403 authentication failure returns PROVIDER_UNAVAILABLE")
        void testWebRiskAuthFailureHandling() throws Exception {
            ReputationHttpClient authFailClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(403, "{\"error\":{\"code\":403,\"message\":\"API key invalid\"}}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(403, "{}", Map.of());
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    authFailClient,
                    3000
            );

            ParsedUrl parsed = UrlParser.parse(TEST_URL);
            ReputationResult result = provider.checkReputation(parsed);

            assertEquals(ReputationState.PROVIDER_UNAVAILABLE, result.getState());
            assertTrue(result.getStatusMessage().contains("403"));
        }

        @Test
        @DisplayName("1.6 Privacy Guarantee: Query parameters are stripped prior to remote lookup")
        void testPrivacyQueryParamStripping() throws Exception {
            AtomicReference<String> transmittedPayload = new AtomicReference<>();
            ReputationHttpClient payloadInspector = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    transmittedPayload.set(jsonBody);
                    return new HttpResponse(200, "{}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                    "Google Web Risk",
                    "https://webrisk.saathi.internal/checkUrl",
                    payloadInspector,
                    3000
            );

            ParsedUrl parsed = UrlParser.parse("https://bank.com/transfer?token=SUPER_SECRET_123&user=9810123456");
            provider.checkReputation(parsed);

            assertNotNull(transmittedPayload.get());
            assertFalse(transmittedPayload.get().contains("SUPER_SECRET_123"), "Sensitive token must NOT be transmitted");
            assertFalse(transmittedPayload.get().contains("9810123456"), "User phone must NOT be transmitted");
            assertTrue(transmittedPayload.get().contains("https://bank.com/transfer"));
        }

        @Test
        @DisplayName("1.7 Unconfigured provider safely returns NOT_CHECKED without throwing")
        void testUnconfiguredProviderFallback() throws Exception {
            ThreatReputationProvider provider = new ThreatReputationProvider.NoOpReputationProvider();
            ParsedUrl parsed = UrlParser.parse("https://example.com");
            ReputationResult result = provider.checkReputation(parsed);

            assertEquals(ReputationState.NOT_CHECKED, result.getState());
            assertFalse(result.isLiveCheckAttempted());
        }
    }

    // =========================================================================
    // 2. APK HASH REPUTATION (VirusTotal Intelligence / Cloud Threat Database)
    // =========================================================================
    @Nested
    @DisplayName("APK Hash Reputation Provider (VirusTotal Intelligence)")
    class ApkHashReputationTests {

        @Test
        @DisplayName("2.1 Malicious hash match returns THREAT_MATCH with vendor counts & family")
        void testHashMatchMaliciousVerdicts() {
            ReputationHttpClient mockClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    String vtResponse = "{\n" +
                            "  \"state\": \"threat_match\",\n" +
                            "  \"malicious\": 28,\n" +
                            "  \"total\": 72,\n" +
                            "  \"threatfamily\": \"Trojan-Banker.AndroidOS.Agent\",\n" +
                            "  \"provider\": \"VirusTotal Threat Cloud\"\n" +
                            "}";
                    return new HttpResponse(200, vtResponse, Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    mockClient,
                    3000
            );

            HashReputationResult result = provider.checkHashReputation(TEST_SHA256);

            assertEquals(ReputationState.THREAT_MATCH, result.getState());
            assertEquals(28, result.getMaliciousDetections());
            assertEquals(72, result.getTotalEngines());
            assertEquals("Trojan-Banker.AndroidOS.Agent", result.getThreatDetails());
            assertTrue(result.getStatusMessage().contains("28/72"));
        }

        @Test
        @DisplayName("2.2 Clean hash (0 detections) returns NO_KNOWN_THREAT_MATCH")
        void testCleanHashZeroDetections() {
            ReputationHttpClient mockClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    String cleanResponse = "{\n" +
                            "  \"state\": \"no_known_threat_match\",\n" +
                            "  \"clean\": true,\n" +
                            "  \"malicious\": 0,\n" +
                            "  \"total\": 72,\n" +
                            "  \"provider\": \"VirusTotal Threat Cloud\"\n" +
                            "}";
                    return new HttpResponse(200, cleanResponse, Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    mockClient,
                    3000
            );

            HashReputationResult result = provider.checkHashReputation(TEST_SHA256);

            assertEquals(ReputationState.NO_KNOWN_THREAT_MATCH, result.getState());
            assertEquals(0, result.getMaliciousDetections());
            assertTrue(result.getStatusMessage().contains("No known threat match"));
        }

        @Test
        @DisplayName("2.3 Timeout returns TIMEOUT_NETWORK_ERROR")
        void testHashTimeoutHandling() {
            ReputationHttpClient timeoutClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) throws IOException {
                    throw new SocketTimeoutException("Read timed out");
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) throws IOException {
                    throw new SocketTimeoutException("Read timed out");
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    timeoutClient,
                    3000
            );

            HashReputationResult result = provider.checkHashReputation(TEST_SHA256);

            assertEquals(ReputationState.TIMEOUT_NETWORK_ERROR, result.getState());
            assertTrue(result.getStatusMessage().contains("timeout") || result.getStatusMessage().contains("Network"));
        }

        @Test
        @DisplayName("2.4 Rate limit (429) returns PROVIDER_UNAVAILABLE")
        void testHashRateLimitHandling() {
            ReputationHttpClient rateLimitedClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(429, "{\"message\":\"Rate limit exceeded\"}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(429, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    rateLimitedClient,
                    3000
            );

            HashReputationResult result = provider.checkHashReputation(TEST_SHA256);

            assertEquals(ReputationState.PROVIDER_UNAVAILABLE, result.getState());
            assertTrue(result.getStatusMessage().contains("429"));
        }

        @Test
        @DisplayName("2.5 Invalid input (non-64 hex char) is rejected immediately without network call")
        void testInvalidHashInputRejection() {
            AtomicInteger callCount = new AtomicInteger(0);
            ReputationHttpClient counterClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    callCount.incrementAndGet();
                    return new HttpResponse(200, "{}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    counterClient,
                    3000
            );

            HashReputationResult res1 = provider.checkHashReputation("not-a-hash");
            assertEquals(ReputationState.INVALID_INPUT, res1.getState());
            assertEquals(0, callCount.get());

            HashReputationResult res2 = provider.checkHashReputation("12345");
            assertEquals(ReputationState.INVALID_INPUT, res2.getState());
            assertEquals(0, callCount.get());

            HashReputationResult res3 = provider.checkHashReputation(null);
            assertEquals(ReputationState.INVALID_INPUT, res3.getState());
            assertEquals(0, callCount.get());
        }

        @Test
        @DisplayName("2.6 Cache deduplication reuses result within TTL without sending duplicate HTTP requests")
        void testHashCacheDeduplication() {
            AtomicInteger networkCalls = new AtomicInteger(0);
            ReputationHttpClient countingClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    networkCalls.incrementAndGet();
                    return new HttpResponse(200, "{\"clean\":true}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    countingClient,
                    3000
            );

            HashReputationResult r1 = provider.checkHashReputation(TEST_SHA256);
            assertEquals(1, networkCalls.get());
            assertEquals(ReputationState.NO_KNOWN_THREAT_MATCH, r1.getState());

            HashReputationResult r2 = provider.checkHashReputation(TEST_SHA256);
            assertEquals(1, networkCalls.get(), "Second call within TTL must reuse cached result");
            assertEquals(ReputationState.NO_KNOWN_THREAT_MATCH, r2.getState());
        }

        @Test
        @DisplayName("2.7 Privacy Guarantee: Strictly only the hash is transmitted in JSON payload")
        void testPrivacyPayloadOnlyHash() {
            AtomicReference<String> transmittedBody = new AtomicReference<>();
            ReputationHttpClient inspector = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    transmittedBody.set(jsonBody);
                    return new HttpResponse(200, "{\"clean\":true}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider provider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    inspector,
                    3000
            );

            provider.checkHashReputation(TEST_SHA256);
            assertEquals("{\"sha256\":\"" + TEST_SHA256 + "\"}", transmittedBody.get());
        }
    }

    // =========================================================================
    // 3. END-TO-END ENGINE INTEGRATION
    // =========================================================================
    @Nested
    @DisplayName("APK Intelligence Engine Integration with Hash Provider")
    class ApkEngineIntegrationTests {

        @Test
        @DisplayName("3.1 SaathiApkIntelligence integrates hash reputation match into report indicators")
        void testApkEngineWithHashMatch() throws Exception {
            // Create a small valid minimal zip representing an APK
            File tempApk = File.createTempFile("test_sample_", ".apk");
            tempApk.deleteOnExit();

            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempApk))) {
                zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
                zos.write(new byte[]{0x03, 0x00, 0x08, 0x00}); // minimal binary header
                zos.closeEntry();
            }

            ReputationHttpClient matchClient = new ReputationHttpClient() {
                @Override
                public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                    return new HttpResponse(200, "{\"state\":\"threat_match\",\"malicious\":35,\"total\":72,\"threatfamily\":\"Spyware.Banker\"}", Map.of());
                }

                @Override
                public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                    return new HttpResponse(200, "{}", Map.of());
                }
            };

            ApkHashReputationProvider hashProvider = new ApkHashReputationProvider.HttpApkHashReputationProvider(
                    "VirusTotal Threat Cloud",
                    "https://hashintel.saathi.internal/checkHash",
                    matchClient,
                    3000
            );

            SaathiApkIntelligence engine = new SaathiApkIntelligence(null, hashProvider);
            ApkAnalysisReport report = engine.analyzeApk(tempApk);

            assertNotNull(report.getHashReputationResult());
            assertEquals(ReputationState.THREAT_MATCH, report.getHashReputationResult().getState());
            assertEquals(35, report.getHashReputationResult().getMaliciousDetections());

            // Threat indicator must be synthesized
            boolean foundIndicator = false;
            for (ThreatIndicator ti : report.getIndicators()) {
                if ("ONLINE_THREAT_INTEL_HASH_MATCH".equals(ti.getId())) {
                    foundIndicator = true;
                    assertEquals(ThreatSeverity.CRITICAL, ti.getSeverity());
                    assertTrue(ti.getDescription().contains("VirusTotal Threat Cloud"));
                    break;
                }
            }
            assertTrue(foundIndicator, "ONLINE_THREAT_INTEL_HASH_MATCH indicator must be present in report");
            assertEquals(ScanVerdict.KNOWN_MALICIOUS, report.getVerdict());
        }

        @Test
        @DisplayName("3.2 SaathiApkIntelligence with NoOpHashReputationProvider preserves NOT_CHECKED state")
        void testApkEngineWithNoOpHashProvider() throws Exception {
            File tempApk = File.createTempFile("test_clean_", ".apk");
            tempApk.deleteOnExit();

            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempApk))) {
                zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
                zos.write(new byte[]{0x03, 0x00, 0x08, 0x00});
                zos.closeEntry();
            }

            SaathiApkIntelligence engine = new SaathiApkIntelligence();
            ApkAnalysisReport report = engine.analyzeApk(tempApk);

            assertNotNull(report.getHashReputationResult());
            assertEquals(ReputationState.NOT_CHECKED, report.getHashReputationResult().getState());
        }
    }
}
