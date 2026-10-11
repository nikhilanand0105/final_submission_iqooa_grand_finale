package dev.guardianai.url;

import dev.guardianai.ai.ExplainableAiPromptBuilder;
import dev.guardianai.ai.GemmaModelBridge;
import dev.guardianai.model.ScanVerdict;
import dev.guardianai.model.ThreatSeverity;
import dev.guardianai.shield.network.PhishingUrlScanner;
import dev.guardianai.shield.network.url.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class UrlSafetyPipelineTest {

    private LocalUrlAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new LocalUrlAnalyzer();
    }

    // ==========================================
    // 1. Parsing & Normalisation Tests
    // ==========================================

    @Test
    @DisplayName("Should normalise scheme, host casing, whitespace and default ports")
    void testNormalisationAndWhitespace() throws Exception {
        ParsedUrl parsed = UrlParser.parse("   HTTP://Example.COM:80/path/to/page?q=1   ");
        assertEquals("http", parsed.getScheme());
        assertEquals("example.com", parsed.getAsciiHost());
        assertEquals(80, parsed.getPort());
        assertFalse(parsed.isNonStandardPort(), "Port 80 is standard for HTTP");
        assertEquals("/path/to/page", parsed.getPath());
        assertEquals("q=1", parsed.getQuery());
        assertEquals("http://example.com/path/to/page?q=1", parsed.getNormalizedUrl());
    }

    @Test
    @DisplayName("Should parse custom non-standard port")
    void testNonStandardPortParsing() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://safe-service.org:8443/api");
        assertEquals("safe-service.org", parsed.getAsciiHost());
        assertEquals(8443, parsed.getPort());
        assertTrue(parsed.isNonStandardPort());
        assertEquals("https://safe-service.org:8443/api", parsed.getNormalizedUrl());
    }

    @Test
    @DisplayName("Should automatically assume https when scheme is omitted without crashing")
    void testOmittedScheme() throws Exception {
        ParsedUrl parsed = UrlParser.parse("bank-portal.co.in/verify");
        assertEquals("https", parsed.getScheme());
        assertTrue(parsed.isSchemeImplicitlyAdded());
        assertEquals("bank-portal.co.in", parsed.getAsciiHost());
        assertEquals("/verify", parsed.getPath());
    }

    // ==========================================
    // 2. Invalid Input & Boundary Case Tests
    // ==========================================

    @Test
    @DisplayName("Should reject null, empty, and whitespace-only inputs with informative error")
    void testRejectEmptyInput() {
        UrlParseException ex1 = assertThrows(UrlParseException.class, () -> UrlParser.parse(null));
        assertEquals(UrlParseException.ErrorCode.EMPTY_INPUT, ex1.getErrorCode());

        UrlParseException ex2 = assertThrows(UrlParseException.class, () -> UrlParser.parse("   "));
        assertEquals(UrlParseException.ErrorCode.EMPTY_INPUT, ex2.getErrorCode());
        assertTrue(ex2.getMessage().contains("empty or blank"));
    }

    @Test
    @DisplayName("Should reject overly long URLs exceeding 4096 characters without crashing")
    void testRejectOverlyLongInput() {
        String longUrl = "https://example.com/" + "a".repeat(4100);
        UrlParseException ex = assertThrows(UrlParseException.class, () -> UrlParser.parse(longUrl));
        assertEquals(UrlParseException.ErrorCode.INPUT_TOO_LONG, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("maximum supported length"));
    }

    @Test
    @DisplayName("Should reject dangerous schemes like javascript:, data:, and file:")
    void testRejectDangerousSchemes() {
        UrlParseException ex1 = assertThrows(UrlParseException.class, () -> UrlParser.parse("javascript:alert(1)"));
        assertEquals(UrlParseException.ErrorCode.DANGEROUS_SCHEME, ex1.getErrorCode());

        UrlParseException ex2 = assertThrows(UrlParseException.class, () -> UrlParser.parse("data:text/html,<script>"));
        assertEquals(UrlParseException.ErrorCode.DANGEROUS_SCHEME, ex2.getErrorCode());

        UrlParseException ex3 = assertThrows(UrlParseException.class, () -> UrlParser.parse("file:///etc/passwd"));
        assertEquals(UrlParseException.ErrorCode.DANGEROUS_SCHEME, ex3.getErrorCode());
    }

    @Test
    @DisplayName("Should reject invalid port numbers outside 1-65535")
    void testRejectInvalidPorts() {
        UrlParseException ex1 = assertThrows(UrlParseException.class, () -> UrlParser.parse("http://example.com:99999/"));
        assertEquals(UrlParseException.ErrorCode.INVALID_PORT, ex1.getErrorCode());
        assertTrue(ex1.getMessage().contains("99999"));

        UrlParseException ex2 = assertThrows(UrlParseException.class, () -> UrlParser.parse("http://example.com:abc/"));
        assertEquals(UrlParseException.ErrorCode.INVALID_PORT, ex2.getErrorCode());
    }

    // ==========================================
    // 3. Internationalised Domains & Punycode Tests
    // ==========================================

    @Test
    @DisplayName("Should resolve IDN to Punycode and detect Cyrillic lookalike homoglyphs")
    void testInternationalisedDomainAndHomoglyphs() throws Exception {
        // "sbi" with Cyrillic 'а' or 'о'
        // Using "раураl.com" where 'р' (\u0440) and 'а' (\u0430) are Cyrillic
        String homoglyphInput = "https://\u0440\u0430\u0443\u0440\u0430l.com/signin";
        ParsedUrl parsed = UrlParser.parse(homoglyphInput);

        assertTrue(parsed.isPunycode() || parsed.containsNonAscii());
        assertTrue(parsed.getAsciiHost().startsWith("xn--"), "Punycode host starts with xn--");

        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        boolean hasHomoglyphIndicator = indicators.stream().anyMatch(i -> i.getId().equals("IND_HOMOGLYPH_LOOKALIKE") || i.getId().equals("IND_PUNYCODE_DOMAIN"));
        assertTrue(hasHomoglyphIndicator, "Should detect homoglyph lookalike characters");

        ScanVerdict verdict = analyzer.determineVerdict(indicators);
        assertTrue(verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK);
    }

    // ==========================================
    // 4. Structural Indicator Tests
    // ==========================================

    @Test
    @DisplayName("Should detect raw IPv4, IPv6, and obfuscated numeric IP hosts")
    void testNumericIpHosts() throws Exception {
        // 1. Standard dotted decimal IPv4
        ParsedUrl ipUrl = UrlParser.parse("http://192.168.1.100/bank/login");
        assertTrue(ipUrl.isIpAddress());
        List<UrlIndicator> ind1 = analyzer.analyze(ipUrl);
        assertTrue(ind1.stream().anyMatch(i -> i.getId().equals("IND_NUMERIC_IP_HOST")));
        assertEquals(ScanVerdict.HIGH_RISK, analyzer.determineVerdict(ind1));

        // 2. Obfuscated dword integer IP (2130706433 = 127.0.0.1)
        ParsedUrl dwordUrl = UrlParser.parse("http://2130706433/login");
        assertTrue(dwordUrl.isIpAddress());
        List<UrlIndicator> ind2 = analyzer.analyze(dwordUrl);
        assertTrue(ind2.stream().anyMatch(i -> i.getId().equals("IND_NUMERIC_IP_HOST")));
        assertEquals(ThreatSeverity.CRITICAL, ind2.get(0).getSeverity());

        // 3. IPv6 literal
        ParsedUrl ipv6Url = UrlParser.parse("http://[2001:db8::1]:8080/portal");
        assertTrue(ipv6Url.isIpAddress());
        List<UrlIndicator> ind3 = analyzer.analyze(ipv6Url);
        assertTrue(ind3.stream().anyMatch(i -> i.getId().equals("IND_NUMERIC_IP_HOST")));
    }

    @Test
    @DisplayName("Should detect user-info tricks using '@' delimiter")
    void testUserInfoTrick() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://onlinesbi.sbi@scam-attacker.net/login");
        assertTrue(parsed.hasUserInfo());
        assertEquals("onlinesbi.sbi", parsed.getUserInfo());
        assertEquals("scam-attacker.net", parsed.getAsciiHost());

        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.stream().anyMatch(i -> i.getId().equals("IND_USER_INFO_TRICK")));
        assertEquals(ScanVerdict.KNOWN_MALICIOUS, analyzer.determineVerdict(indicators));
    }

    @Test
    @DisplayName("Should detect deceptive subdomain brand impersonation")
    void testDeceptiveSubdomains() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://sbi.co.in.customer-verification-portal.com/update");
        assertEquals("sbi.co.in.customer-verification-portal.com", parsed.getAsciiHost());
        assertEquals("customer-verification-portal.com", parsed.getRegistrableDomain());

        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.stream().anyMatch(i -> i.getId().equals("IND_DECEPTIVE_BRAND_HOST")));
        assertEquals(ScanVerdict.KNOWN_MALICIOUS, analyzer.determineVerdict(indicators));
    }

    @Test
    @DisplayName("Should detect high-risk throwaway TLDs (.top, .xyz, .buzz)")
    void testHighRiskTlds() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://quick-claim-rewards.top/claim");
        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.stream().anyMatch(i -> i.getId().equals("IND_HIGH_RISK_TLD")));
    }

    @Test
    @DisplayName("Should detect unencrypted HTTP transport on sensitive credential endpoints")
    void testInsecureTransportOnSensitivePaths() throws Exception {
        ParsedUrl parsed = UrlParser.parse("http://example-merchant.com/login?redirect=account");
        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.stream().anyMatch(i -> i.getId().equals("IND_INSECURE_HTTP_CREDENTIAL")));
        assertEquals(ThreatSeverity.HIGH, indicators.stream().filter(i -> i.getId().equals("IND_INSECURE_HTTP_CREDENTIAL")).findFirst().get().getSeverity());
    }

    @Test
    @DisplayName("Should detect urgency and KYC verification lures")
    void testUrgencyLures() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://utility-notice.org/electricity-disconnection/pay-bill");
        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.stream().anyMatch(i -> i.getId().equals("IND_URGENCY_LURE")));
    }

    @Test
    @DisplayName("Legitimate official domains evaluate as NO_KNOWN_THREAT_DETECTED")
    void testCleanOfficialDomain() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://onlinesbi.sbi");
        List<UrlIndicator> indicators = analyzer.analyze(parsed);
        assertTrue(indicators.isEmpty(), "Official trusted domain should have no suspicious structural indicators");
        assertEquals(ScanVerdict.NO_KNOWN_THREAT_DETECTED, analyzer.determineVerdict(indicators));
    }

    // ==========================================
    // 5. Threat-Reputation Provider & Error Tests
    // ==========================================

    @Test
    @DisplayName("Default unconfigured provider returns explicit NOT_CHECKED state")
    void testUnconfiguredProviderReturnsNotChecked() throws Exception {
        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, new ThreatReputationProvider.NoOpReputationProvider());
        UrlAnalysisResult result = pipeline.analyze("https://example.com");

        assertEquals(ReputationState.NOT_CHECKED, result.getReputationResult().getState());
        assertTrue(result.getReputationResult().getStatusMessage().contains("not configured"));
        assertTrue(result.getUncertaintyLimitations().contains("NOT checked"));
    }

    @Test
    @DisplayName("Online threat match elevates verdict to KNOWN_MALICIOUS")
    void testProviderThreatMatch() throws Exception {
        ReputationHttpClient mockClient = new ReputationHttpClient() {
            @Override
            public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                return new HttpResponse(200, "{\"threat\":true,\"category\":\"phishing\"}", Map.of());
            }

            @Override
            public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                return new HttpResponse(200, "{}", Map.of());
            }
        };

        ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                "CloudThreatDB",
                "https://threat.guardianai.dev/v1/check",
                mockClient,
                3000
        );

        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, provider);
        UrlAnalysisResult result = pipeline.analyze("https://clean-looking-domain.org/page");

        assertEquals(ReputationState.THREAT_MATCH, result.getReputationResult().getState());
        assertEquals(ScanVerdict.KNOWN_MALICIOUS, result.getCombinedVerdict(), "Threat match must force KNOWN_MALICIOUS");
        assertEquals(ThreatSeverity.CRITICAL, result.getOverallSeverity());
    }

    @Test
    @DisplayName("Online clean response returns NO_KNOWN_THREAT_MATCH")
    void testProviderCleanResponse() throws Exception {
        ReputationHttpClient mockClient = new ReputationHttpClient() {
            @Override
            public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                return new HttpResponse(200, "{\"clean\":true}", Map.of());
            }

            @Override
            public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                return new HttpResponse(200, "{}", Map.of());
            }
        };

        ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                "CloudThreatDB",
                "https://threat.guardianai.dev/v1/check",
                mockClient,
                3000
        );

        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, provider);
        UrlAnalysisResult result = pipeline.analyze("https://example.com");

        assertEquals(ReputationState.NO_KNOWN_THREAT_MATCH, result.getReputationResult().getState());
    }

    @Test
    @DisplayName("Provider server errors (500/503) and rate limits (429) return PROVIDER_UNAVAILABLE")
    void testProviderUnavailableAndRateLimits() throws Exception {
        // 503 Service Unavailable
        ReputationHttpClient mock503 = new ReputationHttpClient() {
            @Override
            public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                return new HttpResponse(503, "Service Unavailable", Map.of());
            }

            @Override
            public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                return new HttpResponse(503, "", Map.of());
            }
        };

        ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                "CloudThreatDB",
                "https://threat.guardianai.dev/v1/check",
                mock503,
                3000
        );

        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, provider);
        UrlAnalysisResult result = pipeline.analyze("https://example.com");

        assertEquals(ReputationState.PROVIDER_UNAVAILABLE, result.getReputationResult().getState());
        assertTrue(result.getReputationResult().getStatusMessage().contains("503"));
    }

    @Test
    @DisplayName("Timeout and network failure return TIMEOUT_NETWORK_ERROR and must NEVER produce a clean result")
    void testTimeoutNeverProducesCleanResult() throws Exception {
        ReputationHttpClient timingOutClient = new ReputationHttpClient() {
            @Override
            public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) throws IOException {
                throw new SocketTimeoutException("Read timed out");
            }

            @Override
            public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) throws IOException {
                throw new SocketTimeoutException("Read timed out");
            }
        };

        ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                "CloudThreatDB",
                "https://threat.guardianai.dev/v1/check",
                timingOutClient,
                2000
        );

        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, provider);

        // Analyze a syntactically normal URL
        UrlAnalysisResult result = pipeline.analyze("https://unknown-service.com");

        assertEquals(ReputationState.TIMEOUT_NETWORK_ERROR, result.getReputationResult().getState());
        // Must NEVER produce a clean result! A clean local verdict with timeout elevates to CAUTION.
        assertNotEquals(ScanVerdict.NO_KNOWN_THREAT_DETECTED, result.getCombinedVerdict(), "Timeout must never produce NO_KNOWN_THREAT_DETECTED");
        assertEquals(ScanVerdict.CAUTION, result.getCombinedVerdict());
        assertTrue(result.getPlainAdvice().contains("timeout"));
    }

    @Test
    @DisplayName("Duplicate lookups within TTL reuse cached result without sending duplicate requests")
    void testDuplicateRequestDeduplication() throws Exception {
        AtomicInteger requestCounter = new AtomicInteger(0);
        ReputationHttpClient countingClient = new ReputationHttpClient() {
            @Override
            public HttpResponse executePost(String endpointUrl, Map<String, String> headers, String jsonBody, int timeoutMs) {
                requestCounter.incrementAndGet();
                return new HttpResponse(200, "{\"clean\":true}", Map.of());
            }

            @Override
            public HttpResponse executeGet(String endpointUrl, Map<String, String> headers, int timeoutMs) {
                return new HttpResponse(200, "{}", Map.of());
            }
        };

        ThreatReputationProvider provider = new ThreatReputationProvider.HttpThreatReputationProvider(
                "CloudThreatDB",
                "https://threat.guardianai.dev/v1/check",
                countingClient,
                3000
        );

        UrlSafetyPipeline pipeline = new UrlSafetyPipeline(analyzer, provider);

        pipeline.analyze("https://example.com/login");
        pipeline.analyze("https://example.com/login");
        pipeline.analyze("https://example.com/login");

        assertEquals(1, requestCounter.get(), "Duplicate requests must be cached within TTL");
    }

    // ==========================================
    // 6. Privacy & Sensitive Query Sanitization
    // ==========================================

    @Test
    @DisplayName("UrlSanitizer strips user credentials and sensitive tokens from log URLs")
    void testUrlSanitizationForLogs() throws Exception {
        ParsedUrl parsed = UrlParser.parse("https://admin:secretPass@portal.com/auth?token=eyJhbGciOiJIUzI1Ni&user=nikhil&code=948210");
        String sanitized = UrlSanitizer.sanitizeForLog(parsed);

        assertFalse(sanitized.contains("secretPass"), "Password must be stripped");
        assertFalse(sanitized.contains("eyJhbGciOiJIUzI1Ni"), "Token value must be redacted");
        assertFalse(sanitized.contains("948210"), "Code value must be redacted");
        assertTrue(sanitized.contains("token=[REDACTED]"));
        assertTrue(sanitized.contains("code=[REDACTED]"));
        assertTrue(sanitized.contains("portal.com/auth"));
    }

    // ==========================================
    // 7. Gemma Model Integration & Prompt Tests
    // ==========================================

    @Test
    @DisplayName("Gemma prompt builder produces well-formed turn-based prompts for URLs")
    void testGemmaPromptBuilder() throws Exception {
        UrlSafetyPipeline pipeline = new UrlSafetyPipeline();
        UrlAnalysisResult result = pipeline.analyze("http://sbi-kyc-verify.top/login");

        String prompt = ExplainableAiPromptBuilder.buildUrlExplanationPrompt(result, true);
        assertTrue(prompt.contains("<start_of_turn>user"));
        assertTrue(prompt.contains("<end_of_turn>"));
        assertTrue(prompt.contains("<start_of_turn>model"));
        assertTrue(prompt.contains("Senior citizen in India"));
        assertTrue(prompt.contains("sbi-kyc-verify.top"));
        assertTrue(prompt.contains("1930"));
    }

    @Test
    @DisplayName("GemmaModelBridge detects and verifies gemma-4-E2B-it.litertlm header")
    void testGemmaModelBridgeIntegrity() {
        File modelFile = new File("d:/iqoo-gf/gemma-4-E2B-it.litertlm");
        if (modelFile.exists()) {
            GemmaModelBridge bridge = new GemmaModelBridge(modelFile);
            assertEquals(GemmaModelBridge.ModelStatus.READY_LITERTLM, bridge.getStatus(), "Model file header must be valid LITERTLM");
            assertTrue(bridge.isModelReady());
        }
    }
}
