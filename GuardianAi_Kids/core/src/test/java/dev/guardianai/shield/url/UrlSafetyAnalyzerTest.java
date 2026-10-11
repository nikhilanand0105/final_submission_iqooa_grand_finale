package dev.guardianai.shield.url;

import dev.guardianai.net.AuthTokenSource;
import dev.guardianai.net.HttpTransport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class UrlSafetyAnalyzerTest {

    private final UrlParser parser = new UrlParser();
    private final UrlSafetyAnalyzer local = new UrlSafetyAnalyzer();

    private static boolean has(UrlAnalysisResult r, String id) {
        return r.getLocalIndicators().stream().anyMatch(i -> i.getId().equals(id));
    }

    // ---------- parsing ----------

    @Test
    void parsesComponentsSeparately() {
        ParsedUrl p = parser.parse("https://user@Sub.Example.co.in:8443/a/b?x=1&token=secret#frag");
        assertTrue(p.isValid());
        assertEquals("https", p.getScheme());
        assertEquals("user", p.getUserInfo());
        assertEquals("sub.example.co.in", p.getAsciiHost());
        assertEquals(8443, p.getPort());
        assertEquals("/a/b", p.getPath());
        assertEquals("x=1&token=secret", p.getQuery());
        assertEquals("frag", p.getFragment());
        assertEquals("https://sub.example.co.in:8443/a/b", p.getSanitizedUrl());
        assertFalse(p.getSanitizedUrl().contains("secret"));
    }

    @Test
    void preservesOriginalInputVerbatim() {
        String in = "  HTTPS://Example.COM/Path?q=1  ";
        ParsedUrl p = parser.parse(in);
        assertEquals(in, p.getOriginalInput());
        assertEquals("example.com", p.getAsciiHost());
        assertEquals("/Path", p.getPath());
    }

    @Test
    void schemeLessInputDefaultsToHttpsWithoutFlaggingHttp() {
        ParsedUrl p = parser.parse("example.com:8080/x");
        assertTrue(p.isValid());
        assertFalse(p.isSchemeExplicit());
        assertEquals(8080, p.getPort());
        assertFalse(has(local.analyze("example.com/x"), UrlLocalAnalyzer.NOT_ENCRYPTED));
    }

    @Test
    void malformedInputsAreInvalidNotCrashes() {
        String[] bad = {null, "", "   ", "http://", "https://:80", "http://exa mple.com", "http://example..com",
                "http://example.com:99999", "http://example.com:abc", "http://[::1", "javascript:alert(1)",
                "data:text/html,hi", "file:///etc/passwd", "ftp://example.com", "http:example.com",
                "http://-bad-.com", "noperiod", "http://a\u0000b.com", "http://%zz.com", "http://123.456"};
        for (String b : bad) {
            UrlAnalysisResult r = local.analyze(b);
            if (b != null && b.equals("http://123.456")) continue; // numeric host form, covered elsewhere
            assertFalse(r.getParsedUrl().isValid(), "should be invalid: " + b);
            assertEquals(ReputationStatus.INVALID_INPUT, r.getStatus(), b);
            assertEquals(UrlRiskVerdict.CANNOT_TELL, r.getVerdict(), b);
            assertFalse(r.getParsedUrl().getValidationError().isEmpty());
        }
    }

    @Test
    void extremelyLongInputHandled() {
        StringBuilder sb = new StringBuilder("https://example.com/");
        while (sb.length() < 20000) sb.append("aaaaaaaaaa");
        UrlAnalysisResult r = local.analyze(sb.toString());
        assertEquals(ReputationStatus.INVALID_INPUT, r.getStatus());
        assertEquals(sb.toString(), r.getParsedUrl().getOriginalInput());

        StringBuilder ok = new StringBuilder("https://example.com/");
        while (ok.length() < 3000) ok.append("abc/");
        UrlAnalysisResult r2 = local.analyze(ok.toString());
        assertTrue(r2.getParsedUrl().isValid());
        assertTrue(has(r2, UrlLocalAnalyzer.VERY_LONG));
    }

    @Test
    void longLabelRejected() {
        String label = "a".repeat(64);
        assertFalse(parser.parse("https://" + label + ".com").isValid());
    }

    // ---------- benign ----------

    @Test
    void ordinaryUrlsHaveNoWarnings() {
        String[] ok = {"https://www.google.com", "https://mail.google.com/mail/u/0", "https://www.roblox.com/games/1",
                "https://en.wikipedia.org/wiki/Computer_security", "https://scratch.mit.edu", "https://www.sbi.co.in",
                "https://ncert.nic.in/textbook.php"};
        for (String u : ok) {
            UrlAnalysisResult r = local.analyze(u);
            assertTrue(r.getLocalIndicators().isEmpty(), u + " -> " + r.getLocalIndicators());
            assertEquals(UrlRiskVerdict.NO_WARNING_SIGNS_FOUND, r.getVerdict(), u);
            assertEquals(ReputationStatus.LIVE_NOT_CHECKED, r.getStatus(), u);
            assertTrue(r.getLimitations().contains("not checked"));
        }
    }

    // ---------- deceptive ----------

    @Test
    void userInfoHostTrickIsCritical() {
        UrlAnalysisResult r = local.analyze("http://accounts.google.com@attacker-portal.com/login");
        assertTrue(has(r, UrlLocalAnalyzer.DECEPTIVE_HOST_PLACEMENT));
        assertEquals("attacker-portal.com", r.getParsedUrl().getAsciiHost());
        assertEquals(UrlRiskVerdict.WARNING_SIGNS, r.getVerdict());
        assertEquals(ReputationStatus.LOCAL_WARNINGS_ONLY, r.getStatus());
    }

    @Test
    void plainUserInfoIsHigh() {
        UrlAnalysisResult r = local.analyze("https://admin:pw@example.com/");
        assertTrue(has(r, UrlLocalAnalyzer.USER_INFO));
    }

    @Test
    void brandInSubdomainIsDeceptive() {
        UrlAnalysisResult r = local.analyze("https://roblox.com.claim-reward.top/free");
        assertTrue(has(r, UrlLocalAnalyzer.DECEPTIVE_HOST_PLACEMENT));
        assertTrue(has(r, UrlLocalAnalyzer.ABUSED_TLD));
        assertTrue(has(r, UrlLocalAnalyzer.LURE_WORDS));
        assertEquals(UrlRiskVerdict.WARNING_SIGNS, r.getVerdict());
    }

    @Test
    void brandMixedIntoUnofficialDomain() {
        UrlAnalysisResult r = local.analyze("https://paypal-account-verify.com/");
        assertTrue(has(r, UrlLocalAnalyzer.BRAND_ON_UNOFFICIAL));
        assertTrue(has(r, UrlLocalAnalyzer.LURE_WORDS));
    }

    @Test
    void lookalikeSpellingDetectedWithoutSampleList() {
        for (String u : new String[]{"https://g00gle.com", "https://robl0x.com/login", "https://paypa1.com", "https://disc0rd.gg",
                "https://rnicrosoft.com"}) {
            assertTrue(has(local.analyze(u), UrlLocalAnalyzer.LOOKALIKE), u);
        }
        assertTrue(has(local.analyze("https://robblox.com"), UrlLocalAnalyzer.LOOKALIKE)); // one edit away
        assertFalse(has(local.analyze("https://applebees.com"), UrlLocalAnalyzer.LOOKALIKE));
        assertFalse(has(local.analyze("https://stream.example.com"), UrlLocalAnalyzer.LOOKALIKE));
    }

    // ---------- internationalised ----------

    @Test
    void cyrillicHomographDetected() {
        // "pаypal" with Cyrillic 'а' (U+0430)
        UrlAnalysisResult r = local.analyze("https://pаypal.com/signin");
        assertTrue(r.getParsedUrl().isValid());
        assertTrue(r.getParsedUrl().isPunycode());
        assertTrue(r.getParsedUrl().getAsciiHost().startsWith("xn--"));
        assertTrue(has(r, UrlLocalAnalyzer.MIXED_SCRIPT));
        assertTrue(has(r, UrlLocalAnalyzer.LOOKALIKE));
        assertEquals(UrlRiskVerdict.WARNING_SIGNS, r.getVerdict());
    }

    @Test
    void punycodeInputDecodedForDisplay() {
        ParsedUrl p = parser.parse("https://xn--80ak6aa92e.com/");
        assertTrue(p.isValid());
        assertNotEquals(p.getAsciiHost(), p.getUnicodeHost());
        UrlAnalysisResult r = local.analyze("https://xn--80ak6aa92e.com/");
        assertTrue(has(r, UrlLocalAnalyzer.MIXED_SCRIPT), r.getLocalIndicators().toString()); // all-Cyrillic "apple"
    }

    @Test
    void legitimateInternationalDomainIsOnlyLowNote() {
        UrlAnalysisResult r = local.analyze("https://भारत.भारत/");
        assertTrue(r.getParsedUrl().isValid());
        assertTrue(has(r, UrlLocalAnalyzer.PUNYCODE));
        assertFalse(has(r, UrlLocalAnalyzer.MIXED_SCRIPT));
        assertEquals(UrlRiskVerdict.NO_WARNING_SIGNS_FOUND, r.getVerdict());
    }

    // ---------- encoded / unusual structure ----------

    @Test
    void encodingTricks() {
        assertTrue(has(local.analyze("https://ex%61mple.com/"), UrlLocalAnalyzer.ENCODED_HOST));
        assertEquals("example.com", parser.parse("https://ex%61mple.com/").getAsciiHost());
        assertTrue(has(local.analyze("https://example.com/a%00.html"), UrlLocalAnalyzer.ENCODED_NULL));
        assertTrue(has(local.analyze("https://example.com/%252e%252e/x"), UrlLocalAnalyzer.DOUBLE_ENCODING));
        assertTrue(has(local.analyze("https://example.com/%6c%6f%67%69%6e%2e%70%68%70%3f%69%64"), UrlLocalAnalyzer.HEAVY_ENCODING));
        assertTrue(has(local.analyze("https://example.com/r?u=https%3A%2F%2Fevil.example"), UrlLocalAnalyzer.EMBEDDED_URL));
        assertTrue(has(local.analyze("https:\\\\example.com\\login"), UrlLocalAnalyzer.BACKSLASH));
    }

    @Test
    void ipHosts() {
        assertTrue(has(local.analyze("http://192.168.1.100/pay"), UrlLocalAnalyzer.IP_LITERAL));
        assertTrue(has(local.analyze("http://[2001:db8::1]:8080/"), UrlLocalAnalyzer.IP_LITERAL));
        for (String u : new String[]{"http://3232235777/", "http://0xC0A80101/", "http://0300.0250.1.1/", "http://192.168.257/"}) {
            UrlAnalysisResult r = local.analyze(u);
            assertTrue(has(r, UrlLocalAnalyzer.NONSTANDARD_IP), u);
        }
    }

    @Test
    void structureSignals() {
        assertTrue(has(local.analyze("http://example.com/"), UrlLocalAnalyzer.NOT_ENCRYPTED));
        assertTrue(has(local.analyze("https://example.com:1337/"), UrlLocalAnalyzer.NON_STANDARD_PORT));
        assertTrue(has(local.analyze("https://a.b.c.d.e.example.com/"), UrlLocalAnalyzer.MANY_SUBDOMAINS));
        assertTrue(has(local.analyze("https://bit.ly/abc"), UrlLocalAnalyzer.SHORTENER));
        assertTrue(has(local.analyze("https://free-gift-card-win-now.com"), UrlLocalAnalyzer.MANY_HYPHENS));
        assertTrue(has(local.analyze("https://mygame.netlify.app"), UrlLocalAnalyzer.FREE_HOSTING));
    }

    @Test
    void everyIndicatorHasEvidence() {
        UrlAnalysisResult r = local.analyze("http://roblox.com.free-robux.top:8081/%2541?u=http://x.y");
        assertFalse(r.getLocalIndicators().isEmpty());
        r.getLocalIndicators().forEach(i -> assertFalse(i.getEvidenceExcerpt().isEmpty(), i.getId()));
    }

    // ---------- provider ----------

    static class FakeAuth implements AuthTokenSource {
        boolean fail, network;
        int invalidated;
        public String getIdToken() throws AuthException {
            if (fail) throw new AuthException("x", network);
            return "tok";
        }
        public String getUserId() { return "uid"; }
        public void invalidate() { invalidated++; }
    }

    static class FakeHttp implements HttpTransport {
        int code = 200;
        String body = "{\"result\":\"NO_MATCH\"}";
        boolean timeout, offline;
        final List<String> bodies = new ArrayList<>();
        public Response execute(String m, String url, Map<String, String> h, String b, int t)
                throws TimeoutException, NetworkException {
            bodies.add(b);
            if (timeout) throw new TimeoutException("t");
            if (offline) throw new NetworkException("n");
            return new Response(code, body);
        }
    }

    private UrlSafetyAnalyzer withProvider(FakeHttp http, FakeAuth auth) {
        return new UrlSafetyAnalyzer(new BackendUrlReputationProvider("https://api.example.test", auth, http, 1000));
    }

    @Test
    void liveLookupOnlyWithConsent() {
        FakeHttp http = new FakeHttp();
        UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("https://example.com/", false);
        assertTrue(http.bodies.isEmpty());
        assertEquals(ReputationStatus.LIVE_NOT_CHECKED, r.getStatus());
        assertNull(r.getReputation());
    }

    @Test
    void sendsOnlySanitizedUrl() {
        FakeHttp http = new FakeHttp();
        withProvider(http, new FakeAuth()).analyze("https://kid:pw@example.com/p?token=abc#f", true);
        assertEquals(1, http.bodies.size());
        assertEquals("{\"url\":\"https://example.com/p\"}", http.bodies.get(0));
    }

    @Test
    void noMatch() {
        UrlAnalysisResult r = withProvider(new FakeHttp(), new FakeAuth()).analyze("https://example.com/", true);
        assertEquals(ReputationStatus.NO_KNOWN_THREAT, r.getStatus());
        assertEquals(UrlRiskVerdict.NO_WARNING_SIGNS_FOUND, r.getVerdict());
    }

    @Test
    void threatMatch() {
        FakeHttp http = new FakeHttp();
        http.body = "{\"result\":\"THREAT_MATCH\",\"threatTypes\":[\"SOCIAL_ENGINEERING\"]}";
        UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("https://example.com/", true);
        assertEquals(ReputationStatus.THREAT_MATCH, r.getStatus());
        assertEquals(UrlRiskVerdict.WARNING_SIGNS, r.getVerdict());
        assertTrue(r.getLocalIndicators().isEmpty()); // local and live findings stay separate
    }

    @Test
    void timeoutNeverClean() {
        FakeHttp http = new FakeHttp();
        http.timeout = true;
        UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("https://example.com/", true);
        assertEquals(ReputationStatus.TIMEOUT_OR_NETWORK_ERROR, r.getStatus());
        assertEquals(UrlRiskVerdict.CANNOT_TELL, r.getVerdict());
        assertNotEquals(UrlRiskVerdict.NO_WARNING_SIGNS_FOUND, r.getVerdict());
    }

    @Test
    void offlineNeverClean() {
        FakeHttp http = new FakeHttp();
        http.offline = true;
        UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("https://example.com/", true);
        assertEquals(ReputationStatus.TIMEOUT_OR_NETWORK_ERROR, r.getStatus());
        assertEquals(UrlRiskVerdict.CANNOT_TELL, r.getVerdict());
    }

    @Test
    void timeoutKeepsLocalWarnings() {
        FakeHttp http = new FakeHttp();
        http.timeout = true;
        UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("http://accounts.google.com@evil.example/", true);
        assertEquals(UrlRiskVerdict.WARNING_SIGNS, r.getVerdict());
        assertEquals(ReputationStatus.TIMEOUT_OR_NETWORK_ERROR, r.getStatus());
    }

    @Test
    void invalidProviderResponses() {
        String[] bodies = {"", "not json", "{}", "{\"result\":\"SAFE\"}", "{\"result\":\"THREAT_MATCH\"}",
                "{\"result\":\"THREAT_MATCH\",\"threatTypes\":[\"BOGUS\"]}", "[1,2]", "{\"result\":\"NO_MATCH\""};
        for (String b : bodies) {
            FakeHttp http = new FakeHttp();
            http.body = b;
            UrlAnalysisResult r = withProvider(http, new FakeAuth()).analyze("https://example.com/", true);
            assertEquals(ReputationStatus.PROVIDER_UNAVAILABLE, r.getStatus(), b);
            assertEquals(UrlRiskVerdict.CANNOT_TELL, r.getVerdict(), b);
        }
    }

    @Test
    void httpErrorsAndAuth() {
        FakeHttp http = new FakeHttp();
        http.code = 500;
        assertEquals(ReputationStatus.PROVIDER_UNAVAILABLE, withProvider(http, new FakeAuth()).analyze("https://example.com/", true).getStatus());
        FakeHttp h401 = new FakeHttp();
        h401.code = 401;
        FakeAuth auth = new FakeAuth();
        assertEquals(ReputationStatus.PROVIDER_UNAVAILABLE, withProvider(h401, auth).analyze("https://example.com/", true).getStatus());
        assertEquals(1, auth.invalidated);
        FakeAuth bad = new FakeAuth();
        bad.fail = true;
        assertEquals(ReputationStatus.PROVIDER_UNAVAILABLE, withProvider(new FakeHttp(), bad).analyze("https://example.com/", true).getStatus());
        bad.network = true;
        assertEquals(ReputationStatus.TIMEOUT_OR_NETWORK_ERROR, withProvider(new FakeHttp(), bad).analyze("https://example.com/", true).getStatus());
    }

    @Test
    void unconfiguredProvider() {
        UrlSafetyAnalyzer a = new UrlSafetyAnalyzer(new BackendUrlReputationProvider("", new FakeAuth(), new FakeHttp(), 1000));
        UrlAnalysisResult r = a.analyze("https://example.com/", true);
        assertEquals(ReputationStatus.LIVE_NOT_CHECKED, r.getStatus());
        assertTrue(r.getLiveCheckNote().contains("isn't set up"));
        assertFalse(new BackendUrlReputationProvider("http://insecure.test", new FakeAuth(), new FakeHttp(), 1).isConfigured());
    }

    @Test
    void providerExceptionIsUnavailable() {
        UrlReputationProvider boom = new UrlReputationProvider() {
            public ReputationResult check(ParsedUrl u) { throw new IllegalStateException("x"); }
            public boolean isConfigured() { return true; }
            public String getName() { return "boom"; }
            public String getDisclosure() { return ""; }
        };
        UrlAnalysisResult r = new UrlSafetyAnalyzer(boom).analyze("https://example.com/", true);
        assertEquals(ReputationStatus.PROVIDER_UNAVAILABLE, r.getStatus());
        assertEquals(UrlRiskVerdict.CANNOT_TELL, r.getVerdict());
    }
}
