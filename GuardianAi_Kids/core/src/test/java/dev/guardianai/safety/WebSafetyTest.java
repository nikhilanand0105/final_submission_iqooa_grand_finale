package dev.guardianai.safety;

import dev.guardianai.safety.SafetyTypes.AgeConcern;
import dev.guardianai.safety.SafetyTypes.SourceType;
import dev.guardianai.shield.url.DomainTrust;
import dev.guardianai.shield.url.OfficialDomainRegistry;
import dev.guardianai.shield.url.ParsedUrl;
import dev.guardianai.shield.url.ReputationResult;
import dev.guardianai.shield.url.UrlAnalysisResult;
import dev.guardianai.shield.url.UrlLocalAnalyzer;
import dev.guardianai.shield.url.UrlReputationProvider;
import dev.guardianai.shield.url.UrlSafetyAnalyzer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class WebSafetyTest {

    private final OfficialDomainRegistry reg = OfficialDomainRegistry.bundled();
    private final UrlSafetyAnalyzer local = new UrlSafetyAnalyzer();

    private DomainTrust trust(String url) {
        return DomainTrust.evaluate(local.analyze(url), reg);
    }

    // ---------------- registry ----------------

    @Test
    void registryLoadsAndEnforcesLabelBoundaries() {
        assertNotNull(reg.version);
        assertTrue(reg.orgs.size() >= 20);
        OfficialDomainRegistry.Org hdfc = reg.byKeyword("hdfc");
        assertTrue(hdfc.owns("hdfcbank.com"));
        assertTrue(hdfc.owns("netbanking.hdfcbank.com"));
        assertFalse(hdfc.owns("evilhdfcbank.com"));
        assertFalse(hdfc.owns("hdfcbank.com.evil.top"));
        assertThrows(Exception.class, () -> OfficialDomainRegistry.parse("{\"schemaVersion\":1,\"organisations\":[{\"id\":\"x\"}]}"));
        assertThrows(Exception.class, () -> OfficialDomainRegistry.parse("{\"schemaVersion\":2,\"organisations\":[]}"));
    }

    // ---------------- domain trust outcomes ----------------

    @Test
    void officialAndSubdomains() {
        // Verified official primary domains under RBI .bank.in
        DomainTrust sbi = trust("https://sbi.bank.in/");
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, sbi.outcome);
        assertEquals("State Bank of India", sbi.organisation);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://www.sbi.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://hdfc.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://www.hdfc.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://icici.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://www.icici.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://axis.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://pnb.bank.in/").outcome);
        assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, trust("https://bankofbaroda.bank.in/").outcome);

        // Officially linked legacy domains and portals
        DomainTrust hdfcLegacy = trust("https://www.hdfcbank.com/");
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, hdfcLegacy.outcome);
        assertEquals("HDFC Bank", hdfcLegacy.organisation);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://netbanking.hdfcbank.com/login").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://onlinesbi.sbi/").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://sbi.co.in/").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://icicibank.com/").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://axisbank.com/").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://pnbindia.in/").outcome);
        assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, trust("https://bankofbaroda.in/").outcome);

        // Both official and officially linked legacy domains are allowed in Safe Browser
        assertEquals(WebSafety.Action.ALLOW, WebSafety.forUrl(sbi).action);
        assertEquals(WebSafety.Action.ALLOW, WebSafety.forUrl(hdfcLegacy).action);
    }

    @Test
    void spoofs() {
        String[] spoofs = {
                "https://sbi-secure-login.example.test/verify", // synthetic fixture from prompt
                "https://sbi.bank.in.attacker.test/",         // lookalike domain wrapping bank.in
                "https://hdfcbank.com.verify-kyc.top/login",  // misleading subdomain
                "https://hdfcbnak.com/",                       // misspelling (transposition)
                "https://1c1c1bank.com/",                     // digit lookalikes
                "https://icici-netbanking-update.com/",       // brand plus extra words
                "https://hdfcbank.com@secure-login.example/", // user-info trick
                "https://іcicibank.com/",                     // Cyrillic і (punycode)
        };
        for (String s : spoofs) {
            DomainTrust t = trust(s);
            assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, t.outcome, s + " -> " + t.reason);
            assertEquals(WebSafety.Action.WARN, WebSafety.forUrl(t).action, s);
        }
        assertEquals("HDFC Bank", trust("https://hdfcbank.com.verify-kyc.top/login").organisation);
        assertEquals("State Bank of India", trust("https://sbi-secure-login.example.test/verify").organisation);
    }

    @Test
    void unknownUnavailableAndKnownHarmful() {
        DomainTrust u = trust("https://my-school-project.example.org/");
        assertEquals(DomainTrust.Outcome.UNKNOWN, u.outcome);
        assertTrue(u.reason.contains("not checked"));
        assertEquals(WebSafety.Action.ALLOW, WebSafety.forUrl(u).action);
        assertEquals(DomainTrust.Outcome.UNAVAILABLE, trust("http://").outcome);

        UrlReputationProvider down = provider(ReputationResult.timeout("t"));
        assertEquals(DomainTrust.Outcome.UNAVAILABLE,
                DomainTrust.evaluate(new UrlSafetyAnalyzer(down).analyze("https://example.org/", true), reg).outcome);
        UrlReputationProvider bad = provider(ReputationResult.threat(java.util.Collections.singletonList("SOCIAL_ENGINEERING")));
        DomainTrust k = DomainTrust.evaluate(new UrlSafetyAnalyzer(bad).analyze("https://example.org/", true), reg);
        assertEquals(DomainTrust.Outcome.KNOWN_HARMFUL, k.outcome);
        WebSafety.Decision d = WebSafety.forUrl(k);
        assertEquals(WebSafety.Action.BLOCK, d.action);
        assertFalse(d.canContinue);
        UrlReputationProvider clean = provider(ReputationResult.noMatch());
        DomainTrust nk = DomainTrust.evaluate(new UrlSafetyAnalyzer(clean).analyze("https://example.org/", true), reg);
        assertEquals(DomainTrust.Outcome.UNKNOWN, nk.outcome, "absence from a threat list is not 'recognised'");
    }

    @Test
    void portsAndRedirects() {
        UrlAnalysisResult port = local.analyze("https://hdfcbank.com:8443/");
        assertTrue(port.getLocalIndicators().stream().anyMatch(i -> i.getId().equals(UrlLocalAnalyzer.NON_STANDARD_PORT)));
        UrlAnalysisResult redirect = local.analyze("https://www.google.com/url?q=https%3A%2F%2Fhdfcbank.com.verify-kyc.top%2F");
        assertTrue(redirect.getLocalIndicators().stream().anyMatch(i -> i.getId().equals(UrlLocalAnalyzer.EMBEDDED_URL)));
        // The Safe Browser evaluates each hop; the destination of the redirect is a spoof on its own.
        assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, trust("https://hdfcbank.com.verify-kyc.top/").outcome);
    }

    private static UrlReputationProvider provider(ReputationResult r) {
        return new UrlReputationProvider() {
            public ReputationResult check(ParsedUrl u) { return r; }
            public boolean isConfigured() { return true; }
            public String getName() { return "Test reputation"; }
            public String getDisclosure() { return ""; }
        };
    }

    // ---------------- search and page content ----------------

    @Test
    void searchQueries() {
        assertEquals("how to make slime", WebSafety.searchQuery("https://www.google.com/search?q=how+to+make+slime&hl=en"));
        assertEquals("cats", WebSafety.searchQuery("https://duckduckgo.com/?q=cats"));
        assertEquals("lofi", WebSafety.searchQuery("https://m.youtube.com/results?search_query=lofi"));
        assertEquals("x y", WebSafety.searchQuery("https://www.bing.com/search?q=x%20y"));
        assertNull(WebSafety.searchQuery("https://www.google.com/maps?q=delhi"));
        assertNull(WebSafety.searchQuery("https://example.com/search?q=hi"));
        assertNull(WebSafety.searchQuery("not a url"));
    }

    @Test
    void selfHarmSearchContext() {
        SafetyPipeline p = new SafetyPipeline(null);
        SafetyClassification personal = p.analyze(SourceType.BROWSER_SEARCH, "i want to die how to do it", null, null).classification;
        assertEquals(WebSafety.Action.SUPPORT, WebSafety.forContent(personal).action);
        SafetyClassification school = p.analyze(SourceType.BROWSER_SEARCH, "suicide prevention day essay ideas", null, null).classification;
        assertEquals(WebSafety.Action.ALLOW, WebSafety.forContent(school).action, "general research is not blocked");
        SafetyClassification word = p.analyze(SourceType.BROWSER_SEARCH, "suicide squad movie cast", null, null).classification;
        assertNotEquals(WebSafety.Action.SUPPORT, WebSafety.forContent(word).action);
    }

    @Test
    void pageSuitabilityNeedsRealEvidence() {
        String casino = "Welcome to Lucky Casino. Place your bets now! Jackpot every hour. Best odds, roulette and slot machines. Deposit bonus today.";
        assertEquals(AgeConcern.GAMBLING, WebSafety.pageSuitability(casino).concern);
        String adult = "Are you 18 or older? This site contains adult content and nude videos.";
        assertEquals(AgeConcern.EXPLICIT_CONTENT, WebSafety.pageSuitability(adult).concern);
        String prevention = "If you are having thoughts of suicide you are not alone. Call the helpline and talk to someone. Suicide prevention resources.";
        assertEquals(AgeConcern.NONE, WebSafety.pageSuitability(prevention).concern);
        String method = "Forum thread listing suicide methods and the lethal dose of common medicines for people who want answers.";
        assertEquals(AgeConcern.SELF_HARM_MATERIAL, WebSafety.pageSuitability(method).concern);
        String history = "The history of the casino industry in Macau is a topic in our economics chapter about tourism and regulation.";
        assertEquals(AgeConcern.NONE, WebSafety.pageSuitability(history).concern, "one mention is not enough");
        assertEquals(AgeConcern.UNKNOWN, WebSafety.pageSuitability("short").concern);

        SafetyPipeline p = new SafetyPipeline(null);
        SafetyClassification c = p.analyze(SourceType.BROWSER_PAGE, casino, null, null).classification;
        assertEquals(AgeConcern.GAMBLING, c.age);
        WebSafety.Decision d = WebSafety.forContent(c);
        assertEquals(WebSafety.Action.WARN, d.action);
        assertEquals(WebSafety.Reason.AGE_INAPPROPRIATE, d.reason);
        assertEquals(WebSafety.Action.BLOCK, WebSafety.forContent(p.analyze(SourceType.BROWSER_PAGE, adult, null, null).classification).action);
        assertEquals(WebSafety.Action.SUPPORT, WebSafety.forContent(p.analyze(SourceType.BROWSER_PAGE, method, null, null).classification).action);
        FlagEngine.Decision fd = FlagEngine.decide(c, "", SourceType.BROWSER_PAGE, "lucky-casino.example", "kp", null, 1);
        assertEquals(SafetyEvent.Category.AGE_SUITABILITY, fd.event.category);
        assertEquals(SafetyEvent.Flag.NONE, fd.event.flag, "age suitability is not one of the two safety flags");
    }
}
