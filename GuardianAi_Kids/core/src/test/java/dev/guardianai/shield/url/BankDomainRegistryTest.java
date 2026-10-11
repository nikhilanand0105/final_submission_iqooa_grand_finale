package dev.guardianai.shield.url;

import dev.guardianai.safety.SafetyClassification;
import dev.guardianai.safety.SafetyPipeline;
import dev.guardianai.safety.SafetyTypes;
import dev.guardianai.safety.WebSafety;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class BankDomainRegistryTest {

    private final BankDomainRegistry bankReg = BankDomainRegistry.bundled();
    private final OfficialDomainRegistry offReg = OfficialDomainRegistry.bundled();
    private final UrlSafetyAnalyzer analyzer = new UrlSafetyAnalyzer();

    private DomainTrust evaluate(String url) {
        return DomainTrust.evaluate(analyzer.analyze(url), offReg, bankReg);
    }

    @Test
    void registryLoadsWithAuthorityAndVerificationDate() {
        assertNotNull(bankReg);
        assertEquals("2026.10.1", bankReg.version);
        assertEquals("2026-10-11", bankReg.verificationDate);
        assertTrue(bankReg.authoritySource.contains("Reserve Bank of India"));
        assertTrue(bankReg.banks.size() >= 10);

        // Verify presence of all six core Indian banks
        assertNotNull(bankReg.findBank("sbi.bank.in"));
        assertNotNull(bankReg.findBank("hdfc.bank.in"));
        assertNotNull(bankReg.findBank("icici.bank.in"));
        assertNotNull(bankReg.findBank("axis.bank.in"));
        assertNotNull(bankReg.findBank("pnb.bank.in"));
        assertNotNull(bankReg.findBank("bankofbaroda.bank.in"));
    }

    @Test
    void verifiedOfficialIndianBankDomainsAccepted() {
        String[] officialUrls = {
                "https://sbi.bank.in/",
                "https://www.sbi.bank.in/",
                "https://corp.sbi.bank.in/",
                "https://hdfc.bank.in/",
                "https://www.hdfc.bank.in/",
                "https://icici.bank.in/",
                "https://www.icici.bank.in/",
                "https://axis.bank.in/",
                "https://www.axis.bank.in/",
                "https://pnb.bank.in/",
                "https://www.pnb.bank.in/",
                "https://bankofbaroda.bank.in/",
                "https://www.bankofbaroda.bank.in/"
        };
        for (String url : officialUrls) {
            DomainTrust dt = evaluate(url);
            assertEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, dt.outcome, "Failed for URL: " + url);
            assertNotNull(dt.organisation, "Organisation missing for URL: " + url);
            WebSafety.Decision d = WebSafety.forUrl(dt);
            assertEquals(WebSafety.Action.ALLOW, d.action, "Action must be ALLOW for URL: " + url);
            assertEquals(WebSafety.Reason.NONE, d.reason);
        }
    }

    @Test
    void officiallyLinkedLegacyDomainsAndPortalsAccepted() {
        String[][] legacyCases = {
                {"https://sbi.co.in/", "State Bank of India"},
                {"https://onlinesbi.sbi/", "State Bank of India"},
                {"https://bank.sbi/", "State Bank of India"},
                {"https://hdfcbank.com/", "HDFC Bank"},
                {"https://netbanking.hdfcbank.com/", "HDFC Bank"},
                {"https://icicibank.com/", "ICICI Bank"},
                {"https://infinity.icicibank.com/", "ICICI Bank"},
                {"https://axisbank.com/", "Axis Bank"},
                {"https://pnbindia.in/", "Punjab National Bank"},
                {"https://netpnb.com/", "Punjab National Bank"},
                {"https://bankofbaroda.in/", "Bank of Baroda"},
                {"https://bobibanking.com/", "Bank of Baroda"}
        };
        for (String[] pair : legacyCases) {
            String url = pair[0];
            String expectedOrg = pair[1];
            DomainTrust dt = evaluate(url);
            assertEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, dt.outcome, "Failed for legacy URL: " + url);
            assertEquals(expectedOrg, dt.organisation, "Org mismatch for URL: " + url);
            WebSafety.Decision d = WebSafety.forUrl(dt);
            assertEquals(WebSafety.Action.ALLOW, d.action, "Action must be ALLOW for legacy URL: " + url);
        }
    }

    @Test
    void syntheticAndDeceptiveSpoofsCorrectlyBlocked() {
        // Synthetic fixture explicitly requested in prompt
        DomainTrust synthetic = evaluate("https://sbi-secure-login.example.test/verify");
        assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, synthetic.outcome);
        assertEquals("State Bank of India", synthetic.organisation);
        WebSafety.Decision sd = WebSafety.forUrl(synthetic);
        assertEquals(WebSafety.Action.WARN, sd.action);
        assertEquals(WebSafety.Reason.SUSPECTED_SPOOF, sd.reason);

        // Deceptive subdomain wrapping bank.in
        DomainTrust wrapper = evaluate("https://sbi.bank.in.attacker.test/login");
        assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, wrapper.outcome);
        assertEquals(WebSafety.Action.WARN, WebSafety.forUrl(wrapper).action);

        // Wrong registrable domain
        DomainTrust wrongReg = evaluate("https://sbi.example.test/");
        assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, wrongReg.outcome);

        // Misleading brand combined with lure words
        DomainTrust hdfcSpoof = evaluate("https://hdfcbank.com.verify-kyc.top/update");
        assertEquals(DomainTrust.Outcome.SUSPECTED_SPOOF, hdfcSpoof.outcome);
        assertEquals("HDFC Bank", hdfcSpoof.organisation);
    }

    @Test
    void bankNameInPathOrUserInfoNotAcceptedAsBank() {
        // Bank name appearing only in URL path on unknown site
        DomainTrust pathOnly = evaluate("https://attacker.test/sbi/login");
        assertEquals(DomainTrust.Outcome.UNKNOWN, pathOnly.outcome, "Bank in path must not make domain official");

        // Bank name appearing only in user-info
        DomainTrust userInfo = evaluate("https://sbi@attacker.test/");
        assertNotEquals(DomainTrust.Outcome.RECOGNISED_OFFICIAL, userInfo.outcome, "User-info must not make domain official");
        assertNotEquals(DomainTrust.Outcome.OFFICIALLY_LINKED_LEGACY, userInfo.outcome);
    }

    @Test
    void genuineThreatReputationMatchOverridesOfficialDomain() {
        UrlReputationProvider maliciousProvider = new UrlReputationProvider() {
            public ReputationResult check(ParsedUrl u) {
                return ReputationResult.threat(Collections.singletonList("MALWARE"));
            }
            public boolean isConfigured() { return true; }
            public String getName() { return "Live Threat Feed"; }
            public String getDisclosure() { return ""; }
        };
        UrlSafetyAnalyzer analyzerWithThreat = new UrlSafetyAnalyzer(maliciousProvider);
        UrlAnalysisResult hit = analyzerWithThreat.analyze("https://sbi.bank.in/", true);
        DomainTrust dt = DomainTrust.evaluate(hit, offReg, bankReg);
        // Independent threat hit must not be silently bypassed
        assertEquals(DomainTrust.Outcome.KNOWN_HARMFUL, dt.outcome);
        WebSafety.Decision d = WebSafety.forUrl(dt);
        assertEquals(WebSafety.Action.BLOCK, d.action);
        assertEquals(WebSafety.Reason.KNOWN_HARMFUL, d.reason);
    }

    @Test
    void bankingTerminologyDoesNotTriggerAgeBlock() {
        String bankPage = "Welcome to State Bank of India net banking portal. "
                + "Manage your savings account, fixed deposit interest rates, recurring deposits, loans, "
                + "and credit cards securely. Login with your username and password. "
                + "Term deposit bonus interest of 0.5% available for senior citizens.";
        WebSafety.AgeFinding af = WebSafety.pageSuitability(bankPage);
        assertEquals(SafetyTypes.AgeConcern.NONE, af.concern, "Legitimate banking terms must not trigger age concern");

        SafetyPipeline pipeline = new SafetyPipeline(null);
        SafetyClassification c = pipeline.analyze(SafetyTypes.SourceType.BROWSER_PAGE, bankPage, "from sbi.bank.in", null).classification;
        WebSafety.Decision d = WebSafety.forContent(c);
        assertEquals(WebSafety.Action.ALLOW, d.action);
    }
}
