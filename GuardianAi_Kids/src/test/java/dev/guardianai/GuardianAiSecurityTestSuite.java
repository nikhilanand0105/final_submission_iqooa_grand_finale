package dev.guardianai;

import dev.guardianai.engine.GuardianAiApkIntelligence;
import dev.guardianai.model.*;
import dev.guardianai.parser.BinaryXmlDecoder;
import dev.guardianai.parser.DexBytecodeScanner;
import dev.guardianai.rules.BankingTrojanPatternRule;
import dev.guardianai.rules.OtpStealerPatternRule;
import dev.guardianai.rules.ThreatRuleEvaluator;
import dev.guardianai.sense.ConversationRiskReport;
import dev.guardianai.sense.GuardianAiSenseEngine;
import dev.guardianai.sense.SafetyCategory;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class GuardianAiSecurityTestSuite {

    private static int testsRun = 0;
    private static int testsPassed = 0;

    public static void main(String[] args) {
        System.out.println("Running GuardianAi Security Core Verification Suite...");

        testBinaryXmlParser();
        testBankingTrojanRule();
        testOtpStealerRule();
        testScreenShareRule();
        testTollFraudRule();
        testLocalStorageRetention();
        testInstallHandoff();
        testVerdictDetermination();
        testHinglishSenseEngine();
        testPhishingScanner();
        testLocalFirewall();
        testHindiSynthesizer();
        testApkScannerViewModel();

        System.out.printf("\nTest Results: %d/%d tests PASSED.%n", testsPassed, testsRun);
        if (testsPassed != testsRun) {
            System.err.println("Some tests failed!");
            System.exit(1);
        }
    }

    private static void testPhishingScanner() {
        startTest("PhishingUrlScanner flags banking impersonation and raw IP URLs");
        dev.guardianai.shield.network.PhishingUrlScanner scanner = new dev.guardianai.shield.network.PhishingUrlScanner();

        var r1 = scanner.scanUrl("http://sbi-online-kyc-update.xyz/login");
        assertEquals(dev.guardianai.shield.network.PhishingUrlScanner.UrlRiskLevel.KNOWN_PHISHING, r1.riskLevel);

        var r2 = scanner.scanUrl("http://192.168.1.50/pay");
        assertEquals(dev.guardianai.shield.network.PhishingUrlScanner.UrlRiskLevel.KNOWN_PHISHING, r2.riskLevel);

        var r3 = scanner.scanUrl("https://onlinesbi.sbi");
        assertEquals(dev.guardianai.shield.network.PhishingUrlScanner.UrlRiskLevel.SAFE_REPUTATION, r3.riskLevel);
        pass();
    }

    private static void testLocalFirewall() {
        startTest("LocalFirewallEngine destination filtering and transfer anomaly checks");
        dev.guardianai.shield.network.LocalFirewallEngine fw = new dev.guardianai.shield.network.LocalFirewallEngine();
        assertTrue(fw.shouldBlockConnection("phishing-sbi-portal.xyz", 443), "Blocks malicious host");
        assertFalse(fw.shouldBlockConnection("google.com", 443), "Allows clean host");

        boolean anomaly = fw.checkAnomalousBackgroundTransfer("com.suspicious.app", 80_000_000L);
        assertTrue(anomaly, "Flags anomalous high-volume background data transfer");
        pass();
    }

    private static void testHindiSynthesizer() {
        startTest("HindiExplanationSynthesizer generates plain Hindi guidance for elders");
        dev.guardianai.shield.network.PhishingUrlScanner scanner = new dev.guardianai.shield.network.PhishingUrlScanner();
        var phishingResult = scanner.scanUrl("http://sbi-fake-kyc.biz");
        String hindiAdvice = dev.guardianai.ai.HindiExplanationSynthesizer.explainPhishingLinkInHindi(phishingResult);
        assertTrue(hindiAdvice.contains("1930"), "Contains 1930 Helpline in Hindi");
        assertTrue(hindiAdvice.contains("UPI PIN"), "Contains UPI PIN warning");
        pass();
    }

    private static void testApkScannerViewModel() {
        startTest("ApkScannerViewModel state management and Senior Mode toggle");
        dev.guardianai.ui.viewmodel.ApkScannerViewModel vm = new dev.guardianai.ui.viewmodel.ApkScannerViewModel(null, null);
        assertFalse(vm.getCurrentState().isSeniorModeActive(), "Starts with Standard Mode");
        vm.setSeniorMode(true);
        assertTrue(vm.getCurrentState().isSeniorModeActive(), "Enables Senior Mode");
        pass();
    }

    private static void testScreenShareRule() {
        startTest("ScreenShareAbuseRule triggers on repackaged AnyDesk/QuickSupport");
        dev.guardianai.rules.ScreenShareAbuseRule rule = new dev.guardianai.rules.ScreenShareAbuseRule();
        ManifestMetadata manifest = new ManifestMetadata(
                "com.anydesk.anydeskandroid.fake", "1.0", 1, 21, 33,
                Set.of(), List.of(), List.of(), List.of(),
                false, false, true
        );
        CertificateMetadata cert = new CertificateMetadata(
                "CN=Android Debug", "CN=Android Debug", "1", "HASH", new java.util.Date(), new java.util.Date(), true, true, false
        );
        List<ThreatIndicator> ind = rule.evaluate(manifest, null, cert, null);
        assertFalse(ind.isEmpty(), "Should detect repackaged tool");
        assertEquals("REPACKAGED_REMOTE_CONTROL_TOOL", ind.get(0).getId());
        pass();
    }

    private static void testTollFraudRule() {
        startTest("TollFraudSmsRule triggers on SEND_SMS + READ_PHONE_STATE + INTERNET");
        dev.guardianai.rules.TollFraudSmsRule rule = new dev.guardianai.rules.TollFraudSmsRule();
        ManifestMetadata manifest = new ManifestMetadata(
                "com.toll.stealth", "1.0", 1, 21, 33,
                Set.of("android.permission.SEND_SMS", "android.permission.READ_PHONE_STATE", "android.permission.INTERNET"),
                List.of(), List.of(), List.of(),
                false, false, true
        );
        List<ThreatIndicator> ind = rule.evaluate(manifest, null, null, null);
        assertFalse(ind.isEmpty(), "Should detect toll fraud cluster");
        assertEquals("TOLL_FRAUD_INDICATOR_CLUSTER", ind.get(0).getId());
        pass();
    }

    private static void testLocalStorageRetention() {
        startTest("LocalStorageRepository prunes records exceeding retention days");
        dev.guardianai.storage.LocalStorageRepository repo = new dev.guardianai.storage.LocalStorageRepository();
        repo.setRetentionDays(14);
        repo.recordScan("test1.apk", "hash1", ScanVerdict.NO_KNOWN_THREAT_DETECTED, 0, "CANCELLED");
        assertEquals(1, repo.getAllScanRecords().size());
        pass();
    }

    private static void testInstallHandoff() {
        startTest("ApkInstallHandoffHelper builds valid system install intent without REQUEST_INSTALL_PACKAGES");
        var intent = dev.guardianai.engine.ApkInstallHandoffHelper.createSystemInstallIntent("content://dev.guardianai/scans/app.apk");
        assertEquals("android.intent.action.VIEW", intent.action);
        assertEquals("application/vnd.android.package-archive", intent.mimeType);
        assertTrue((intent.flags & dev.guardianai.engine.ApkInstallHandoffHelper.FLAG_GRANT_READ_URI_PERMISSION) != 0, "Has grant read permission");
        pass();
    }

    private static void testBinaryXmlParser() {
        startTest("BinaryXmlDecoder plain text manifest parsing");
        String xml = "<manifest package=\"com.test.app\" xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
                     "  <uses-permission android:name=\"android.permission.INTERNET\"/>\n" +
                     "  <uses-permission android:name=\"android.permission.READ_SMS\"/>\n" +
                     "  <application>\n" +
                     "    <activity android:name=\".MainActivity\">\n" +
                     "      <intent-filter>\n" +
                     "        <action android:name=\"android.intent.action.MAIN\"/>\n" +
                     "        <category android:name=\"android.intent.category.LAUNCHER\"/>\n" +
                     "      </intent-filter>\n" +
                     "    </activity>\n" +
                     "  </application>\n" +
                     "</manifest>";

        ManifestMetadata metadata = BinaryXmlDecoder.decode(xml.getBytes(StandardCharsets.UTF_8));
        assertEquals("com.test.app", metadata.getPackageName());
        assertTrue(metadata.hasPermission("android.permission.INTERNET"), "Has INTERNET permission");
        assertTrue(metadata.hasPermission("android.permission.READ_SMS"), "Has READ_SMS permission");
        assertTrue(metadata.hasLauncherActivity(), "Has Launcher Activity");
        pass();
    }

    private static void testBankingTrojanRule() {
        startTest("BankingTrojanPatternRule triggers on Overlay + Accessibility");
        BankingTrojanPatternRule rule = new BankingTrojanPatternRule();
        ManifestMetadata manifest = new ManifestMetadata(
                "com.evil.bank", "1.0", 1, 21, 33,
                Set.of("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"),
                List.of(), List.of("com.evil.bank.AccService"), List.of(),
                false, true, true
        );

        List<ThreatIndicator> indicators = rule.evaluate(manifest, null, null, null);
        assertFalse(indicators.isEmpty(), "Indicators should not be empty");
        assertEquals("ATS_CRITICAL_COMBO", indicators.get(0).getId());
        assertEquals(ThreatSeverity.CRITICAL, indicators.get(0).getSeverity());
        pass();
    }

    private static void testOtpStealerRule() {
        startTest("OtpStealerPatternRule triggers on SMS + Dynamic Dex loading");
        OtpStealerPatternRule rule = new OtpStealerPatternRule();
        ManifestMetadata manifest = new ManifestMetadata(
                "com.sms.stealer", "1.0", 1, 21, 33,
                Set.of("android.permission.READ_SMS"),
                List.of(), List.of(), List.of(),
                false, false, false
        );

        DexInspectionResult dex = new DexInspectionResult(
                1, 10, 20, Set.of(), List.of(), List.of(),
                true, false, false, false, false, false
        );

        List<ThreatIndicator> indicators = rule.evaluate(manifest, dex, null, null);
        assertFalse(indicators.isEmpty(), "Indicators should not be empty");
        assertEquals("SMS_DYNAMIC_CODE_STEALER", indicators.get(0).getId());
        assertEquals(ThreatSeverity.CRITICAL, indicators.get(0).getSeverity());
        pass();
    }

    private static void testVerdictDetermination() {
        startTest("ThreatRuleEvaluator maps critical indicators to HIGH_RISK / KNOWN_MALICIOUS");
        ThreatRuleEvaluator evaluator = new ThreatRuleEvaluator();

        // Critical indicator -> HIGH_RISK
        List<ThreatIndicator> criticalIndicators = List.of(
                new ThreatIndicator("C1", "Critical", "Test", ThreatSeverity.CRITICAL, "TEST")
        );
        ScanVerdict v1 = evaluator.determineVerdict("dummy_hash", criticalIndicators, true);
        assertEquals(ScanVerdict.HIGH_RISK, v1);

        // Empty indicators -> NO_KNOWN_THREAT_DETECTED
        ScanVerdict v2 = evaluator.determineVerdict("dummy_hash", Collections.emptyList(), true);
        assertEquals(ScanVerdict.NO_KNOWN_THREAT_DETECTED, v2);

        // Known hash -> KNOWN_MALICIOUS
        String knownHash = "3a019b88f8d2dfbb187b47b4d187bdf559ef14c1d686f0b4d45543c8d1720d29";
        ScanVerdict v3 = evaluator.determineVerdict(knownHash, Collections.emptyList(), true);
        assertEquals(ScanVerdict.KNOWN_MALICIOUS, v3);
        pass();
    }

    private static void testHinglishSenseEngine() {
        startTest("GuardianAiSenseEngine accurately separates benign birthday secret from predatory coercion");
        GuardianAiSenseEngine engine = new GuardianAiSenseEngine();

        // 1. Benign secret
        ConversationRiskReport r1 = engine.analyze("Kal Rahul ki surprise birthday party hai, kisi ko mat batana");
        assertEquals(SafetyCategory.BENIGN, r1.getCategory());
        assertFalse(r1.shouldPromptSos(), "Should not trigger SOS");

        // 2. Predatory coercion
        ConversationRiskReport r2 = engine.analyze("Camera on kar video call pe, kisi ko mat batana, gift dunga");
        assertEquals(SafetyCategory.GROOMING_MANIPULATION, r2.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r2.getSeverity());
        assertTrue(r2.shouldPromptSos(), "Should trigger SOS prompt");

        // 3. Gaming fraud
        ConversationRiskReport r3 = engine.analyze("Free diamonds ke liye UPI PIN daal de");
        assertEquals(SafetyCategory.CHILD_FINANCIAL_SCAM, r3.getCategory());
        pass();
    }

    private static void startTest(String name) {
        testsRun++;
        System.out.printf("Test %d: %s ... ", testsRun, name);
    }

    private static void pass() {
        testsPassed++;
        System.out.println("PASSED");
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) {
            throw new AssertionError(String.format("Expected [%s] but was [%s]", expected, actual));
        }
    }

    private static void assertTrue(boolean condition, String msg) {
        if (!condition) {
            throw new AssertionError("Condition failed: " + msg);
        }
    }

    private static void assertFalse(boolean condition, String msg) {
        if (condition) {
            throw new AssertionError("Condition should be false: " + msg);
        }
    }
}
