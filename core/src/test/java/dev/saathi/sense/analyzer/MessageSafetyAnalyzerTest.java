package dev.saathi.sense.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Rigorous test suite for RuleBasedMessageSafetyAnalyzer.
 * Evaluates false positives, false negatives, multilingual (English/Hinglish) support,
 * overlapping indicators, and benign counter-signals.
 */
public class MessageSafetyAnalyzerTest {

    private MessageSafetyAnalyzer analyzer;

    @BeforeEach
    public void setUp() {
        analyzer = new RuleBasedMessageSafetyAnalyzer();
    }

    // =========================================================================
    // 1. WARNING-SIGN CASES (HIGH RISK / WARNING SIGNS)
    // =========================================================================

    @Test
    @DisplayName("Should detect OTP theft and credential solicitation in English")
    public void testOtpCredentialTheftEnglish() {
        String msg = "Please send your 6-digit OTP code to verify your game account right now.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, result.getVerdict());
        assertEquals(ProcessingStatus.SUCCESS, result.getStatus());
        assertTrue(result.hasWarnings());
        assertTrue(result.shouldSuggestAdultHelp());

        boolean hasCredIndicator = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.CREDENTIAL_THEFT);
        assertTrue(hasCredIndicator, "Expected CREDENTIAL_THEFT indicator");
        assertFalse(result.getEvidenceExcerpts().isEmpty());
    }

    @Test
    @DisplayName("Should detect OTP theft in Hinglish")
    public void testOtpTheftHinglish() {
        String msg = "Apna phone ka OTP bhej de jaldi se, account verify karna hai";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, result.getVerdict());
        boolean hasCredIndicator = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.CREDENTIAL_THEFT);
        assertTrue(hasCredIndicator, "Expected CREDENTIAL_THEFT indicator in Hinglish");
    }

    @Test
    @DisplayName("Should detect Grooming combo: Secrecy + Private Photo demand in English")
    public void testGroomingSecrecyPhotoEnglish() {
        String msg = "Don't tell anyone, send your private photo and turn on your camera.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, result.getVerdict());
        boolean hasSecrecy = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.SECRECY_PRESSURE);
        boolean hasPrivacy = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.PRIVACY_INVASION);
        assertTrue(hasSecrecy && hasPrivacy, "Expected both SECRECY and PRIVACY_INVASION indicators");
    }

    @Test
    @DisplayName("Should detect Grooming combo: Secrecy + Platform Migration in Hinglish")
    public void testGroomingSecrecyPlatformHinglish() {
        String msg = "Mummy papa ko mat batana, telegram pe aao wahan chat karte hain";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, result.getVerdict());
        boolean hasSecrecy = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.SECRECY_PRESSURE);
        boolean hasPlatform = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.PLATFORM_MIGRATION);
        assertTrue(hasSecrecy && hasPlatform, "Expected both SECRECY and PLATFORM_MIGRATION indicators");
    }

    @Test
    @DisplayName("Should detect Coercion and Blackmail threat in English and Hinglish")
    public void testCoercionAndIntimidation() {
        String msgEnglish = "Do this right now or else I will post your photo and leak your chats.";
        MessageAnalysisResult resEn = analyzer.analyze(msgEnglish);
        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, resEn.getVerdict());

        String msgHinglish = "Warna sabko bata dunga school me, chupchap photo bhej";
        MessageAnalysisResult resHi = analyzer.analyze(msgHinglish);
        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, resHi.getVerdict());
    }

    @Test
    @DisplayName("Should detect Overlapping indicators (Robux scam + suspicious URL + password solicit)")
    public void testOverlappingIndicatorsScam() {
        String msg = "Claim 5000 free Robux right now before event ends! Send your password to http://robux-claim.top";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, result.getVerdict());
        assertTrue(result.getMatchedIndicators().size() >= 2, "Expected multiple indicators");

        boolean hasPrize = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.PRIZE_SCAM);
        boolean hasCred = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.CREDENTIAL_THEFT);
        boolean hasLink = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.SUSPICIOUS_LINK);

        assertTrue(hasPrize, "Should detect prize scam");
        assertTrue(hasCred, "Should detect credential solicit");
        assertTrue(hasLink, "Should detect suspicious link");
    }

    // =========================================================================
    // 2. SUSPICIOUS CASES (BE_CAREFUL)
    // =========================================================================

    @Test
    @DisplayName("Should flag Cyberbullying language as BE_CAREFUL with anti-harassment advice")
    public void testCyberbullyingHarassment() {
        String msg = "You are the worst player ever, nobody likes you. Delete your account right now.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.BE_CAREFUL, result.getVerdict());
        boolean hasBully = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.BULLYING_HARASSMENT);
        assertTrue(hasBully, "Expected BULLYING_HARASSMENT indicator");
        assertTrue(result.getExplanation().toLowerCase().contains("bullying") ||
                   result.getExplanation().toLowerCase().contains("hurtful"));
    }

    @Test
    @DisplayName("Should flag Urgent Payment / UPI Demands")
    public void testUrgentPaymentDemand() {
        String msg = "Urgent payment of Rs 500 required immediately or fine will be charged.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.BE_CAREFUL, result.getVerdict());
        boolean hasPayment = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.FINANCIAL_DEMAND);
        assertTrue(hasPayment, "Expected FINANCIAL_DEMAND indicator");
    }

    @Test
    @DisplayName("Should flag standalone Platform Migration without secrecy as BE_CAREFUL")
    public void testStandalonePlatformMigration() {
        String msg = "Hey let's move to telegram, chat there instead of here.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.BE_CAREFUL, result.getVerdict());
        boolean hasPlatform = result.getMatchedIndicators().stream()
                .anyMatch(i -> i.getCategory() == SafetyIndicatorCategory.PLATFORM_MIGRATION);
        assertTrue(hasPlatform, "Expected PLATFORM_MIGRATION indicator");
    }

    // =========================================================================
    // 3. BENIGN & MISLEADING KEYWORDS (FALSE POSITIVE PREVENTION)
    // =========================================================================

    @Test
    @DisplayName("Should NOT flag innocent password mention regarding school portal")
    public void testBenignPasswordMentionSchool() {
        String msg = "I forgot my password for the school homework portal, can you ask teacher for reset?";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.NO_FLAGS_DETECTED, result.getVerdict());
        assertTrue(result.getMatchedIndicators().isEmpty(), "Should have no warning indicators");
    }

    @Test
    @DisplayName("Should NOT flag innocent surprise birthday party secrecy")
    public void testBenignBirthdaySurpriseSecrecy() {
        String msg = "Tomorrow is Rahul's surprise birthday party, don't tell anyone because it is a secret gift!";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.NO_FLAGS_DETECTED, result.getVerdict());
        assertTrue(result.getMatchedIndicators().isEmpty(), "Benign celebration should not trigger secrecy alarm");
    }

    @Test
    @DisplayName("Should NOT flag innocent gaming chat")
    public void testBenignGamingChat() {
        String msg = "Hey let's play our favorite Roblox building game together after we finish school homework.";
        MessageAnalysisResult result = analyzer.analyze(msg);

        assertEquals(MessageRiskVerdict.NO_FLAGS_DETECTED, result.getVerdict());
        assertFalse(result.hasWarnings());
    }

    @Test
    @DisplayName("Should NOT flag ordinary sports and homework chat")
    public void testOrdinaryBenignMessages() {
        String msg1 = "Are you coming to football practice today afternoon? Bring the water bottle.";
        assertEquals(MessageRiskVerdict.NO_FLAGS_DETECTED, analyzer.analyze(msg1).getVerdict());

        String msg2 = "Science project assignment is due on Friday, let's work on Chapter 4 together.";
        assertEquals(MessageRiskVerdict.NO_FLAGS_DETECTED, analyzer.analyze(msg2).getVerdict());
    }

    // =========================================================================
    // 4. INSUFFICIENT CONTEXT & EDGE CASES
    // =========================================================================

    @Test
    @DisplayName("Should return INCONCLUSIVE for empty, blank, or null text")
    public void testEmptyOrNullInput() {
        MessageAnalysisResult resNull = analyzer.analyze(null);
        assertEquals(MessageRiskVerdict.INCONCLUSIVE, resNull.getVerdict());
        assertEquals(ProcessingStatus.INCONCLUSIVE, resNull.getStatus());

        MessageAnalysisResult resBlank = analyzer.analyze("    ");
        assertEquals(MessageRiskVerdict.INCONCLUSIVE, resBlank.getVerdict());
    }

    @Test
    @DisplayName("Should return INCONCLUSIVE for short or ambiguous inputs (never promises 100% safe)")
    public void testShortAmbiguousInputs() {
        String[] shortInputs = {"hi", "hello", "ok", "cool bro", "???", "👍😊"};
        for (String input : shortInputs) {
            MessageAnalysisResult res = analyzer.analyze(input);
            assertEquals(MessageRiskVerdict.INCONCLUSIVE, res.getVerdict(),
                    "Short input '" + input + "' should be INCONCLUSIVE, not marked clean");
            assertEquals(ProcessingStatus.INCONCLUSIVE, res.getStatus());
            assertTrue(res.getExplanation().contains("short") || res.getExplanation().contains("context"));
        }
    }

    @Test
    @DisplayName("Should correctly analyze long multi-paragraph messages")
    public void testLongMultiParagraphMessage() {
        String longMsg = "Hey buddy! Hope you are doing great.\n\n" +
                "I found this amazing website where we can claim 5000 free Robux before today's deadline.\n" +
                "All you have to do is send your password and 6-digit OTP code to unlock it.\n\n" +
                "Mummy papa ko mat batana, keep this secret between us ok?";

        MessageAnalysisResult res = analyzer.analyze(longMsg);
        assertEquals(MessageRiskVerdict.WARNING_SIGNS_DETECTED, res.getVerdict());
        assertTrue(res.getCharacterCount() > 200);
        assertTrue(res.getWordCount() > 40);
        assertTrue(res.getMatchedIndicators().size() >= 2);
    }

    // =========================================================================
    // 5. TEST SET BENCHMARK (MEASURING FALSE POSITIVES & FALSE NEGATIVES)
    // =========================================================================

    private static class TestCase {
        final String text;
        final MessageRiskVerdict expectedVerdict;
        final String label;

        TestCase(String text, MessageRiskVerdict expectedVerdict, String label) {
            this.text = text;
            this.expectedVerdict = expectedVerdict;
            this.label = label;
        }
    }

    @Test
    @DisplayName("Documented Benchmark Test Set: False Positives & False Negatives")
    public void testBenchmarkDatasetMetrics() {
        List<TestCase> benchmarkCases = List.of(
                // True Positives (High Risk / Warning Signs)
                new TestCase("Send me your 6-digit OTP code immediately", MessageRiskVerdict.WARNING_SIGNS_DETECTED, "TP: OTP solicit"),
                new TestCase("Don't tell your mom, send your private photo now", MessageRiskVerdict.WARNING_SIGNS_DETECTED, "TP: Secrecy + Photo"),
                new TestCase("Mummy papa ko mat batana, telegram pe aao", MessageRiskVerdict.WARNING_SIGNS_DETECTED, "TP: Secrecy + Telegram"),
                new TestCase("Give your login password for free Robux: http://robux-claim.top", MessageRiskVerdict.WARNING_SIGNS_DETECTED, "TP: Credential + Scam URL"),
                new TestCase("Warna sabko bata dunga school me photo bhej", MessageRiskVerdict.WARNING_SIGNS_DETECTED, "TP: Coercion + Photo"),

                // True Positives (Suspicious / Be Careful)
                new TestCase("Claim 5000 free Robux right now before the event ends!", MessageRiskVerdict.BE_CAREFUL, "TP: Prize scam"),
                new TestCase("You are the worst player ever, nobody in class likes you.", MessageRiskVerdict.BE_CAREFUL, "TP: Bullying"),
                new TestCase("Urgent payment of Rs 500 required or fine charged", MessageRiskVerdict.BE_CAREFUL, "TP: Payment demand"),
                new TestCase("Message me on Snapchat instead of here", MessageRiskVerdict.BE_CAREFUL, "TP: Platform migration"),

                // True Negatives (Benign / No Flags)
                new TestCase("Tomorrow is Rahul's surprise birthday party, keep it a secret gift", MessageRiskVerdict.NO_FLAGS_DETECTED, "TN: Birthday secret"),
                new TestCase("I forgot my password to school portal, can you ask teacher for reset?", MessageRiskVerdict.NO_FLAGS_DETECTED, "TN: Portal password reset"),
                new TestCase("Hey! Are you done with the science project homework?", MessageRiskVerdict.NO_FLAGS_DETECTED, "TN: Homework discussion"),
                new TestCase("Let's play soccer during lunch break tomorrow at school", MessageRiskVerdict.NO_FLAGS_DETECTED, "TN: Sports invitation"),
                new TestCase("Did you buy the birthday gift for mom yet?", MessageRiskVerdict.NO_FLAGS_DETECTED, "TN: Birthday gift for mom"),

                // Inconclusive (Short / Ambiguous)
                new TestCase("ok", MessageRiskVerdict.INCONCLUSIVE, "Inconclusive: short single word"),
                new TestCase("hello there", MessageRiskVerdict.INCONCLUSIVE, "Inconclusive: greeting"),
                new TestCase("👍", MessageRiskVerdict.INCONCLUSIVE, "Inconclusive: single emoji")
        );

        int falsePositives = 0;
        int falseNegatives = 0;
        int total = benchmarkCases.size();

        for (TestCase tc : benchmarkCases) {
            MessageAnalysisResult res = analyzer.analyze(tc.text);

            boolean isExpectedNegative = tc.expectedVerdict == MessageRiskVerdict.NO_FLAGS_DETECTED;
            boolean isActualPositive = res.getVerdict() == MessageRiskVerdict.WARNING_SIGNS_DETECTED || res.getVerdict() == MessageRiskVerdict.BE_CAREFUL;

            if (isExpectedNegative && isActualPositive) {
                falsePositives++;
                System.err.println("FALSE POSITIVE on [" + tc.label + "]: " + tc.text);
            }

            boolean isExpectedPositive = tc.expectedVerdict == MessageRiskVerdict.WARNING_SIGNS_DETECTED || tc.expectedVerdict == MessageRiskVerdict.BE_CAREFUL;
            boolean isActualNegative = res.getVerdict() == MessageRiskVerdict.NO_FLAGS_DETECTED;

            if (isExpectedPositive && isActualNegative) {
                falseNegatives++;
                System.err.println("FALSE NEGATIVE on [" + tc.label + "]: " + tc.text);
            }

            assertEquals(tc.expectedVerdict, res.getVerdict(), "Failed on benchmark test: " + tc.label);
        }

        System.out.printf("Benchmark Results: Total=%d, False Positives=%d (0%%), False Negatives=%d (0%%)%n",
                total, falsePositives, falseNegatives);
        assertEquals(0, falsePositives, "False Positives must be 0 on documented benchmark set");
        assertEquals(0, falseNegatives, "False Negatives must be 0 on documented benchmark set");
    }
}
