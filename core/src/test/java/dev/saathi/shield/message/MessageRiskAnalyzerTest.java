package dev.saathi.shield.message;

import dev.saathi.model.ThreatSeverity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MessageRiskAnalyzerTest {

    private MessageRiskAnalyzer analyzer;

    @BeforeEach
    public void setUp() {
        analyzer = new RuleBasedMessageRiskAnalyzer();
    }

    @Test
    @DisplayName("Engine metadata and versioning are properly declared")
    public void testEngineMetadata() {
        assertEquals("saathi-ondevice-message-rules-v1.0", analyzer.getEngineId());
        assertEquals("2026.10", analyzer.getRulesVersion());

        MessageRiskAssessment assessment = analyzer.analyze("Hello world");
        assertEquals("saathi-ondevice-message-rules-v1.0", assessment.getEngineId());
        assertEquals("2026.10", assessment.getRulesVersion());
        assertNotNull(assessment.getLimitations());
        assertTrue(assessment.getLimitations().contains("Deterministic on-device heuristic engine"));
        assertTrue(assessment.getLimitations().contains("without making claims about an individual's character or intent"));
    }

    @Test
    @DisplayName("Positive English scam samples are accurately detected")
    public void testPositiveScamCases_English() {
        // 1. OTP Credential Theft
        MessageRiskAssessment r1 = analyzer.analyze(
                "Dear customer, please share the 6-digit OTP sent to your registered mobile number to verify your bank account."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r1.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r1.getSeverity());
        assertTrue(r1.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.CREDENTIAL_OTP_DEMAND));

        // 2. IndiaPost parcel sorting depot fee lure with shortlink
        MessageRiskAssessment r2 = analyzer.analyze(
                "Your IndiaPost package #IN8492 is held at sorting depot. Pay ₹25 address confirmation fee at bit.ly/del-track or item will be discarded today."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r2.getCategory());
        assertTrue(r2.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.LURE_REWARD_OR_SUSPENSION));
        assertTrue(r2.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT));

        // 3. Fake Bank Suspension Prompt
        MessageRiskAssessment r3 = analyzer.analyze(
                "Dear Customer, your SBI YONO account has been suspended due to pending KYC. Update PAN card at http://sbi-kyc.top to avoid card freeze."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r3.getCategory());
        assertTrue(r3.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.LURE_REWARD_OR_SUSPENSION));
        assertTrue(r3.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT));

        // 4. Remote Support Sideload Tool
        MessageRiskAssessment r4 = analyzer.analyze(
                "To resolve your refund issue, please install AnyDesk support app immediately on your phone."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r4.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r4.getSeverity());
        assertTrue(r4.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT));

        // 5. Digital Arrest Extortion
        MessageRiskAssessment r5 = analyzer.analyze(
                "This is Delhi Police Crime Branch. A digital arrest warrant has been issued against your Aadhaar. Do not disconnect the call."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r5.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r5.getSeverity());
        assertTrue(r5.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.AUTHORITY_IMPERSONATION));
        assertTrue(r5.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.ARTIFICIAL_URGENCY_PANIC));
    }

    @Test
    @DisplayName("Positive Hinglish scam samples are accurately detected")
    public void testPositiveScamCases_Hinglish() {
        // 1. Hinglish OTP demand
        MessageRiskAssessment r1 = analyzer.analyze(
                "Bhai jaldi se OTP bata do jo tere phone pe aaya hai, transaction complete karni hai."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r1.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r1.getSeverity());
        assertTrue(r1.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.CREDENTIAL_OTP_DEMAND));

        // 2. Accidental UPI Refund trap
        MessageRiskAssessment r2 = analyzer.analyze(
                "Bhai galti se maine aapke Google Pay number pe 5000 rupaye bhej diye hain. Please turant refund kar do emergency hai, hospital bill bharna hai!"
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r2.getCategory());
        assertTrue(r2.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.URGENT_PAYMENT_PRESSURE));

        // 3. Secrecy and Camera Coercion
        MessageRiskAssessment r3 = analyzer.analyze(
                "Yeh baat sirf hamare beech rahegi, kisi ko mat batana. Camera on kar ke aaja call pe, parents ko pata nahi chalna chahiye."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r3.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r3.getSeverity());
        assertTrue(r3.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.SECRECY_ISOLATION));
        assertTrue(r3.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.SENSITIVE_DATA_REQUEST));

        // 4. Police Station / Jail Coercion
        MessageRiskAssessment r4 = analyzer.analyze(
                "Police station se bol raha hu, tere khilaaf case darz ho gaya hai, turant paise bhej varna jail jana padega."
        );
        assertEquals(MessageRiskCategory.HIGH_RISK, r4.getCategory());
        assertEquals(ThreatSeverity.CRITICAL, r4.getSeverity());
        assertTrue(r4.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.AUTHORITY_IMPERSONATION));
        assertTrue(r4.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.COERCION_OR_THREAT));

        // 5. Electricity Disconnection threat
        MessageRiskAssessment r5 = analyzer.analyze(
                "Aapki bijli ka connection aaj raat band kar diya jayega. Bill payment turant karein."
        );
        assertTrue(r5.getCategory() == MessageRiskCategory.HIGH_RISK || r5.getCategory() == MessageRiskCategory.SUSPICIOUS);
        assertTrue(r5.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.LURE_REWARD_OR_SUSPENSION));
    }

    @Test
    @DisplayName("Benign conversations and legitimate alerts produce no false positives")
    public void testNegativeBenignCases() {
        // 1. Everyday conversational chat
        MessageRiskAssessment r1 = analyzer.analyze(
                "Hi Amit, are we meeting for coffee today at 5 PM near Connaught Place? Let me know!"
        );
        assertEquals(MessageRiskCategory.LOW_RISK, r1.getCategory());
        assertEquals(0, r1.getIndicatorCount());

        // 2. Birthday surprise secret (benign counter-signal)
        MessageRiskAssessment r2 = analyzer.analyze(
                "Kal Rahul ki surprise birthday party hai, kisi ko mat batana please!"
        );
        assertEquals(MessageRiskCategory.LOW_RISK, r2.getCategory());
        assertEquals(0, r2.getIndicatorCount());

        // 3. School homework chat
        MessageRiskAssessment r3 = analyzer.analyze(
                "Hey Priya, can you send the science homework project notes before tomorrow's exam prep?"
        );
        assertEquals(MessageRiskCategory.LOW_RISK, r3.getCategory());
        assertEquals(0, r3.getIndicatorCount());

        // 4. Educational safety warning (does not demand OTP, reminds user NOT to share)
        MessageRiskAssessment r4 = analyzer.analyze(
                "Safety Alert from Bank: Never share your OTP, UPI PIN, or passwords with anyone claiming to be bank staff."
        );
        assertEquals(MessageRiskCategory.LOW_RISK, r4.getCategory());
        assertEquals(0, r4.getIndicatorCount());

        // 5. Legitimate bank credit transactional SMS (informational receipt without urgency or action links)
        MessageRiskAssessment r5 = analyzer.analyze(
                "Dear Customer, your Account XX4821 is credited with INR 5,000 on 10-Oct-26 by UPI Ref 98472. Available balance INR 24,500."
        );
        assertEquals(MessageRiskCategory.LOW_RISK, r5.getCategory());
        assertEquals(0, r5.getIndicatorCount());
    }

    @Test
    @DisplayName("Ambiguous messages are properly classified as AMBIGUOUS without false panic")
    public void testAmbiguousCases() {
        // Informal casual lunch money request without urgency or threat
        MessageRiskAssessment r1 = analyzer.analyze(
                "Can you lend me 500 rupees for college canteen lunch? Will pay back tomorrow morning."
        );
        // Should not be flagged as HIGH_RISK or SCAM
        assertNotEquals(MessageRiskCategory.HIGH_RISK, r1.getCategory());

        // Mention of password reset in casual chat
        MessageRiskAssessment r2 = analyzer.analyze(
                "I forgot my password again haha, will visit the bank branch tomorrow to reset it."
        );
        assertNotEquals(MessageRiskCategory.HIGH_RISK, r2.getCategory());
    }

    @Test
    @DisplayName("Balanced test matrix verification measuring False Positives and False Negatives")
    public void testMetrics_AccuracyFalsePositivesFalseNegatives() {
        String[] trueScamSamples = {
                "Share your SBI netbanking password and OTP to unfreeze your account.",
                "IndiaPost courier package held at sorting depot. Pay ₹25 confirmation fee at bit.ly/test-track",
                "Your electricity power will be disconnected tonight. Pay unpaid bill immediately.",
                "Congratulations! You won ₹25,00,000 lottery in KBC. Contact officer now.",
                "Install AnyDesk app to verify your KYC details right now.",
                "This is CBI Delhi. Digital arrest warrant issued. Do not hang up the call.",
                "Bhai OTP bhej jaldi jo tere phone pe aaya hai.",
                "Galti se 5000 rupaye bhej diye hain, turant refund karo emergency hai!",
                "Yeh baat kisi ko mat batana, camera on kar video call pe, parents ko mat bolna.",
                "Police station se bol raha hu, jail jana padega agar paise transfer nahi kiye."
        };

        String[] trueBenignSamples = {
                "Hi mom, I reached the railway station safely, will call you in an hour.",
                "Kal Rahul ki surprise birthday party hai, kisi ko mat batana!",
                "Are you coming to office today or working from home?",
                "Bank safety tip: Never share your OTP or PIN with anyone.",
                "Account XX1234 credited with INR 1,500 on 10-Oct-26 by UPI. Avl Bal INR 12,000.",
                "Please bring bread and milk while coming back home.",
                "Can you share the lecture slides for our machine learning class?",
                "Happy Diwali to you and your family! Have a wonderful celebration.",
                "Doctor appointment is scheduled for tomorrow at 4:30 PM.",
                "Thank you for ordering on Swiggy. Your food is on the way."
        };

        int falsePositives = 0;
        int falseNegatives = 0;

        for (String scam : trueScamSamples) {
            MessageRiskAssessment res = analyzer.analyze(scam);
            if (!res.isThreat()) {
                falseNegatives++;
                System.err.println("False Negative detected on: " + scam);
            }
        }

        for (String benign : trueBenignSamples) {
            MessageRiskAssessment res = analyzer.analyze(benign);
            if (res.isThreat()) {
                falsePositives++;
                System.err.println("False Positive detected on: " + benign);
            }
        }

        assertEquals(0, falseNegatives, "Expected 0 false negatives on benchmark scam set");
        assertEquals(0, falsePositives, "Expected 0 false positives on benchmark benign set");
    }

    @Test
    @DisplayName("Unicode evasion resistance: zero-width characters and full-width tokens")
    public void testUnicodeAndZeroWidthBypassResilience() {
        // Zero-width space / ZWNJ inserted between letters to evade keyword detection: O​T​P b​h​e​j​o
        String zeroWidthObfuscated = "O\u200BT\u200CP b\u200Dh\u200Ce\u200Dj\u200Do jaldi se";
        MessageRiskAssessment r1 = analyzer.analyze(zeroWidthObfuscated);
        assertEquals(MessageRiskCategory.HIGH_RISK, r1.getCategory());
        assertTrue(r1.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.CREDENTIAL_OTP_DEMAND));

        // Fullwidth Unicode characters: ＳＥＮＤ　ＯＴＰ
        String fullwidthText = "Ｐｌｅａｓｅ　ｓｅｎｄ　ＯＴＰ　ｉｍｍｅｄｉａｔｅｌｙ";
        MessageRiskAssessment r2 = analyzer.analyze(fullwidthText);
        assertEquals(MessageRiskCategory.HIGH_RISK, r2.getCategory());
        assertTrue(r2.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.CREDENTIAL_OTP_DEMAND));
    }

    @Test
    @DisplayName("Input boundary checks: empty, blank, short, and very long text")
    public void testInputBoundaryRobustness() {
        // Null
        MessageRiskAssessment rNull = analyzer.analyze(null);
        assertEquals(MessageRiskCategory.INSUFFICIENT_INPUT, rNull.getCategory());
        assertEquals(0, rNull.getIndicatorCount());

        // Empty
        MessageRiskAssessment rEmpty = analyzer.analyze("");
        assertEquals(MessageRiskCategory.INSUFFICIENT_INPUT, rEmpty.getCategory());

        // Whitespace only
        MessageRiskAssessment rWhitespace = analyzer.analyze("   \t\r\n   ");
        assertEquals(MessageRiskCategory.INSUFFICIENT_INPUT, rWhitespace.getCategory());

        // Single character
        MessageRiskAssessment rShort = analyzer.analyze("A");
        assertEquals(MessageRiskCategory.INSUFFICIENT_INPUT, rShort.getCategory());

        // Very long text (5000+ characters) with buried scam indicator
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            sb.append("This is an ordinary long paragraph discussing general topics in an extended email thread. ");
        }
        sb.append("However, please share OTP immediately to verify your account credentials. ");
        for (int i = 0; i < 50; i++) {
            sb.append("Continuing ordinary discussion without any further urgent actions or demands. ");
        }

        MessageRiskAssessment rLong = analyzer.analyze(sb.toString());
        assertEquals(MessageRiskCategory.HIGH_RISK, rLong.getCategory());
        assertTrue(rLong.getIndicators().stream().anyMatch(i -> i.getType() == MessageIndicatorType.CREDENTIAL_OTP_DEMAND));
        assertTrue(rLong.getInputLength() > 5000);
    }

    @Test
    @DisplayName("Verifiable evidence spans are strictly grounded in user input")
    public void testVerifiableEvidenceSpans() {
        String msg = "Your IndiaPost package is held. Pay ₹25 confirmation fee at bit.ly/del-track";
        MessageRiskAssessment res = analyzer.analyze(msg);

        assertFalse(res.getIndicators().isEmpty());
        for (MessageIndicator ind : res.getIndicators()) {
            assertNotNull(ind.getEvidenceSpan(), "Evidence span must not be null");
            assertNotNull(ind.getEvidenceText(), "Evidence text must not be null");
            assertFalse(ind.getEvidenceText().isEmpty(), "Evidence text must not be empty");
            assertTrue(msg.toLowerCase().contains(ind.getEvidenceText().toLowerCase()),
                    "Evidence text '" + ind.getEvidenceText() + "' must be present in source input");
        }
    }
}
