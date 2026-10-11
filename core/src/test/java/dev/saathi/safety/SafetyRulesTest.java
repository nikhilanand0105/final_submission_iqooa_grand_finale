package dev.saathi.safety;

import dev.saathi.safety.SafetyTypes.SelfHarmKind;
import dev.saathi.safety.SafetyTypes.Severity;
import dev.saathi.safety.SafetyTypes.ThreatKind;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Synthetic fixtures only. Variants and benign look-alikes show the result comes from content, not from a sample list. */
public class SafetyRulesTest {

    private static ThreatKind threat(String s) { return ThreatKind.valueOf(SafetyRules.threat(s).kind); }
    private static Severity threatSev(String s) { return SafetyRules.threat(s).severity; }
    private static SelfHarmKind sh(String s) { return SelfHarmKind.valueOf(SafetyRules.selfHarm(s).kind); }
    private static Severity shSev(String s) { return SafetyRules.selfHarm(s).severity; }

    @Test
    void blackmailVariants() {
        String[] msgs = {
                "Send me 5000 rupees or I'll post your photos everywhere",
                "pay ₹2000 by tonight warna teri pics viral kar dunga",
                "If you don't send more pics I will share your chats with your school",
                "Transfer money on UPI otherwise everyone sees your videos",
        };
        for (String m : msgs) {
            assertEquals(ThreatKind.BLACKMAIL, threat(m), m);
            assertEquals(Severity.HIGH, threatSev(m), m);
            assertFalse(SafetyRules.threat(m).evidence.isEmpty(), m);
        }
    }

    @Test
    void harmAndExposureThreats() {
        assertEquals(ThreatKind.HARM_THREAT, threat("I know where you live. I'll hurt you if you tell anyone"));
        assertEquals(Severity.HIGH, threatSev("I know where you live. I'll hurt you if you tell anyone"));
        assertEquals(ThreatKind.EXPOSURE_THREAT, threat("I will share your private chats with the whole class"));
        assertEquals(ThreatKind.HARM_THREAT, threat("school ke baad dekh lena, maar dunga"));
    }

    @Test
    void credentialAndPaymentCoercion() {
        assertEquals(ThreatKind.CREDENTIAL_DEMAND, threat("Give me the OTP now or I'll delete your account"));
        assertEquals(ThreatKind.CREDENTIAL_DEMAND, threat("OTP bata warna account band ho jayega"));
        assertEquals(ThreatKind.PAYMENT_COERCION, threat("Pay 500 rupees today otherwise your game ID gets banned"));
        assertEquals(ThreatKind.INTIMIDATION, threat("nobody likes you, go die"));
    }

    @Test
    void harmlessTextWithThreatWords() {
        assertEquals(Severity.LOW, threatSev("I'm going to kill you in the next round 😂"));
        assertEquals(ThreatKind.NONE, threat("My mom will kill me if I'm late lol"));
        assertEquals(ThreatKind.NONE, threat("The movie was about blackmail and revenge"));
        assertEquals(ThreatKind.NONE, threat("Can you send me the homework photos?"));
        assertEquals(ThreatKind.NONE, threat("See you at practice tomorrow"));
        assertEquals(ThreatKind.NONE, threat("Please share the photos from the trip with everyone in the family group"), "sharing request without threat");
    }

    @Test
    void personalSelfHarm() {
        assertEquals(SelfHarmKind.PERSONAL_IDEATION, sh("I want to die, nobody cares about me"));
        assertEquals(SelfHarmKind.PERSONAL_INTENT, sh("I'm going to kill myself tonight"));
        assertEquals(Severity.IMMINENT, shSev("I'm going to kill myself tonight"));
        assertEquals(SelfHarmKind.PERSONAL_IDEATION, sh("sach mein main marna chahti hoon"));
        assertEquals(SelfHarmKind.HELP_SEEKING, sh("I need help, I keep thinking about hurting myself"));
        assertEquals(SelfHarmKind.PERSONAL_IDEATION, sh("i dont want to live anymore"));
        assertEquals(SelfHarmKind.PERSONAL_INTENT, sh("I've decided, I have the pills. goodbye everyone"));
    }

    @Test
    void educationalNewsAndNegation() {
        assertEquals(SelfHarmKind.NEWS_OR_PREVENTION, sh("Research project on suicide prevention statistics in India"));
        assertEquals(SelfHarmKind.NEWS_OR_PREVENTION, sh("Police said the teen died by suicide; helpline numbers are below"));
        assertEquals(SelfHarmKind.INFORMATIONAL, sh("For my psychology homework: what are the warning signs of suicide?"));
        assertEquals(Severity.NONE, shSev("Research project on suicide prevention statistics in India"));
        assertEquals(SelfHarmKind.NONE, sh("I would never hurt myself, don't worry"));
        assertEquals(SelfHarmKind.NONE, sh("I'm dying of laughter at this video"));
        assertEquals(SelfHarmKind.NONE, sh("This homework is killing me"));
        assertEquals(SelfHarmKind.AMBIGUOUS, sh("my friend said he wants to kill himself"));
        assertEquals(SelfHarmKind.AMBIGUOUS, sh("suicide"));
    }

    @Test
    void hugeAndOddInputDoesNotBreak() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 2000; i++) b.append("lorem ipsum ");
        assertEquals(ThreatKind.NONE, threat(b.toString()));
        assertEquals(SelfHarmKind.NONE, sh(b.toString()));
        assertEquals(ThreatKind.NONE, threat(""));
        assertEquals(SelfHarmKind.NONE, sh(null));
    }
}
