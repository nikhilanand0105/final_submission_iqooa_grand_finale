package dev.guardianai.shield.message;

import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maintainable, versioned rules catalogue for message risk analysis.
 * Implements context-aware regex patterns for English and Romanised Hindi (Hinglish).
 */
public final class MessageRulesCatalogue {

    public static final String ENGINE_ID = "guardianai-ondevice-message-rules-v1.0";
    public static final String RULES_VERSION = "2026.10";

    // -------------------------------------------------------------
    // 1. CREDENTIAL & OTP SOLICITATION PATTERNS
    // -------------------------------------------------------------
    private static final Pattern PATTERN_CREDENTIAL_ENG = Pattern.compile(
            "(?i)\\b(?:share|send|enter|give|provide|verify|tell\\s+me|input)\\b.{0,30}\\b(?:otp|one\\s*time\\s*password|upi\\s*pin|atm\\s*pin|login\\s*password|cvv|secret\\s*code|netbanking\\s*password)\\b"
    );

    private static final Pattern PATTERN_CREDENTIAL_HINGLISH = Pattern.compile(
            "(?i)\\b(?:otp|pin|password|cvv)\\b.{0,30}\\b(?:bhej(?:o|na)?|bata(?:o|na|do)?|share\\s*kar(?:o|na)?|daal(?:o|e|na)?|send\\s*kar(?:o|na)?)\\b"
    );

    // Negative counter-signals for OTP (e.g., educational warnings: "never share your OTP")
    private static final Pattern PATTERN_OTP_WARNING = Pattern.compile(
            "(?i)\\b(?:never|don't|do\\s*not|kabhi\\s*mat|mat)\\b.{0,25}\\b(?:share|tell|give|bata|bhej)\\b.{0,25}\\b(?:otp|pin|password)\\b"
    );

    // -------------------------------------------------------------
    // 2. URGENT PAYMENT & FUND-TRANSFER PRESSURE
    // -------------------------------------------------------------
    private static final Pattern PATTERN_PAYMENT_PRESSURE_ENG = Pattern.compile(
            "(?i)\\b(?:send|transfer|pay|refund|deposit)\\b.{0,30}\\b(?:(?:rs\\.?|inr|₹)\\s*\\d+|\\d+\\s*(?:rs|rupees)|money|amount|funds)\\b.{0,30}\\b(?:immediately|urgently|now|today|emergency|within\\s*\\d+\\s*hours?)\\b"
    );

    private static final Pattern PATTERN_ACCIDENTAL_REFUND_SCAM = Pattern.compile(
            "(?i)\\b(?:accidentally|by\\s*mistake|galti\\s*se)\\b.{0,90}\\b(?:sent|transferred|bhej\\s*diye|gpay|phonepe|number)\\b.{0,60}\\b(?:refund|return|send\\s*back|wapas)\\b"
    );

    private static final Pattern PATTERN_PAYMENT_PRESSURE_HINGLISH = Pattern.compile(
            "(?i)\\b(?:turant|jaldi|emergency)\\b.{0,40}\\b(?:paise|amount|rupaye|gpay|phonepe|refund)\\b.{0,40}\\b(?:bhej(?:o|na)?|transfer\\s*kar(?:o|na)?|daal(?:o|na)?|kar(?:o|do|na|de)?|wapas\\s*kar(?:o|de)?)\\b"
    );

    // -------------------------------------------------------------
    // 3. PRIZE, PARCEL & SUSPENSION LURES
    // -------------------------------------------------------------
    private static final Pattern PATTERN_SUSPENSION_LURE = Pattern.compile(
            "(?i)\\b(?:account|yono|card|sim|connection|pan)\\b.{0,35}\\b(?:suspended|blocked|frozen|terminated|deactivated|expire|block\\s*ho\\s*jayega|freeze)\\b"
    );

    private static final Pattern PATTERN_ELECTRICITY_LURE = Pattern.compile(
            "(?i)\\b(?:electricity|power|bijli)\\b.{0,40}\\b(?:disconnected|cut|band)\\b.{0,35}\\b(?:tonight|today|aaj\\s*raat|immediately|turant)\\b"
    );

    private static final Pattern PATTERN_PRIZE_LURE = Pattern.compile(
            "(?i)\\b(?:congratulations|winner|won|lottery|kbc|inam)\\b.{0,50}\\b(?:won|crorepati|prize|reward|gift\\s*voucher|\\d+\\s*(?:lakh|crore)|₹\\s*\\d+|lottery)\\b"
    );

    private static final Pattern PATTERN_PARCEL_LURE = Pattern.compile(
            "(?i)\\b(?:parcel|package|indiapost|courier|consignment)\\b.{0,40}\\b(?:held|stuck|sorting\\s*depot|customs|undelivered|address\\s*confirmation|discarded)\\b"
    );

    // -------------------------------------------------------------
    // 4. SUSPICIOUS LINKS & ATTACHMENT / REMOTE-TOOL DEMANDS
    // -------------------------------------------------------------
    private static final Pattern PATTERN_SHORTLINKS = Pattern.compile(
            "(?i)\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd|cutt\\.ly|rb\\.gy)/[a-zA-Z0-9_\\-]+"
    );

    private static final Pattern PATTERN_DISPOSABLE_URLS = Pattern.compile(
            "(?i)(?:https?://)?\\b[a-zA-Z0-9.\\-]+\\.(?:top|xyz|club|click|work|app|tk|vip|gq|ml|cf|live|site)(?::\\d+)?(?:/\\S*)?"
    );

    private static final Pattern PATTERN_REMOTE_TOOLS_APK = Pattern.compile(
            "(?i)\\b(?:install|download|open)\\b.{0,30}\\b(?:anydesk|teamviewer|quicksupport|apk|support\\s*app|rustdesk|screen\\s*share)\\b"
    );

    // -------------------------------------------------------------
    // 5. AUTHORITY & INSTITUTIONAL IMPERSONATION
    // -------------------------------------------------------------
    private static final Pattern PATTERN_AUTHORITY_ENG = Pattern.compile(
            "(?i)\\b(?:cbi|crime\\s*branch|delhi\\s*police|mumbai\\s*police|cyber\\s*police|trai|rbi|customs\\s*department|narcotics\\s*control|interpol|enforcement\\s*directorate)\\b"
    );

    private static final Pattern PATTERN_DIGITAL_ARREST = Pattern.compile(
            "(?i)\\bdigital\\s*arrest\\b"
    );

    private static final Pattern PATTERN_BANK_AUTHORITY = Pattern.compile(
            "(?i)\\b(?:sbi|hdfc|icici|axis|rbi)\\b.{0,25}\\b(?:head\\s*office|security\\s*team|fraud\\s*department|manager|nodal\\s*officer)\\b"
    );

    private static final Pattern PATTERN_AUTHORITY_HINGLISH = Pattern.compile(
            "(?i)\\b(?:police\\s*station\\s*se|cbi\\s*officer|customs\\s*mein\\s*drugs|trai\\s*ki\\s*taraf\\s*se)\\b"
    );

    // -------------------------------------------------------------
    // 6. SECRECY & ISOLATION COERCION
    // -------------------------------------------------------------
    private static final Pattern PATTERN_SECRECY_ENG = Pattern.compile(
            "(?i)\\b(?:don't|do\\s*not)\\s+(?:tell|inform|share\\s+with)\\s+(?:anyone|parents|family|police|friends|others)\\b"
    );

    private static final Pattern PATTERN_SECRECY_CONFIDENTIAL = Pattern.compile(
            "(?i)\\b(?:keep\\s+this\\s+secret|strictly\\s+confidential\\s+investigation|secret\\s+between\\s+us)\\b"
    );

    private static final Pattern PATTERN_SECRECY_HINGLISH = Pattern.compile(
            "(?i)\\b(?:kisi\\s*ko\\s*mat\\s*batana|kisi\\s*ko\\s*mat\\s*bolna|kisi\\s*se\\s*share\\s*mat\\s*karna|parents\\s*ko\\s*mat\\s*(?:batana|bolna)|mummy\\s*papa\\s*ko\\s*mat|akele\\s*mein\\s*(?:baat|raho))\\b"
    );

    // -------------------------------------------------------------
    // 7. COERCION, ARREST THREATS & INTIMIDATION
    // -------------------------------------------------------------
    private static final Pattern PATTERN_LEGAL_THREAT_ENG = Pattern.compile(
            "(?i)\\b(?:fir\\s*(?:registered|lodged)|arrest\\s*warrant|court\\s*summons|non-bailable|police\\s*raid|legal\\s*action\\s*initiated|jail\\s*term)\\b"
    );

    private static final Pattern PATTERN_LEGAL_THREAT_HINGLISH = Pattern.compile(
            "(?i)\\b(?:jail\\s*jana\\s*padega|police\\s*bhej\\s*rahe|arrest\\s*kar\\s*lenge|ghar\\s*pe\\s*police\\s*aayegi|case\\s*darz\\s*ho\\s*gaya)\\b"
    );

    // -------------------------------------------------------------
    // 8. SENSITIVE DATA & CAMERA DEMANDS
    // -------------------------------------------------------------
    private static final Pattern PATTERN_ID_DEMAND = Pattern.compile(
            "(?i)\\b(?:send|share|upload|provide|update|bhej(?:o)?)\\b.{0,30}\\b(?:aadhaar|pan\\s*card|credit\\s*card|debit\\s*card|passport|bank\\s*passbook|kyc)\\b"
    );

    private static final Pattern PATTERN_CAMERA_EXPLOITATION = Pattern.compile(
            "(?i)\\b(?:turn\\s*on\\s*camera|camera\\s*on\\s*kar|video\\s*call\\s*pe\\s*aaja|send\\s*(?:your\\s*)?(?:private\\s*)?photo|photo\\s*bhej(?:o)?)\\b"
    );

    // -------------------------------------------------------------
    // 9. ARTIFICIAL URGENCY & CALL-HANGUP PROHIBITION
    // -------------------------------------------------------------
    private static final Pattern PATTERN_HANGUP_PREVENTION = Pattern.compile(
            "(?i)\\b(?:do\\s*not\\s*disconnect|do\\s*not\\s*hang\\s*up|call\\s*cut\\s*mat\\s*karna|phone\\s*mat\\s*kaatna|stay\\s*on\\s*(?:the\\s*)?call)\\b"
    );

    private static final Pattern PATTERN_TIGHT_TIME_PRESSURE = Pattern.compile(
            "(?i)\\b(?:within\\s*(?:5|10|15|30)\\s*minutes?|immediate\\s*action\\s*within|aaj\\s*hi\\s*turant|\\d+\\s*minute\\s*ke\\s*andar)\\b"
    );

    // -------------------------------------------------------------
    // BENIGN CONTEXT COUNTER-SIGNALS
    // -------------------------------------------------------------
    private static final Pattern PATTERN_BENIGN_CELEBRATION = Pattern.compile(
            "(?i)\\b(?:surprise\\s*(?:party|gift|present)|birthday\\s*(?:party|surprise|gift)|homework|school\\s*project|exam\\s*prep)\\b"
    );

    private static final Pattern PATTERN_BENIGN_BANK_ALERT = Pattern.compile(
            "(?i)\\b(?:a/c|account)\\b.{0,30}\\b(?:credited|debited)\\b.{0,30}\\b(?:inr|rs\\.?)\\b"
    );

    private MessageRulesCatalogue() {
        // Static rules catalogue
    }

    public static List<MessageIndicator> evaluateRules(MessageNormalizer.ProcessedText processed) {
        List<MessageIndicator> indicators = new ArrayList<>();
        String text = processed.getCleanText();
        if (text.isEmpty()) {
            return indicators;
        }

        // Check if message is purely an educational warning about NOT sharing OTPs
        boolean isEducationalOtpWarning = PATTERN_OTP_WARNING.matcher(text).find();

        // 1. Credential & OTP Solicitations
        if (!isEducationalOtpWarning) {
            checkPattern(text, PATTERN_CREDENTIAL_ENG, indicators,
                    "RULE_CREDENTIAL_OTP_DEMAND",
                    MessageIndicatorType.CREDENTIAL_OTP_DEMAND,
                    ThreatSeverity.CRITICAL,
                    "Credential or One-Time Passcode (OTP) Solicitation",
                    "The message requests an OTP, PIN, password, or security code. Legitimate institutions never request confidential security credentials over SMS or chat."
            );
            checkPattern(text, PATTERN_CREDENTIAL_HINGLISH, indicators,
                    "RULE_CREDENTIAL_OTP_DEMAND",
                    MessageIndicatorType.CREDENTIAL_OTP_DEMAND,
                    ThreatSeverity.CRITICAL,
                    "Credential or One-Time Passcode (OTP) Solicitation (Hinglish)",
                    "Message contains instructions demanding that you send or enter an OTP, PIN, or password. Disclosing OTPs enables unauthorized financial transfers."
            );
        }

        // 2. Urgent Payment Pressure
        checkPattern(text, PATTERN_PAYMENT_PRESSURE_ENG, indicators,
                    "RULE_URGENT_PAYMENT_PRESSURE",
                    MessageIndicatorType.URGENT_PAYMENT_PRESSURE,
                    ThreatSeverity.HIGH,
                    "Urgent Money Transfer or Fine Pressure",
                    "The message demands rapid financial payment or transfer with artificial deadlines. Fraudsters use urgency to prevent careful verification."
        );
        checkPattern(text, PATTERN_ACCIDENTAL_REFUND_SCAM, indicators,
                    "RULE_URGENT_PAYMENT_PRESSURE",
                    MessageIndicatorType.URGENT_PAYMENT_PRESSURE,
                    ThreatSeverity.HIGH,
                    "Accidental UPI Transfer / Emergency Refund Trap",
                    "The message claims funds were sent by mistake and requests an immediate refund. Fraudsters frequently manipulate fake payment screenshots or request reverse UPI payments."
        );
        checkPattern(text, PATTERN_PAYMENT_PRESSURE_HINGLISH, indicators,
                    "RULE_URGENT_PAYMENT_PRESSURE",
                    MessageIndicatorType.URGENT_PAYMENT_PRESSURE,
                    ThreatSeverity.HIGH,
                    "Urgent Money Transfer Demand (Hinglish)",
                    "Urgent demand for funds or UPI transfer with emergency pretext observed."
        );

        // 3. Prize, Parcel & Suspension Lures
        checkPattern(text, PATTERN_SUSPENSION_LURE, indicators,
                    "RULE_LURE_REWARD_SUSPENSION",
                    MessageIndicatorType.LURE_REWARD_OR_SUSPENSION,
                    ThreatSeverity.HIGH,
                    "Account Suspension or Card Freeze Threat",
                    "Claims that your bank account, KYC, or card is suspended. Banks do not freeze accounts via unauthenticated SMS prompts."
        );
        checkPattern(text, PATTERN_ELECTRICITY_LURE, indicators,
                    "RULE_LURE_REWARD_SUSPENSION",
                    MessageIndicatorType.LURE_REWARD_OR_SUSPENSION,
                    ThreatSeverity.HIGH,
                    "Utility / Electricity Disconnection Threat",
                    "Claims that your power or connection will be disconnected tonight. This is a widespread phishing template designed to induce immediate panic."
        );
        checkPattern(text, PATTERN_PRIZE_LURE, indicators,
                    "RULE_LURE_REWARD_SUSPENSION",
                    MessageIndicatorType.LURE_REWARD_OR_SUSPENSION,
                    ThreatSeverity.HIGH,
                    "Unsolicited Lottery or Prize Reward Lure",
                    "Claims of winning lotteries, cash prizes, or reward points. Legitimate lotteries do not notify winners via unexpected SMS messages."
        );
        checkPattern(text, PATTERN_PARCEL_LURE, indicators,
                    "RULE_LURE_REWARD_SUSPENSION",
                    MessageIndicatorType.LURE_REWARD_OR_SUSPENSION,
                    ThreatSeverity.HIGH,
                    "Parcel Delivery / Sorting Depot Fee Lure",
                    "Claims a postal package is held for small confirmation fees or address updates. Attackers use nominal fees to harvest debit card numbers."
        );

        // 4. Suspicious Links & Attachment Demands
        checkPattern(text, PATTERN_SHORTLINKS, indicators,
                    "RULE_UNTRUSTED_LINK_ATTACHMENT",
                    MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT,
                    ThreatSeverity.HIGH,
                    "Obfuscated Shortened Link (bit.ly / URL Shortener)",
                    "Message contains a shortened URL masking the actual destination server."
        );
        checkPattern(text, PATTERN_DISPOSABLE_URLS, indicators,
                    "RULE_UNTRUSTED_LINK_ATTACHMENT",
                    MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT,
                    ThreatSeverity.HIGH,
                    "Suspicious or Disposable Web Address",
                    "Web link points to a high-risk or disposable top-level domain frequently associated with temporary scam landings."
        );
        checkPattern(text, PATTERN_REMOTE_TOOLS_APK, indicators,
                    "RULE_UNTRUSTED_LINK_ATTACHMENT",
                    MessageIndicatorType.UNTRUSTED_LINK_OR_ATTACHMENT,
                    ThreatSeverity.CRITICAL,
                    "Remote-Access Tool or Unverified App Sideload Demand",
                    "Instructs you to install tools like AnyDesk, TeamViewer, or an APK. Screen-sharing apps allow remote attackers full device takeover."
        );

        // 5. Authority & Institutional Impersonation
        checkPattern(text, PATTERN_AUTHORITY_ENG, indicators,
                    "RULE_AUTHORITY_IMPERSONATION",
                    MessageIndicatorType.AUTHORITY_IMPERSONATION,
                    ThreatSeverity.HIGH,
                    "Law Enforcement or Regulatory Agency Impersonation",
                    "Claims to originate from police, CBI, TRAI, RBI, or customs agencies. Real law enforcement conducts formal proceedings, not SMS ultimatums."
        );
        checkPattern(text, PATTERN_DIGITAL_ARREST, indicators,
                    "RULE_AUTHORITY_IMPERSONATION",
                    MessageIndicatorType.AUTHORITY_IMPERSONATION,
                    ThreatSeverity.CRITICAL,
                    "Fraudulent 'Digital Arrest' Coercion",
                    "Refers to 'Digital Arrest'—a known extortion tactic. Indian law and law enforcement agencies do not possess any legal concept of 'Digital Arrest'."
        );
        checkPattern(text, PATTERN_BANK_AUTHORITY, indicators,
                    "RULE_AUTHORITY_IMPERSONATION",
                    MessageIndicatorType.AUTHORITY_IMPERSONATION,
                    ThreatSeverity.HIGH,
                    "Financial Institution / Security Department Impersonation",
                    "Claims to originate from a bank's security or fraud team."
        );
        checkPattern(text, PATTERN_AUTHORITY_HINGLISH, indicators,
                    "RULE_AUTHORITY_IMPERSONATION",
                    MessageIndicatorType.AUTHORITY_IMPERSONATION,
                    ThreatSeverity.HIGH,
                    "Authority Impersonation Claim (Hinglish)",
                    "Claims of police, customs, or official authority communicated informally."
        );

        // 6. Secrecy & Isolation Coercion
        checkPattern(text, PATTERN_SECRECY_ENG, indicators,
                    "RULE_SECRECY_ISOLATION",
                    MessageIndicatorType.SECRECY_ISOLATION,
                    ThreatSeverity.HIGH,
                    "Isolation & Secrecy Pressure",
                    "Instructs you not to disclose the conversation to family, parents, or advisers. Isolation is a primary coercion technique."
        );
        checkPattern(text, PATTERN_SECRECY_CONFIDENTIAL, indicators,
                    "RULE_SECRECY_ISOLATION",
                    MessageIndicatorType.SECRECY_ISOLATION,
                    ThreatSeverity.HIGH,
                    "Confidentiality Pressure",
                    "Demands strict secrecy under guise of an investigation or personal request."
        );
        checkPattern(text, PATTERN_SECRECY_HINGLISH, indicators,
                    "RULE_SECRECY_ISOLATION",
                    MessageIndicatorType.SECRECY_ISOLATION,
                    ThreatSeverity.HIGH,
                    "Secrecy Demand (Hinglish: 'Kisi Ko Mat Batana')",
                    "Demands concealing communications from parents or family."
        );

        // 7. Coercion, Arrest Threats & Intimidation
        checkPattern(text, PATTERN_LEGAL_THREAT_ENG, indicators,
                    "RULE_COERCION_THREAT",
                    MessageIndicatorType.COERCION_OR_THREAT,
                    ThreatSeverity.CRITICAL,
                    "Arrest Warrant, FIR, or Legal Intimidation",
                    "Threatens immediate arrest, court action, or police raids to induce panic."
        );
        checkPattern(text, PATTERN_LEGAL_THREAT_HINGLISH, indicators,
                    "RULE_COERCION_THREAT",
                    MessageIndicatorType.COERCION_OR_THREAT,
                    ThreatSeverity.CRITICAL,
                    "Legal Coercion / Jail Threat (Hinglish)",
                    "Threatens imprisonment or police action if demands are not met immediately."
        );

        // 8. Sensitive Data & Camera Demands
        checkPattern(text, PATTERN_ID_DEMAND, indicators,
                    "RULE_SENSITIVE_DATA_REQUEST",
                    MessageIndicatorType.SENSITIVE_DATA_REQUEST,
                    ThreatSeverity.HIGH,
                    "Government ID / Sensitive Document Solicitation",
                    "Demands photos or copies of Aadhaar, PAN card, or payment cards."
        );
        checkPattern(text, PATTERN_CAMERA_EXPLOITATION, indicators,
                    "RULE_SENSITIVE_DATA_REQUEST",
                    MessageIndicatorType.SENSITIVE_DATA_REQUEST,
                    ThreatSeverity.CRITICAL,
                    "Camera Access / Private Media Solicitation",
                    "Demands private photos or turning on device cameras in an isolated setting."
        );

        // 9. Artificial Urgency & Hangup Prohibition
        checkPattern(text, PATTERN_HANGUP_PREVENTION, indicators,
                    "RULE_ARTIFICIAL_URGENCY_PANIC",
                    MessageIndicatorType.ARTIFICIAL_URGENCY_PANIC,
                    ThreatSeverity.HIGH,
                    "Call Disconnection Prohibition",
                    "Orders you not to hang up or disconnect the call. Scammers enforce continuous engagement to prevent victim verification."
        );
        checkPattern(text, PATTERN_TIGHT_TIME_PRESSURE, indicators,
                    "RULE_ARTIFICIAL_URGENCY_PANIC",
                    MessageIndicatorType.ARTIFICIAL_URGENCY_PANIC,
                    ThreatSeverity.MEDIUM,
                    "Strict Time Limit / Artificial Urgency",
                    "Enforces an artificial deadline ('within 15 minutes') to force impulsive action."
        );

        return indicators;
    }

    public static boolean hasBenignCounterSignal(String cleanText) {
        if (cleanText == null || cleanText.isEmpty()) return false;
        // Check celebration/birthday/homework context
        if (PATTERN_BENIGN_CELEBRATION.matcher(cleanText).find()) {
            return true;
        }
        // Check educational security warning (e.g. bank warning about OTP)
        if (PATTERN_OTP_WARNING.matcher(cleanText).find()) {
            return true;
        }
        return false;
    }

    public static boolean isInformationalBankAlert(String cleanText) {
        if (cleanText == null || cleanText.isEmpty()) return false;
        // Must look like an account credit/debit alert without action triggers
        return PATTERN_BENIGN_BANK_ALERT.matcher(cleanText).find()
                && !PATTERN_CREDENTIAL_ENG.matcher(cleanText).find()
                && !PATTERN_SHORTLINKS.matcher(cleanText).find()
                && !PATTERN_DISPOSABLE_URLS.matcher(cleanText).find()
                && !PATTERN_PAYMENT_PRESSURE_ENG.matcher(cleanText).find();
    }

    private static void checkPattern(
            String text,
            Pattern pattern,
            List<MessageIndicator> outList,
            String ruleId,
            MessageIndicatorType type,
            ThreatSeverity severity,
            String title,
            String explanation) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            EvidenceSpan span = new EvidenceSpan(matcher.start(), matcher.end(), matcher.group());
            outList.add(new MessageIndicator(ruleId, type, severity, title, explanation, span));
            // Break after first match of the same specific pattern to avoid duplicate identical findings
            break;
        }
    }
}
