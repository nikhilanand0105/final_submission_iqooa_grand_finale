package dev.guardianai.sense.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, explainable local rule-based implementation of MessageSafetyAnalyzer.
 * Evaluates observable safety patterns, linguistic cues, and Hinglish idioms.
 *
 * Implements context-aware combinations and counter-signals to minimise false positives.
 */
public class RuleBasedMessageSafetyAnalyzer implements MessageSafetyAnalyzer {

    public static final String ANALYZER_TYPE = "RuleBasedDeterministicSafetyEngine";
    public static final String VERSION = "1.0.0-rules";

    private static final String LIMITATIONS_DISCLAIMER =
            "Basic on-device pattern analysis only. Does not guarantee safety; cannot assess what happened " +
            "outside this excerpt. Always trust your feelings and talk to an adult you trust if something feels wrong.";

    // =========================================================================
    // COMPILED PATTERNS FOR INDICATORS (English & Hinglish)
    // =========================================================================

    // 1. Credentials / OTP / PIN theft
    private static final Pattern PATTERN_CREDENTIALS_SOLICIT = Pattern.compile(
            "\\b(?:" +
            "(?:send|give|share|tell|enter|type|provide|daal|bhej|batao?)\\b[^.?!\\n]{0,35}\\b(?:otp|pin|password|passcode|login|credentials|6-digit code|auth code|verification code)" +
            "|" +
            "(?:otp|pin|password|passcode|6-digit code|verification code)\\b[^.?!\\n]{0,35}\\b(?:send|give|share|tell|enter|type|daal|bhej|batao?)" +
            "|" +
            "(?:upi pin|atm pin|login password|account password)" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Benign credential counter-signals (e.g. forgot school portal password)
    private static final Pattern PATTERN_BENIGN_CREDENTIALS = Pattern.compile(
            "\\b(?:forgot my password|reset my password|reset password|portal password|school portal|zoom password|teacher gave the password)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 2. Urgent payment or money-transfer demands
    private static final Pattern PATTERN_PAYMENT_DEMAND = Pattern.compile(
            "\\b(?:" +
            "(?:send|transfer|pay|upi)\\s*(?:me|us)?\\s*(?:money|rs\\.?|rupees|inr|cash|paise)\\b" +
            "|" +
            "(?:paise|paisa)\\s*(?:bhej|transfer kar|de do|dal|chahiye)\\b" +
            "|" +
            "(?:turant|urgent|immediately)\\s*(?:pay|payment|transfer|paise|upi)\\b" +
            "|" +
            "(?:urgent\\s*payment|payment\\s*of\\s*(?:rs|rupees|[0-9]+))\\b" +
            "|" +
            "(?:fine|penalty|charge)\\s*(?:of|rs|pay|deducted|will\\s*be\\s*charged|charged)\\b" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 3. Fake prizes, game rewards, parcel charges, account warnings
    private static final Pattern PATTERN_PRIZE_SCAM = Pattern.compile(
            "\\b(?:" +
            "(?:free\\s*(?:robux|v-?bucks|diamonds|gems|uc|skin|gift card|rewards?))" +
            "|" +
            "(?:claim\\s*(?:free|[0-9]+\\s*(?:robux|diamonds|uc|cash|iphone|prize)))" +
            "|" +
            "(?:you\\s*(?:have\\s*)?won\\s*(?:an?\\s*)?(?:iphone|lottery|prize|cash|gift))" +
            "|" +
            "(?:bgmi\\s*uc\\s*free|free\\s*redeem\\s*code|lottery\\s*lag\\s*gayi|inaam\\s*jeeta)" +
            "|" +
            "(?:account\\s*(?:will\\s*be|is)\\s*(?:blocked|suspended|terminated|deleted)\\s*(?:in|within|immediately))" +
            "|" +
            "(?:customs?\\s*(?:fee|duty|charge)\\s*(?:for|parcel|courier))" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 4. Suspicious links and attachment prompts
    private static final Pattern PATTERN_SUSPICIOUS_LINK = Pattern.compile(
            "(?:https?://[^\\s]+(?:\\.top|\\.xyz|\\.buzz|\\.click|\\.tk|\\.gq|\\.cc|\\.claims|\\.rest)[^\\s]*)" +
            "|" +
            "(?:https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}[^\\s]*)" +
            "|" +
            "(?:https?://[^\\s]*(?:robux|free-skin|claim-gift|reward-portal)[^\\s]*)" +
            "|" +
            "\\b(?:click\\s*(?:this|the)?\\s*link\\s*to\\s*claim|ye\\s*link\\s*open\\s*kar|download\\s*the\\s*attached\\s*apk|install\\s*this\\s*mod)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 5. Threats, repeated humiliation or bullying language
    private static final Pattern PATTERN_BULLYING = Pattern.compile(
            "\\b(?:" +
            "(?:nobody\\s*likes\\s*you|worst\\s*player|delete\\s*your\\s*account|kill\\s*yourself|you\\s*are\\s*(?:ugly|loser|worthless|stupid|pathetic))" +
            "|" +
            "(?:we\\s*will\\s*beat\\s*you\\s*up|everyone\\s*hates\\s*you|leave\\s*the\\s*group\\s*loser)" +
            "|" +
            "(?:tujhe\\s*pitunga|tujhe\\s*chodenge\\s*nahi|mar\\s*jaa|tu\\s*bekar\\s*hai|kisi\\s*ko\\s*pasand\\s*nahi\\s*tu)" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 6. Pressure to share private information or pictures
    private static final Pattern PATTERN_PRIVACY_INVASION = Pattern.compile(
            "\\b(?:" +
            "(?:send|share|show|post|leak)\\s*(?:your|a|me)?\\s*(?:private|secret)?\\s*(?:photo|selfie|picture|pic|video|camera|face)\\b" +
            "|" +
            "(?:private|secret)\\s*(?:photo|selfie|picture|pic|video)\\b" +
            "|" +
            "(?:turn\\s*on\\s*(?:your)?\\s*camera|video\\s*call\\s*(?:me)?\\s*(?:alone|privately)?)\\b" +
            "|" +
            "(?:photo\\s*bhej|apni\\s*photo\\s*dikha|camera\\s*on\\s*kar|akeli\\s*photo|video\\s*call\\s*kar\\s*akele)\\b" +
            "|" +
            "(?:what\\s*is\\s*your\\s*(?:home\\s*)?address|where\\s*do\\s*you\\s*live|are\\s*you\\s*alone\\s*at\\s*home)\\b" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 7. Pressure to keep an interaction secret
    private static final Pattern PATTERN_SECRECY = Pattern.compile(
            "\\b(?:" +
            "(?:don'?t\\s*tell\\s*(?:anyone|anybody|your\\s*parents|your\\s*mom|your\\s*dad))" +
            "|" +
            "(?:keep\\s*this\\s*(?:a\\s*)?secret|secret\\s*between\\s*us|promise\\s*not\\s*to\\s*tell)" +
            "|" +
            "(?:delete\\s*(?:this\\s*)?chat|clear\\s*(?:this\\s*)?conversation)" +
            "|" +
            "(?:mummy\\s*papa\\s*ko\\s*mat\\s*batana|parents\\s*ko\\s*mat\\s*batana|kisi\\s*ko\\s*mat\\s*(?:batana|bolna))" +
            "|" +
            "(?:ghar\\s*pe\\s*mat\\s*(?:batana|bolna)|ye\\s*secret\\s*hai|chupana)" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Benign celebration secrecy counter-signals (e.g., surprise birthday party)
    private static final Pattern PATTERN_BENIGN_SECRECY = Pattern.compile(
            "\\b(?:" +
            "(?:surprise\\s*(?:birthday|party|gift|present))" +
            "|" +
            "(?:birthday\\s*(?:surprise|party|gift|celebration))" +
            "|" +
            "(?:gift\\s*for\\s*(?:mom|dad|mother|father|teacher|friend))" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 8. Attempts to move a conversation somewhere less visible (Platform migration)
    private static final Pattern PATTERN_PLATFORM_MIGRATION = Pattern.compile(
            "\\b(?:" +
            "(?:(?:move|switch)\\s*to\\s*(?:telegram|snap(?:chat)?|insta(?:gram)?|whatsapp))" +
            "|" +
            "(?:(?:message|dm|text|chat|talk|add)\\s*(?:me|us)?\\s*on\\s*(?:telegram|snap(?:chat)?|insta(?:gram)?|whatsapp))" +
            "|" +
            "(?:telegram\\s*pe\\s*(?:aao|message\\s*kar|baat\\s*kar))" +
            "|" +
            "(?:snap(?:chat)?\\s*pe\\s*(?:add\\s*kar|aao|message\\s*kar))" +
            "|" +
            "(?:insta\\s*pe\\s*(?:aao|message\\s*kar|dm\\s*kar))" +
            "|" +
            "(?:come\\s*to\\s*(?:a\\s*)?private\\s*room|private\\s*room\\s*mein\\s*aao|disappearing\\s*messages)" +
            "|" +
            "(?:talk\\s*on\\s*whatsapp|whatsapp\\s*pe\\s*baat\\s*karte\\s*hai)" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // 9. Coercive or threatening language
    private static final Pattern PATTERN_COERCION = Pattern.compile(
            "\\b(?:" +
            "(?:or\\s*else\\s*(?:I\\s*will|something)|if\\s*you\\s*don'?t\\s*I\\s*will|do\\s*this\\s*or\\s*else|or\\s*else\\b)" +
            "|" +
            "(?:I\\s*will\\s*(?:tell|leak|post|share)\\s*(?:your|everyone))" +
            "|" +
            "(?:warna\\s*(?:sabko\\s*bata\\s*dunga|viral\\s*kar\\s*dunga|maar\\s*padegi|sabko\\s*bol\\s*dunga))" +
            "|" +
            "(?:agar\\s*nahi\\s*kiya\\s*toh)" +
            "|" +
            "(?:leak\\s*(?:your\\s*)?(?:chats?|photos?|pics?))" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Benign school/general counter-signals
    private static final Pattern PATTERN_BENIGN_CONTEXT = Pattern.compile(
            "\\b(?:" +
            "(?:homework|assignment|project|exam|study\\s*hour|classwork|school\\s*tomorrow|teacher\\s*said)" +
            "|" +
            "(?:football\\s*practice|cricket\\s*match|soccer\\s*practice|lunch\\s*break)" +
            ")\\b",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public MessageAnalysisResult analyze(String messageText) {
        long timestamp = System.currentTimeMillis();

        // 1. Check for null or empty input
        if (messageText == null || messageText.trim().isEmpty()) {
            return new MessageAnalysisResult(
                    MessageRiskVerdict.INCONCLUSIVE,
                    ProcessingStatus.INCONCLUSIVE,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    "No message text was provided to analyze.",
                    "We need words or a sentence from a message to look for safety signs.",
                    List.of("Paste or type a message, chat excerpt, or note to check it."),
                    LIMITATIONS_DISCLAIMER,
                    ANALYZER_TYPE,
                    VERSION,
                    timestamp,
                    0,
                    0
            );
        }

        String rawText = messageText.trim();
        int charCount = rawText.length();
        String[] words = rawText.split("\\s+");
        int wordCount = words.length;

        // 2. Check for insufficient context (too short, single word, emojis only)
        // Strip non-alphanumeric to see actual semantic content length
        String strippedAlphaNum = rawText.replaceAll("[^\\p{L}\\p{Nd}]", "");
        if (wordCount < 3 || strippedAlphaNum.length() < 7) {
            SafetyIndicator shortIndicator = new SafetyIndicator(
                    "IND_INSUFFICIENT_CONTEXT",
                    SafetyIndicatorCategory.INSUFFICIENT_CONTEXT,
                    "Short or Ambiguous Text",
                    "The message excerpt is very brief and does not provide enough context to check for risks.",
                    rawText,
                    IndicatorSeverity.INFO
            );

            return new MessageAnalysisResult(
                    MessageRiskVerdict.INCONCLUSIVE,
                    ProcessingStatus.INCONCLUSIVE,
                    List.of(shortIndicator),
                    List.of(rawText),
                    "This message is very short (e.g., a greeting or single reply). There is not enough context here to spot warning signs or understand what the conversation is about.",
                    "Short words like 'hello' or 'ok' don't contain clues on their own. Safety depends on how the conversation continues and who is talking to you.",
                    List.of(
                            "If the conversation starts feeling strange or uncomfortable, paste more lines to check again",
                            "Never share passwords, addresses, or private photos even in short chats",
                            "Talk to a trusted adult if you ever feel uneasy"
                    ),
                    LIMITATIONS_DISCLAIMER,
                    ANALYZER_TYPE,
                    VERSION,
                    timestamp,
                    charCount,
                    wordCount
            );
        }

        // 3. Scan for Benign Counter-Signals
        boolean hasBenignCelebration = PATTERN_BENIGN_SECRECY.matcher(rawText).find();
        boolean hasBenignSchool = PATTERN_BENIGN_CONTEXT.matcher(rawText).find();
        boolean hasBenignCredentials = PATTERN_BENIGN_CREDENTIALS.matcher(rawText).find();

        // 4. Scan Indicators
        List<SafetyIndicator> indicators = new ArrayList<>();
        List<String> excerpts = new ArrayList<>();

        // (a) Credentials / OTP
        Matcher mCred = PATTERN_CREDENTIALS_SOLICIT.matcher(rawText);
        if (mCred.find() && !hasBenignCredentials) {
            String match = extractExcerpt(rawText, mCred.start(), mCred.end());
            indicators.add(new SafetyIndicator(
                    "IND_CREDENTIAL_SOLICITATION",
                    SafetyIndicatorCategory.CREDENTIAL_THEFT,
                    "Password or One-Time Code (OTP) Request",
                    "Asks for confidential login passwords, OTP verification codes, or PINs.",
                    match,
                    IndicatorSeverity.CRITICAL
            ));
            excerpts.add(match);
        }

        // (b) Urgent payment demands
        Matcher mPay = PATTERN_PAYMENT_DEMAND.matcher(rawText);
        if (mPay.find()) {
            String match = extractExcerpt(rawText, mPay.start(), mPay.end());
            indicators.add(new SafetyIndicator(
                    "IND_FINANCIAL_DEMAND",
                    SafetyIndicatorCategory.FINANCIAL_DEMAND,
                    "Urgent Money Transfer Demand",
                    "Demands money, UPI payment, or claims penalties/fines.",
                    match,
                    IndicatorSeverity.HIGH
            ));
            excerpts.add(match);
        }

        // (c) Fake prizes & game rewards
        Matcher mPrize = PATTERN_PRIZE_SCAM.matcher(rawText);
        if (mPrize.find()) {
            String match = extractExcerpt(rawText, mPrize.start(), mPrize.end());
            indicators.add(new SafetyIndicator(
                    "IND_PRIZE_SCAM",
                    SafetyIndicatorCategory.PRIZE_SCAM,
                    "Fake Prize, Reward, or Account Warning",
                    "Promises free game currency (Robux/diamonds) or warns of sudden account suspension.",
                    match,
                    IndicatorSeverity.HIGH
            ));
            excerpts.add(match);
        }

        // (d) Suspicious links & downloads
        Matcher mLink = PATTERN_SUSPICIOUS_LINK.matcher(rawText);
        if (mLink.find()) {
            String match = extractExcerpt(rawText, mLink.start(), mLink.end());
            indicators.add(new SafetyIndicator(
                    "IND_SUSPICIOUS_LINK",
                    SafetyIndicatorCategory.SUSPICIOUS_LINK,
                    "Suspicious Link or Download Prompt",
                    "Points to an uncommon domain extension, raw IP address, or requests installing unknown files.",
                    match,
                    IndicatorSeverity.HIGH
            ));
            excerpts.add(match);
        }

        // (e) Bullying & humiliation
        Matcher mBully = PATTERN_BULLYING.matcher(rawText);
        if (mBully.find()) {
            String match = extractExcerpt(rawText, mBully.start(), mBully.end());
            indicators.add(new SafetyIndicator(
                    "IND_BULLYING_LANGUAGE",
                    SafetyIndicatorCategory.BULLYING_HARASSMENT,
                    "Hurtful or Bullying Language",
                    "Contains mean, demeaning, or hostile phrases intended to upset the child.",
                    match,
                    IndicatorSeverity.HIGH
            ));
            excerpts.add(match);
        }

        // (f) Privacy invasion / Photo requests
        Matcher mPriv = PATTERN_PRIVACY_INVASION.matcher(rawText);
        if (mPriv.find()) {
            String match = extractExcerpt(rawText, mPriv.start(), mPriv.end());
            indicators.add(new SafetyIndicator(
                    "IND_PRIVACY_INVASION",
                    SafetyIndicatorCategory.PRIVACY_INVASION,
                    "Private Photo, Camera, or Location Request",
                    "Pressures the child to share photos, switch on their camera, or disclose their home address.",
                    match,
                    IndicatorSeverity.CRITICAL
            ));
            excerpts.add(match);
        }

        // (g) Secrecy pressure (filtering out birthday/celebration surprises)
        Matcher mSec = PATTERN_SECRECY.matcher(rawText);
        if (mSec.find() && !hasBenignCelebration) {
            String match = extractExcerpt(rawText, mSec.start(), mSec.end());
            indicators.add(new SafetyIndicator(
                    "IND_SECRECY_PRESSURE",
                    SafetyIndicatorCategory.SECRECY_PRESSURE,
                    "Pressure to Keep Secrets",
                    "Asks to hide the conversation from parents or family members.",
                    match,
                    IndicatorSeverity.HIGH
            ));
            excerpts.add(match);
        }

        // (h) Platform migration
        Matcher mPlat = PATTERN_PLATFORM_MIGRATION.matcher(rawText);
        if (mPlat.find()) {
            String match = extractExcerpt(rawText, mPlat.start(), mPlat.end());
            indicators.add(new SafetyIndicator(
                    "IND_PLATFORM_MIGRATION",
                    SafetyIndicatorCategory.PLATFORM_MIGRATION,
                    "Attempt to Move to Private Channel",
                    "Encourages switching to Telegram, Snapchat, or private disappearing chats.",
                    match,
                    IndicatorSeverity.MEDIUM
            ));
            excerpts.add(match);
        }

        // (i) Coercion and intimidation
        Matcher mCoerc = PATTERN_COERCION.matcher(rawText);
        if (mCoerc.find()) {
            String match = extractExcerpt(rawText, mCoerc.start(), mCoerc.end());
            indicators.add(new SafetyIndicator(
                    "IND_COERCION_INTIMIDATION",
                    SafetyIndicatorCategory.COERCION_INTIMIDATION,
                    "Coercion or Threatening Ultimatum",
                    "Threatens consequences ('or else', 'I will tell everyone') if the child does not comply.",
                    match,
                    IndicatorSeverity.CRITICAL
            ));
            excerpts.add(match);
        }

        // 5. Synthesize Verdict, Child-Friendly Explanations, and Actionable Steps
        return buildEvaluationResult(
                indicators,
                excerpts,
                hasBenignCelebration,
                hasBenignSchool,
                charCount,
                wordCount,
                timestamp
        );
    }

    private MessageAnalysisResult buildEvaluationResult(
            List<SafetyIndicator> indicators,
            List<String> excerpts,
            boolean hasBenignCelebration,
            boolean hasBenignSchool,
            int charCount,
            int wordCount,
            long timestamp) {

        // Check combinations
        boolean hasSecrecy = hasCategory(indicators, SafetyIndicatorCategory.SECRECY_PRESSURE);
        boolean hasPrivacy = hasCategory(indicators, SafetyIndicatorCategory.PRIVACY_INVASION);
        boolean hasPlatform = hasCategory(indicators, SafetyIndicatorCategory.PLATFORM_MIGRATION);
        boolean hasCredentials = hasCategory(indicators, SafetyIndicatorCategory.CREDENTIAL_THEFT);
        boolean hasCoercion = hasCategory(indicators, SafetyIndicatorCategory.COERCION_INTIMIDATION);
        boolean hasBullying = hasCategory(indicators, SafetyIndicatorCategory.BULLYING_HARASSMENT);
        boolean hasPrize = hasCategory(indicators, SafetyIndicatorCategory.PRIZE_SCAM);
        boolean hasFinance = hasCategory(indicators, SafetyIndicatorCategory.FINANCIAL_DEMAND);

        // CASE 1: CRITICAL GROOMING OR COERCIVE RISK (Secrecy + Photo/Camera, or Secrecy + Platform Migration, or Coercion, or Credential Theft)
        if ((hasSecrecy && (hasPrivacy || hasPlatform)) || hasCoercion || hasCredentials || (hasBullying && (hasCoercion || hasPrivacy))) {
            List<String> steps = new ArrayList<>();
            steps.add("Do not send any codes, passwords, or photos");
            steps.add("Show this message to a parent or trusted adult immediately");
            steps.add("Remember you did nothing wrong and you are not in trouble");
            steps.add("Block the sender and tap GuardianAi SOS if you feel scared or unsafe");

            String explanation = "This message contains serious warning signs. It asks for private information or secrets that children should never be pressured into sharing.";
            String whyItMatters = "Real friends and games never ask you to keep secrets from your parents, switch to secret channels, or hand over login codes. These are common tactics used to trick or pressure kids.";

            return new MessageAnalysisResult(
                    MessageRiskVerdict.WARNING_SIGNS_DETECTED,
                    ProcessingStatus.SUCCESS,
                    indicators,
                    excerpts,
                    explanation,
                    whyItMatters,
                    steps,
                    LIMITATIONS_DISCLAIMER,
                    ANALYZER_TYPE,
                    VERSION,
                    timestamp,
                    charCount,
                    wordCount
            );
        }

        // CASE 2: SUSPICIOUS ACTIVITY (Prize scam, single secrecy without photo, single platform hopping, money demand, bullying)
        if (!indicators.isEmpty()) {
            List<String> steps = new ArrayList<>();
            steps.add("Pause before replying or tapping any links");
            steps.add("Remember that genuine prizes do not ask for private info or fast action");
            steps.add("Show this conversation to an adult you trust before taking any action");

            if (hasBullying) {
                steps.add("Do not reply with mean words—take a screenshot and block the sender");
            }

            String explanation = "There are red flags in this message that you should be careful about.";
            String whyItMatters = "Scammers often use fake rewards, urgency, or pushy words to trick people into making mistakes.";

            if (hasBullying) {
                explanation = "This message contains hurtful or bullying words meant to make you feel bad.";
                whyItMatters = "Nobody has the right to treat you unkindly online. You do not have to put up with mean messages.";
            }

            return new MessageAnalysisResult(
                    MessageRiskVerdict.BE_CAREFUL,
                    ProcessingStatus.SUCCESS,
                    indicators,
                    excerpts,
                    explanation,
                    whyItMatters,
                    steps,
                    LIMITATIONS_DISCLAIMER,
                    ANALYZER_TYPE,
                    VERSION,
                    timestamp,
                    charCount,
                    wordCount
            );
        }

        // CASE 3: BENIGN CONTEXT (Celebration / School / Friendly)
        if (hasBenignCelebration || hasBenignSchool) {
            return new MessageAnalysisResult(
                    MessageRiskVerdict.NO_FLAGS_DETECTED,
                    ProcessingStatus.SUCCESS,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    "This looks like an ordinary, friendly school or celebration conversation. No warning signs were found in this excerpt.",
                    "No scam words, secrecy pressure, or suspicious requests were detected in these words.",
                    List.of(
                            "You can continue your conversation normally",
                            "If the other person ever asks for something strange later, you can always check again"
                    ),
                    LIMITATIONS_DISCLAIMER,
                    ANALYZER_TYPE,
                    VERSION,
                    timestamp,
                    charCount,
                    wordCount
            );
        }

        // CASE 4: ORDINARY TEXT - NO FLAGS FOUND
        return new MessageAnalysisResult(
                MessageRiskVerdict.NO_FLAGS_DETECTED,
                ProcessingStatus.SUCCESS,
                Collections.emptyList(),
                Collections.emptyList(),
                "No obvious warning signs were detected in this message excerpt.",
                "The words in this specific message appear ordinary. However, safety also depends on who sent it and how it makes you feel.",
                List.of(
                        "You can continue chatting normally",
                        "Remember never to share private phone numbers, home addresses, or passwords online",
                        "If something feels strange or makes you uncomfortable in your gut, talk to an adult"
                ),
                LIMITATIONS_DISCLAIMER,
                ANALYZER_TYPE,
                VERSION,
                timestamp,
                charCount,
                wordCount
        );
    }

    private boolean hasCategory(List<SafetyIndicator> indicators, SafetyIndicatorCategory category) {
        for (SafetyIndicator ind : indicators) {
            if (ind.getCategory() == category) {
                return true;
            }
        }
        return false;
    }

    private String extractExcerpt(String text, int start, int end) {
        // Expand excerpt slightly for readable context
        int excerptStart = Math.max(0, start - 5);
        int excerptEnd = Math.min(text.length(), end + 5);
        return text.substring(excerptStart, excerptEnd).trim();
    }

    @Override
    public String getAnalyzerType() {
        return ANALYZER_TYPE;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }
}
