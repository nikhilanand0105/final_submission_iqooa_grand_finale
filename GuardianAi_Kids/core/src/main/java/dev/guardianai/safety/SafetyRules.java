package dev.guardianai.safety;

import dev.guardianai.safety.SafetyTypes.SelfHarmKind;
import dev.guardianai.safety.SafetyTypes.Severity;
import dev.guardianai.safety.SafetyTypes.ThreatKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, explainable pattern rules for threats/coercion and self-harm (English, Hinglish and common Hindi).
 * Each rule combines several cues (first-person, intent, conditional demand, educational/news framing, negation,
 * game banter) rather than matching specific sample sentences. Used as the fallback classifier and by the guard.
 */
public final class SafetyRules {

    private SafetyRules() {}

    /** Result of one rule family. */
    public static final class Finding {
        public final String kind;
        public final Severity severity;
        public final List<String> evidence;
        public final String note;

        Finding(String kind, Severity severity, List<String> evidence, String note) {
            this.kind = kind;
            this.severity = severity;
            this.evidence = evidence;
            this.note = note;
        }
    }

    static String normalize(String s) {
        if (s == null) return "";
        String t = s.toLowerCase(Locale.ROOT)
                .replace('’', '\'').replace('‘', '\'')
                .replaceAll("[\\u200b-\\u200d\\ufeff]", "")
                .replaceAll("\\s+", " ");
        // common chat spellings
        t = t.replaceAll("\\bu\\b", "you").replaceAll("\\bur\\b", "your").replaceAll("\\bpls\\b|\\bplz\\b", "please")
                .replaceAll("\\bwanna\\b", "want to").replaceAll("\\bgonna\\b", "going to").replaceAll("\\bim\\b", "i'm")
                .replaceAll("\\bdont\\b", "don't").replaceAll("\\bcant\\b", "can't");
        return t.trim();
    }

    // ------------------------------------------------------------------------------------------ self-harm

    private static final Pattern SH_FIRST_PERSON = Pattern.compile(
            "\\b(?:i (?:want|wish|need|plan|am going|'m going|will|'ll|am planning|'m planning|am thinking about|'m thinking about|keep thinking about|feel like)"
                    + "(?: to)?(?: just)?(?: (?:kill(?:ing)?|end(?:ing)?|hurt(?:ing)?|harm(?:ing)?|cut(?:ting)?)) (?:myself|my life|it all)"
                    + "|(?:kill(?:ing)?|hurt(?:ing)?|harm(?:ing)?|cut(?:ting)?) myself"
                    + "|end my (?:own )?life"
                    + "|i (?:want|wish) (?:to|i (?:was|were)) (?:die|dead)"
                    + "|i (?:don't|do not) want to (?:live|be alive|wake up)"
                    + "|(?:no|not any) reason (?:for me )?to (?:live|go on)"
                    + "|better off (?:dead|without me)"
                    + "|(?:marna|mar jaana|mar jana|khatam hona) (?:chahta|chahti|chahata) (?:hu|hoon|hun)"
                    + "|jeena nahi (?:chahta|chahti)|zindagi khatam kar (?:dunga|dungi|lunga|lungi)"
                    + "|khud ko (?:khatam|hurt|chot) kar"
                    + "|मरना चाहत[ाी]|जीना नहीं चाहत[ाी]|खुद को (?:खत्म|चोट)|आत्महत्या कर (?:लूंगा|लूंगी|लूँगा|लूँगी))");

    private static final Pattern SH_TERM = Pattern.compile(
            "\\b(?:suicid\\w*|self[- ]?harm\\w*|kill (?:my|him|her|them)sel(?:f|ves)|end (?:my|his|her|their) li(?:fe|ves)|overdose"
                    + "|khudkushi|aatmahatya|atmahatya)\\b|आत्महत्या|ख़ुदकुशी|खुदकुशी");

    private static final Pattern SH_INTENT_NOW = Pattern.compile(
            "\\b(?:tonight|right now|today|tomorrow|after (?:school|everyone sleeps)|this weekend|aaj raat|abhi|kal)\\b"
                    + "|\\b(?:pills|tablets|rope|blade|jump (?:off|from)|bridge|building|terrace|chhat)\\b|आज रात|अभी");

    private static final Pattern SH_PLAN = Pattern.compile(
            "\\b(?:i (?:will|'ll|am going to|'m going to|plan to|am planning to|'m planning to|have decided to)"
                    + "|i've decided|my plan|wrote (?:a|my) (?:note|letter)|goodbye (?:everyone|forever)|karunga|karungi|kar lunga|kar lungi)\\b");

    private static final Pattern SH_FAREWELL = Pattern.compile(
            "\\b(?:goodbye (?:everyone|forever|world|all)|this is my last (?:message|day|night)|i won't be (?:around|here) (?:anymore|tomorrow)"
                    + "|sorry for everything|you won't see me again|alvida sabko)\\b");

    private static final Pattern SH_MEANS = Pattern.compile("\\b(?:pills|tablets|sleeping pills|rope|blade|razor|poison|jump(?: off| from)?)\\b");

    private static final Pattern SH_HELP = Pattern.compile(
            "\\b(?:help me|i need help|what (?:do|should) i do|can (?:someone|anyone|you) help|how do i stop|meri madad|madad karo)\\b");

    private static final Pattern SH_NEGATED = Pattern.compile(
            "\\b(?:never|wouldn't|would not|won't|will not|not going to|don't|do not|nahi|kabhi nahi)\\b[^.!?]{0,20}"
                    + "\\b(?:kill(?:ing)? myself|hurt(?:ing)? myself|harm(?:ing)? myself|end(?:ing)? my life|want to die)\\b");

    private static final Pattern SH_INFORMATIONAL = Pattern.compile(
            "\\b(?:essay|project|assignment|homework|research|statistic\\w*|rates?|data|study|studies|chapter|lesson|class (?:on|about)"
                    + "|causes? of|signs? of|symptoms? of|how to help (?:a|my) friend|warning signs|psychology|definition|meaning of"
                    + "|history of|literature|novel|poem|character|movie|film|book)\\b");

    private static final Pattern SH_NEWS = Pattern.compile(
            "\\b(?:news|reported|report|according to|police said|article|headline|died by suicide|prevention|awareness|helpline|hotline"
                    + "|tele[- ]?manas|world suicide prevention day|campaign|ngo|crisis line)\\b");

    private static final Pattern SH_OTHER_PERSON = Pattern.compile(
            "\\b(?:my (?:friend|brother|sister|cousin|classmate)|he|she|they) (?:wants?|said|says|is going|is planning|talks? about|keeps? saying)\\b");

    public static Finding selfHarm(String raw) {
        String t = normalize(raw);
        Matcher fp = SH_FIRST_PERSON.matcher(t);
        boolean first = fp.find();
        String fpEv = first ? excerpt(raw, t, fp.start(), fp.end()) : null;
        boolean negated = SH_NEGATED.matcher(t).find();
        if (first && negated && !SH_PLAN.matcher(t).find()) {
            first = false; // "I would never hurt myself"
        }
        Matcher term = SH_TERM.matcher(t);
        boolean hasTerm = term.find();
        List<String> ev = new ArrayList<>();
        if (first) {
            ev.add(fpEv);
            boolean plan = SH_PLAN.matcher(t).find();
            boolean now = SH_INTENT_NOW.matcher(t).find();
            if (plan || now) {
                Matcher m = (now ? SH_INTENT_NOW : SH_PLAN).matcher(t);
                if (m.find()) ev.add(excerpt(raw, t, m.start(), m.end()));
                return new Finding(SelfHarmKind.PERSONAL_INTENT.name(), now ? Severity.IMMINENT : Severity.HIGH, ev,
                        "First-person statement about ending or hurting their own life" + (now ? " with a time or method" : " with intent"));
            }
            if (SH_HELP.matcher(t).find()) {
                return new Finding(SelfHarmKind.HELP_SEEKING.name(), Severity.HIGH, ev, "Asking for help with thoughts of self-harm");
            }
            return new Finding(SelfHarmKind.PERSONAL_IDEATION.name(), Severity.HIGH, ev, "First-person statement about wanting to die or self-harm");
        }
        Matcher fw = SH_FAREWELL.matcher(t);
        if (!negated && fw.find() && SH_MEANS.matcher(t).find()) {
            ev.add(excerpt(raw, t, fw.start(), fw.end()));
            return new Finding(SelfHarmKind.PERSONAL_INTENT.name(), Severity.HIGH, ev, "A goodbye message together with a mention of a way to self-harm");
        }
        if (!hasTerm) return new Finding(SelfHarmKind.NONE.name(), Severity.NONE, ev, "");
        ev.add(excerpt(raw, t, term.start(), term.end()));
        if (SH_OTHER_PERSON.matcher(t).find()) {
            return new Finding(SelfHarmKind.AMBIGUOUS.name(), Severity.MEDIUM, ev, "Mentions someone else possibly at risk");
        }
        if (SH_NEWS.matcher(t).find()) return new Finding(SelfHarmKind.NEWS_OR_PREVENTION.name(), Severity.NONE, ev, "News or prevention context");
        if (SH_INFORMATIONAL.matcher(t).find()) return new Finding(SelfHarmKind.INFORMATIONAL.name(), Severity.NONE, ev, "Educational context");
        return new Finding(SelfHarmKind.AMBIGUOUS.name(), Severity.LOW, ev, "Self-harm is mentioned but the context is unclear");
    }

    // ------------------------------------------------------------------------------------------ threats

    private static final String MEDIA = "(?:photos?|pics?|pictures?|videos?|nudes|chats?|messages|secrets?|screenshots?|address|number)";
    private static final String YOUR = "(?:your|you|ur|teri|tera|tere|tumhari|tumhara)";

    /** Exposure threats need threat framing: first-person future, or "your" media reaching others. */
    private static final Pattern EXPOSE = Pattern.compile(
            "\\b(?:i(?:'ll| will| am going to|'m going to)|we(?:'ll| will)|or i(?:'ll| will))\\s+(?:\\w+\\s+){0,2}"
                    + "(?:share|post|send|leak|show|upload|forward|spread|tell everyone|make)\\b[^.!?]{0,40}\\b" + YOUR + "\\b[^.!?]{0,15}\\b" + MEDIA + "\\b"
                    + "|\\b" + YOUR + "\\s+(?:\\w+\\s+){0,2}" + MEDIA + "\\b[^.!?]{0,40}\\b(?:viral|leak\\w*|sabko|everyone|internet|whole (?:school|class))\\b"
                    + "|\\b(?:everyone|sabko|whole (?:school|class)|your (?:parents|school|friends))\\s+(?:will\\s+)?(?:see|sees|watch|know about|gets?)\\s+" + YOUR + "\\s+(?:\\w+\\s+){0,1}" + MEDIA + "\\b"
                    + "|\\b(?:viral kar|daal dunga|bhej dunga|dikha dunga|sabko (?:bata|dikha|bhej)) ?(?:dunga|dungi)?\\b");

    private static final Pattern HARM = Pattern.compile(
            "\\b(?:i(?:'ll| will| am going to|'m going to)|we(?:'ll| will)) (?:hurt|beat|kill|stab|find|get|smash|break) (?:you|ur|your|u)\\b"
                    + "|\\bi know where you (?:live|study)\\b|\\b(?:come|coming) to your (?:house|home|school)\\b|\\byou(?:'ll| will) regret\\b"
                    + "|\\b(?:maar|maar dunga|maar dalunga|pitai|dekh lunga|dekh lena|chhodunga nahi|zinda nahi)\\b|मार (?:दूंगा|डालूंगा)|देख लूंगा");

    private static final Pattern CONDITION = Pattern.compile(
            "\\b(?:if you don't|if you do not|if you won't|if you (?:tell|say|report|block|ignore)|unless|or else|otherwise|or i(?:'ll| will)|warna|nahi to|nahi toh|varna)\\b|वरना|नहीं तो");

    private static final Pattern STALKING = Pattern.compile("\\bi know where you (?:live|study)\\b|\\b(?:come|coming) to your (?:house|home|school)\\b");

    private static final Pattern PAY = Pattern.compile(
            "\\b(?:pay|send|transfer|give)\\b[^.!?]{0,25}\\b(?:money|rs\\.?|₹|rupees|inr|upi|paytm|gpay|gift ?cards?|bitcoin|crypto|\\d{3,})\\b"
                    + "|\\b(?:paise|paisa)\\s*(?:bhej|de|transfer)|₹\\s?\\d+");

    private static final Pattern CREDENTIAL = Pattern.compile(
            "\\b(?:otp|password|passcode|pin|verification code|login code|6[- ]digit code)\\b");

    private static final Pattern DEMAND = Pattern.compile(
            "\\b(?:send|give|tell|share|bhej|de do|bata|batao|daal)\\b");

    private static final Pattern SELF_HARM_INCITEMENT = Pattern.compile(
            "\\b(?:kill|hurt) yourself\\b|\\bgo die\\b|\\bnobody (?:likes|wants) you\\b[^.!?]{0,30}\\b(?:die|kill)\\b|\\bmar ja\\b|\\bkhud ko maar\\b");

    private static final Pattern BANTER = Pattern.compile(
            "\\b(?:game|round|match|level|lobby|pubg|bgmi|free ?fire|minecraft|roblox|fortnite|valorant|lol|lmao|jk|just kidding|haha|hehe)\\b|😂|🤣|😜");

    private static final Pattern FICTION = Pattern.compile("\\b(?:movie|film|book|story|novel|episode|series|plot|character|scene)\\b");

    public static Finding threat(String raw) {
        String t = normalize(raw);
        List<String> ev = new ArrayList<>();
        Matcher ex = EXPOSE.matcher(t);
        boolean expose = ex.find();
        Matcher hm = HARM.matcher(t);
        boolean harm = hm.find();
        Matcher cd = CONDITION.matcher(t);
        boolean conditional = cd.find();
        Matcher py = PAY.matcher(t);
        boolean pay = py.find();
        boolean cred = CREDENTIAL.matcher(t).find() && DEMAND.matcher(t).find();
        Matcher inc = SELF_HARM_INCITEMENT.matcher(t);
        boolean incite = inc.find();
        boolean banter = BANTER.matcher(t).find();
        boolean fiction = FICTION.matcher(t).find();

        if (expose) ev.add(excerpt(raw, t, ex.start(), ex.end()));
        if (harm) ev.add(excerpt(raw, t, hm.start(), hm.end()));
        if (conditional) ev.add(excerpt(raw, t, cd.start(), cd.end()));
        if (pay) ev.add(excerpt(raw, t, py.start(), py.end()));

        boolean demand = pay || cred || Pattern.compile("\\b(?:do what i say|send (?:me )?(?:more )?(?:photos?|pics?|videos?))\\b").matcher(t).find();
        if ((expose || harm) && demand && (conditional || expose)) {
            return new Finding(ThreatKind.BLACKMAIL.name(), Severity.HIGH, ev, "A demand combined with a threat if the demand isn't met");
        }
        if (expose && (conditional || !fiction)) {
            return new Finding(ThreatKind.EXPOSURE_THREAT.name(), Severity.HIGH, ev, "Threat to share private photos, chats or information");
        }
        if (harm && !banter && !fiction) {
            boolean severe = conditional || STALKING.matcher(t).find();
            return new Finding(ThreatKind.HARM_THREAT.name(), severe ? Severity.HIGH : Severity.MEDIUM, ev, "Statement threatening to hurt someone");
        }
        if (harm) {
            return new Finding(ThreatKind.HARM_THREAT.name(), Severity.LOW, ev, "Threat-like words, but it may be game talk or a story");
        }
        if (cred && conditional) {
            ev.add("otp/password demand");
            return new Finding(ThreatKind.CREDENTIAL_DEMAND.name(), Severity.HIGH, ev, "Pressure to hand over a code or password with a consequence");
        }
        if (pay && conditional) {
            return new Finding(ThreatKind.PAYMENT_COERCION.name(), Severity.HIGH, ev, "Pressure to pay with a consequence");
        }
        if (incite) {
            ev.add(excerpt(raw, t, inc.start(), inc.end()));
            return new Finding(ThreatKind.INTIMIDATION.name(), Severity.HIGH, ev, "Someone is telling the reader to hurt themselves");
        }
        return new Finding(ThreatKind.NONE.name(), Severity.NONE, ev, "");
    }

    /**
     * Maps an index range in the normalised text back to a short excerpt. Normalisation can change lengths, so the
     * excerpt is taken from the normalised text (lower-case), which still occurs in the original case-insensitively
     * for the common case; the parser/UI treat excerpts as case-insensitive.
     */
    static String excerpt(String raw, String norm, int s, int e) {
        int a = Math.max(0, s - 10), b = Math.min(norm.length(), e + 10);
        String x = norm.substring(a, b).trim();
        return x.length() > 120 ? x.substring(0, 120) : x;
    }
}
