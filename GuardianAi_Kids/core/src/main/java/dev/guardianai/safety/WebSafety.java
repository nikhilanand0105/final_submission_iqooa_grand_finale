package dev.guardianai.safety;

import dev.guardianai.safety.SafetyTypes.AgeConcern;
import dev.guardianai.safety.SafetyTypes.SelfHarmKind;
import dev.guardianai.shield.url.DomainTrust;
import dev.guardianai.shield.url.ParsedUrl;
import dev.guardianai.shield.url.UrlParser;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Safe Browser helpers: search-query extraction, page age-suitability rules, and the navigation decision. */
public final class WebSafety {

    private WebSafety() {}

    // ------------------------------------------------------------------ search queries

    /** Returns the search text if the URL is a results page of a known search engine, else null. */
    public static String searchQuery(String url) {
        ParsedUrl p = new UrlParser().parse(url);
        if (!p.isValid() || p.getQuery().isEmpty()) return null;
        String h = p.getAsciiHost();
        String param = null;
        if ((h.matches("(?:www\\.)?google\\.[a-z.]+") && p.getPath().startsWith("/search"))
                || (h.matches("(?:www\\.)?bing\\.com") && p.getPath().startsWith("/search"))
                || h.matches("(?:www\\.|html\\.)?duckduckgo\\.com")) param = "q";
        else if (h.matches("(?:[a-z]+\\.)?search\\.yahoo\\.com")) param = "p";
        else if (h.matches("(?:www\\.|m\\.)?youtube\\.com") && p.getPath().startsWith("/results")) param = "search_query";
        if (param == null) return null;
        for (String kv : p.getQuery().split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).equals(param)) {
                try {
                    String v = URLDecoder.decode(kv.substring(eq + 1), "UTF-8").trim();
                    return v.isEmpty() ? null : (v.length() > 300 ? v.substring(0, 300) : v);
                } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                    return null;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ page suitability (rules fallback)

    private static final Pattern EXPLICIT = Pattern.compile("\\b(?:porn\\w*|xxx|nsfw|nude[sd]?|naked|sex (?:video|chat|cam)s?|camgirls?|adult content|18\\+ only|escort|onlyfans|hentai)\\b");
    private static final Pattern GAMBLING = Pattern.compile("\\b(?:casino|betting|bet now|place (?:a|your) bets?|jackpot|odds|sportsbook|satta|matka|teen patti cash|real money rummy|slot machines?|roulette|poker for money|(?:casino|welcome|signup) deposit bonus)\\b");
    private static final Pattern VIOLENCE = Pattern.compile("\\b(?:gore|beheading|graphic violence|execution video|torture video|real death footage|massacre footage)\\b");
    private static final Pattern SH_METHOD = Pattern.compile("\\b(?:how to (?:kill|hang|cut) (?:yourself|myself)|painless (?:way|ways) to die|suicide methods?|ways to (?:commit suicide|end (?:your|my) life)|lethal dose)\\b");
    private static final Pattern SH_PREVENTION = Pattern.compile("\\b(?:helpline|crisis line|prevention|get help|talk to someone|tele[- ]?manas|you are not alone|support is available)\\b");
    private static final Pattern AGE_GATE = Pattern.compile("\\b(?:are you (?:18|over 18)|i am 18 or older|must be 18|adults only|age verification)\\b");

    /** Rules-based page suitability from visible page text. Needs repeated evidence; one word is not enough. */
    public static AgeFinding pageSuitability(String pageText) {
        String t = pageText == null ? "" : pageText.toLowerCase(Locale.ROOT);
        if (t.trim().length() < 40) return new AgeFinding(AgeConcern.UNKNOWN, new ArrayList<String>(), "Too little page text to judge");
        int explicit = count(EXPLICIT, t), gamble = count(GAMBLING, t), violent = count(VIOLENCE, t);
        boolean gate = AGE_GATE.matcher(t).find();
        boolean method = SH_METHOD.matcher(t).find();
        boolean prevention = SH_PREVENTION.matcher(t).find();
        List<String> ev = new ArrayList<>();
        if (method && !prevention) return new AgeFinding(AgeConcern.SELF_HARM_MATERIAL, first(SH_METHOD, t, ev), "Page text describes ways to self-harm");
        if (explicit >= 3 || (explicit >= 1 && gate)) return new AgeFinding(AgeConcern.EXPLICIT_CONTENT, first(EXPLICIT, t, ev), "Repeated adult-content terms on the page");
        if (gamble >= 3) return new AgeFinding(AgeConcern.GAMBLING, first(GAMBLING, t, ev), "Repeated gambling terms on the page");
        if (violent >= 2) return new AgeFinding(AgeConcern.VIOLENCE, first(VIOLENCE, t, ev), "Repeated graphic-violence terms on the page");
        return new AgeFinding(AgeConcern.NONE, ev, "");
    }

    public static final class AgeFinding {
        public final AgeConcern concern;
        public final List<String> evidence;
        public final String note;

        AgeFinding(AgeConcern c, List<String> ev, String n) {
            concern = c;
            evidence = ev;
            note = n;
        }
    }

    /** Evidence score: distinct matched terms, plus 2 when terms repeat 5+ times (pages that are about the topic). */
    private static int count(Pattern p, String t) {
        Matcher m = p.matcher(t);
        java.util.Set<String> distinct = new java.util.HashSet<>();
        int total = 0;
        while (m.find() && total < 100) {
            total++;
            distinct.add(m.group());
        }
        return distinct.size() + (total >= 5 ? 2 : 0);
    }

    private static List<String> first(Pattern p, String t, List<String> ev) {
        Matcher m = p.matcher(t);
        if (m.find()) ev.add(t.substring(Math.max(0, m.start() - 20), Math.min(t.length(), m.end() + 20)).trim());
        return ev;
    }

    // ------------------------------------------------------------------ navigation decision

    public enum Action { ALLOW, WARN, BLOCK, SUPPORT }
    public enum Reason { NONE, SUSPECTED_SPOOF, KNOWN_HARMFUL, AGE_INAPPROPRIATE, SELF_HARM_SUPPORT, ANALYSIS_UNAVAILABLE }

    public static final class Decision {
        public final Action action;
        public final Reason reason;
        public final String title;
        public final String message;
        public final boolean canContinue;

        Decision(Action a, Reason r, String title, String message, boolean canContinue) {
            action = a;
            reason = r;
            this.title = title;
            this.message = message;
            this.canContinue = canContinue;
        }
    }

    /** Before navigation: technical trust only. */
    public static Decision forUrl(DomainTrust t) {
        switch (t.outcome) {
            case KNOWN_HARMFUL:
                return new Decision(Action.BLOCK, Reason.KNOWN_HARMFUL, "This site is listed as dangerous",
                        t.reason + ". GuardianAi won't open it.", false);
            case SUSPECTED_SPOOF:
                return new Decision(Action.WARN, Reason.SUSPECTED_SPOOF, "This might be a fake website",
                        (t.organisation != null ? "It looks like it's pretending to be " + t.organisation + ". " : "") + t.reason
                                + ". Never type passwords or OTPs here.", true);
            case UNAVAILABLE:
                return new Decision(Action.ALLOW, Reason.ANALYSIS_UNAVAILABLE, "", t.reason, true);
            case OFFICIALLY_LINKED_LEGACY:
            case RECOGNISED_OFFICIAL:
                return new Decision(Action.ALLOW, Reason.NONE, "", t.reason, true);
            default:
                return new Decision(Action.ALLOW, Reason.NONE, "", t.reason, true);
        }
    }

    /** After a search or page text was classified. */
    public static Decision forContent(SafetyClassification c) {
        if (c.selfHarm.isPersonalRisk() && c.status == SafetyTypes.Status.COMPLETE) {
            return new Decision(Action.SUPPORT, Reason.SELF_HARM_SUPPORT, "You don't have to go through this alone",
                    "It sounds like things might be really hard right now. Talking to someone can help.", true);
        }
        switch (c.age) {
            case EXPLICIT_CONTENT:
                return new Decision(Action.BLOCK, Reason.AGE_INAPPROPRIATE, "This page isn't meant for kids",
                        "It looks like it has adult content. Let's go back.", false);
            case SELF_HARM_MATERIAL:
                return new Decision(Action.SUPPORT, Reason.SELF_HARM_SUPPORT, "This page could be upsetting",
                        "It talks about hurting yourself. If you're having thoughts like that, please talk to someone you trust.", false);
            case GAMBLING:
            case VIOLENCE:
                return new Decision(Action.WARN, Reason.AGE_INAPPROPRIATE, "This page may not be right for you",
                        c.age == AgeConcern.GAMBLING ? "It looks like a gambling site." : "It may show graphic violence.", true);
            default:
                break;
        }
        if (c.selfHarm == SelfHarmKind.AMBIGUOUS && c.status == SafetyTypes.Status.NEEDS_REVIEW) {
            return new Decision(Action.ALLOW, Reason.NONE, "", "Mentions a sensitive topic; no warning shown", true);
        }
        return new Decision(Action.ALLOW, Reason.NONE, "", "", true);
    }
}
