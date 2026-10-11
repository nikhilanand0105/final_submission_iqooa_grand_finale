package dev.guardianai.shield.url;

import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * On-device structural heuristics for a parsed URL. Each indicator has one explicit condition and records the
 * exact part of the address that triggered it. These are warning signs, not proof of malicious intent, and
 * they say nothing about the content of the page. No network access.
 */
public class UrlLocalAnalyzer {

    public static final String VERSION = "url-heuristics-2";

    public static final String USER_INFO = "URL_USER_INFO";
    public static final String DECEPTIVE_HOST_PLACEMENT = "URL_DECEPTIVE_HOST_PLACEMENT";
    public static final String IP_LITERAL = "URL_IP_LITERAL";
    public static final String NONSTANDARD_IP = "URL_NONSTANDARD_IP";
    public static final String PUNYCODE = "URL_INTERNATIONAL_CHARACTERS";
    public static final String MIXED_SCRIPT = "URL_MIXED_SCRIPT";
    public static final String LOOKALIKE = "URL_LOOKALIKE_DOMAIN";
    public static final String BRAND_ON_UNOFFICIAL = "URL_BRAND_ON_UNOFFICIAL_DOMAIN";
    public static final String ENCODED_HOST = "URL_ENCODED_HOST";
    public static final String ENCODED_NULL = "URL_ENCODED_NULL";
    public static final String DOUBLE_ENCODING = "URL_DOUBLE_ENCODING";
    public static final String HEAVY_ENCODING = "URL_HEAVY_ENCODING";
    public static final String BACKSLASH = "URL_BACKSLASH";
    public static final String NON_STANDARD_PORT = "URL_NON_STANDARD_PORT";
    public static final String MANY_SUBDOMAINS = "URL_MANY_SUBDOMAINS";
    public static final String VERY_LONG = "URL_VERY_LONG";
    public static final String NOT_ENCRYPTED = "URL_NOT_ENCRYPTED";
    public static final String EMBEDDED_URL = "URL_EMBEDDED_REDIRECT";
    public static final String SHORTENER = "URL_SHORTENER";
    public static final String FREE_HOSTING = "URL_FREE_HOSTING";
    public static final String LURE_WORDS = "URL_LURE_WORDS";
    public static final String ABUSED_TLD = "URL_FREQUENTLY_ABUSED_TLD";
    public static final String MANY_HYPHENS = "URL_MANY_HYPHENS";

    private static final Pattern PCT = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern EMBEDDED = Pattern.compile("(?i)(https?(:|%3a)(//|%2f%2f))");

    public List<UrlStructuralIndicator> analyze(ParsedUrl p) {
        if (p == null || !p.isValid()) return Collections.emptyList();
        List<UrlStructuralIndicator> out = new ArrayList<>();
        String host = p.getAsciiHost();
        boolean isDomain = p.getHostKind() == ParsedUrl.HostKind.DOMAIN;
        String reg = isDomain ? DomainHeuristics.registrableDomain(host) : host;

        // 1. User-info before '@': the real destination is what comes after the '@'
        if (p.hasUserInfo()) {
            String ui = p.getUserInfo();
            boolean looksLikeHost = ui.contains(".") && !ui.contains(":");
            if (looksLikeHost) {
                out.add(ind(DECEPTIVE_HOST_PLACEMENT, "Fake website name before '@'",
                        "The part before '@' looks like a website name, but your phone would actually go to the part after it.",
                        "'" + clip(ui, 60) + "@' → real destination: " + p.getDisplayHost(), ThreatSeverity.CRITICAL));
            } else {
                out.add(ind(USER_INFO, "Hidden login text in the address",
                        "The address has text and an '@' before the website name. Normal links almost never need this.",
                        "'" + clip(ui, 40) + "@" + p.getDisplayHost() + "'", ThreatSeverity.HIGH));
            }
        }

        // 2. IP address instead of a name
        if (p.getHostKind() == ParsedUrl.HostKind.IPV4_NONSTANDARD) {
            out.add(ind(NONSTANDARD_IP, "Disguised number address",
                    "The website is written as an unusual number format that browsers turn into an IP address. This hides where it really goes.",
                    host, ThreatSeverity.HIGH));
        } else if (p.getHostKind() == ParsedUrl.HostKind.IPV4 || p.getHostKind() == ParsedUrl.HostKind.IPV6) {
            out.add(ind(IP_LITERAL, "Numbers instead of a website name",
                    "The link uses a raw IP address instead of a website name, so you can't tell who runs it.",
                    host, ThreatSeverity.MEDIUM));
        }

        // 3. Encoded / unusual host forms detected during parsing
        if (p.getParseNotes().contains(UrlParser.NOTE_ENCODED_HOST)) {
            out.add(ind(ENCODED_HOST, "Scrambled website name",
                    "Part of the website name is written in %-codes. Real sites don't need this; it can hide the true name.",
                    clip(p.getRawHost(), 60) + " → " + p.getDisplayHost(), ThreatSeverity.HIGH));
        }
        if (p.getParseNotes().contains(UrlParser.NOTE_BACKSLASH)) {
            out.add(ind(BACKSLASH, "Backslashes in the address",
                    "The address uses '\\' where '/' is normal. Browsers quietly fix this, which tricksters use to confuse people.",
                    "\\", ThreatSeverity.MEDIUM));
        }

        // 4. International characters and mixed alphabets (homograph tricks)
        if (isDomain && p.isPunycode()) {
            String mixed = firstMixedScriptLabel(p.getUnicodeHost());
            if (mixed != null) {
                out.add(ind(MIXED_SCRIPT, "Mixed alphabets in the website name",
                        "Letters from different alphabets are mixed in one word. This is a common way to make a fake name look real.",
                        mixed + " (" + host + ")", ThreatSeverity.HIGH));
            } else {
                out.add(ind(PUNYCODE, "Special international letters",
                        "The name uses non-English letters. That's normal for many real sites, but some letters can look like English ones.",
                        p.getUnicodeHost() + " (" + host + ")", ThreatSeverity.LOW));
            }
        }

        // 5. Brand names and lookalikes
        if (isDomain) brandChecks(p, host, reg, out);

        // 6. Encoding tricks in path / query
        String pq = p.getPath() + (p.getQuery().isEmpty() ? "" : "?" + p.getQuery());
        String pqLower = pq.toLowerCase(Locale.ROOT);
        if (pqLower.contains("%00")) {
            out.add(ind(ENCODED_NULL, "Hidden 'null' character",
                    "The address contains %00, a hidden character used to trick filters.", "%00", ThreatSeverity.HIGH));
        }
        Matcher dbl = Pattern.compile("(?i)%25[0-9a-f]{2}").matcher(pq);
        if (dbl.find()) {
            out.add(ind(DOUBLE_ENCODING, "Double-scrambled characters",
                    "Some characters are encoded twice (%25..). This is sometimes used to slip past safety filters.",
                    dbl.group(), ThreatSeverity.MEDIUM));
        }
        int pctCount = 0;
        Matcher m = PCT.matcher(pq);
        while (m.find()) pctCount++;
        if (pq.length() >= 30 && pctCount * 3 > pq.length() * 0.4) {
            out.add(ind(HEAVY_ENCODING, "Mostly scrambled text",
                    "Most of the address after the website name is %-codes, which makes it hard to see what it does.",
                    pctCount + " encoded characters", ThreatSeverity.MEDIUM));
        }

        // 7. Redirect: another full address hidden inside this one
        Matcher em = EMBEDDED.matcher(pq);
        if (em.find()) {
            out.add(ind(EMBEDDED_URL, "Another link hidden inside",
                    "This address contains a second web address. It may send you somewhere other than the site shown first.",
                    clip(pq.substring(em.start()), 50), ThreatSeverity.MEDIUM));
        }

        // 8. Connection / structure
        if ("http".equals(p.getScheme()) && p.isSchemeExplicit()) {
            out.add(ind(NOT_ENCRYPTED, "Not a secure (https) link",
                    "This link uses http, not https. Anything typed on the page could be seen by others on the same network.",
                    "http://", ThreatSeverity.MEDIUM));
        }
        int port = p.getPort();
        if (port > 0 && port != 80 && port != 443) {
            out.add(ind(NON_STANDARD_PORT, "Unusual connection port",
                    "The address asks to connect on an unusual port number. Normal websites rarely do this.",
                    ":" + port, ThreatSeverity.LOW));
        }
        if (isDomain) {
            int labels = host.split("\\.").length;
            int regLabels = reg.split("\\.").length;
            if (labels - regLabels >= 4) {
                out.add(ind(MANY_SUBDOMAINS, "Very long website name",
                        "The website name has many parts stacked in front, which can push the real name out of view.",
                        clip(host, 80), ThreatSeverity.LOW));
            }
            String regLabel = DomainHeuristics.firstLabel(reg);
            int hy = 0;
            for (char c : regLabel.toCharArray()) if (c == '-') hy++;
            if (hy >= 3) {
                out.add(ind(MANY_HYPHENS, "Lots of dashes in the name",
                        "The main website name has many dashes. Scam sites often string words together like this.",
                        regLabel, ThreatSeverity.LOW));
            }
            if (DomainHeuristics.SHORTENERS.contains(reg)) {
                out.add(ind(SHORTENER, "Shortened link",
                        "This is a link shortener, so you can't see where it really goes until you open it.",
                        reg, ThreatSeverity.MEDIUM));
            }
            String suffix = DomainHeuristics.suffixOf(reg);
            if (DomainHeuristics.FREE_HOSTING_SUFFIXES.contains(suffix)) {
                out.add(ind(FREE_HOSTING, "Made on a free website builder",
                        "Anyone can make a page on " + suffix + " in minutes. That's fine for projects, but not for logins or prizes.",
                        suffix, ThreatSeverity.LOW));
            }
            String tld = host.substring(host.lastIndexOf('.') + 1);
            if (DomainHeuristics.FREQUENTLY_ABUSED_TLDS.contains(tld)) {
                out.add(ind(ABUSED_TLD, "Uncommon website ending (." + tld + ")",
                        "Endings like ." + tld + " are cheap and often used by short-lived scam pages — but many real sites use them too.",
                        "." + tld, ThreatSeverity.LOW));
            }
            List<String> lures = new ArrayList<>();
            for (String w : DomainHeuristics.LURE_WORDS) if (host.contains(w)) lures.add(w);
            if (!lures.isEmpty()) {
                out.add(ind(LURE_WORDS, "Tempting or official-sounding words",
                        "The website name contains words like '" + lures.get(0) + "' that tricky sites use to look official or exciting.",
                        String.join(", ", lures), lures.size() >= 2 ? ThreatSeverity.MEDIUM : ThreatSeverity.LOW));
            }
        }
        if (p.getOriginalInput().trim().length() > 200) {
            out.add(ind(VERY_LONG, "Very long address",
                    "The address is very long, which can hide the important part.",
                    p.getOriginalInput().trim().length() + " characters", ThreatSeverity.LOW));
        }
        return out;
    }

    private void brandChecks(ParsedUrl p, String host, String reg, List<UrlStructuralIndicator> out) {
        String regLabel = DomainHeuristics.firstLabel(reg);
        String sub = host.length() > reg.length() ? host.substring(0, host.length() - reg.length() - 1) : "";
        String regSkel = DomainHeuristics.skeleton(p.isPunycode() ? DomainHeuristics.firstLabel(DomainHeuristics.registrableDomain(p.getUnicodeHost())) : regLabel);

        for (Map.Entry<String, java.util.Set<String>> e : DomainHeuristics.BRANDS.entrySet()) {
            String brand = e.getKey();
            if (DomainHeuristics.isOfficial(brand, reg, host)) continue;

            // a) Brand used as a whole word in the subdomain part, e.g. roblox.com.claim-reward.top
            if (!sub.isEmpty() && containsToken(sub, brand)) {
                boolean mimicsFullDomain = false;
                for (String off : e.getValue()) if (sub.contains(off)) mimicsFullDomain = true;
                out.add(ind(DECEPTIVE_HOST_PLACEMENT, "Real company name in the wrong place",
                        "'" + brand + "' appears at the start, but the website actually belongs to " + reg + ".",
                        host + " → owned by " + reg, mimicsFullDomain ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH));
                return;
            }
            // b) Brand combined with other words in the main name, e.g. paypal-login.com
            if (!regLabel.equals(brand) && containsToken(regLabel, brand)) {
                out.add(ind(BRAND_ON_UNOFFICIAL, "Company name mixed into another website",
                        "The name uses '" + brand + "' plus extra words, but it is not " + brand + "'s official website.",
                        reg, ThreatSeverity.HIGH));
                return;
            }
            // c) Exact brand name on an unexpected ending, e.g. roblox.top (companies do own some country domains)
            if (regLabel.equals(brand)) {
                out.add(ind(BRAND_ON_UNOFFICIAL, "Company name on an unexpected ending",
                        "This uses the name '" + brand + "' but not its usual website ending. Some companies own several endings, so check carefully.",
                        reg, ThreatSeverity.MEDIUM));
                return;
            }
            // d) Lookalike spelling: same visual skeleton, or one character different
            String brandSkel = DomainHeuristics.skeleton(brand);
            if (regSkel.equals(brandSkel)) {
                out.add(ind(LOOKALIKE, "Looks like '" + brand + "' but isn't",
                        "The name is spelled with swapped lookalike letters or numbers to look like " + brand + ".",
                        reg + " ≈ " + brand, ThreatSeverity.HIGH));
                return;
            }
            if (brand.length() >= 6 && regSkel.length() >= 5 && DomainHeuristics.editDistance(regSkel, brandSkel) == 1) {
                out.add(ind(LOOKALIKE, "Very similar to '" + brand + "'",
                        "The name is one letter different from " + brand + ". This could be a typo-trap site.",
                        reg + " ≈ " + brand, ThreatSeverity.MEDIUM));
                return;
            }
        }
    }

    /** True if word appears in s as a whole token separated by '.', '-' or '_' (or s starts/ends with it). */
    static boolean containsToken(String s, String word) {
        for (String t : s.split("[.\\-_]")) if (t.equals(word)) return true;
        return false;
    }

    /** Returns the first label of the Unicode host that mixes Latin letters with Cyrillic/Greek/etc., or null. */
    static String firstMixedScriptLabel(String unicodeHost) {
        for (String label : unicodeHost.split("\\.")) {
            java.util.Set<Character.UnicodeScript> scripts = new java.util.HashSet<>();
            label.codePoints().forEach(cp -> {
                if (Character.isLetter(cp)) scripts.add(Character.UnicodeScript.of(cp));
            });
            if (scripts.size() > 1) return label;
            // Whole label in a lookalike-heavy script whose skeleton is pure ASCII, e.g. Cyrillic "раураl"
            if (scripts.size() == 1 && !scripts.contains(Character.UnicodeScript.LATIN)) {
                String sk = DomainHeuristics.skeleton(label);
                if (sk.chars().allMatch(c -> c < 128)) return label;
            }
        }
        return null;
    }

    private static UrlStructuralIndicator ind(String id, String name, String desc, String evidence, ThreatSeverity sev) {
        return new UrlStructuralIndicator(id, name, desc, evidence, sev);
    }

    private static String clip(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
