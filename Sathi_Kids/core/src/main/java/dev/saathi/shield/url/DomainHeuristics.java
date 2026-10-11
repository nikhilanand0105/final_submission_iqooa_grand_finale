package dev.saathi.shield.url;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Explainable domain rule data and helpers used by {@link UrlLocalAnalyzer}.
 *
 * These tables are rule definitions (which brands are commonly impersonated and what their main official
 * domains are; which suffixes are multi-part), NOT a list of malicious domains. A match only means
 * "this address has a structural property worth explaining", never "this site is malicious".
 */
final class DomainHeuristics {

    private DomainHeuristics() {}

    /**
     * Approximate registrable-domain suffixes with more than one label. This is a small subset of the
     * Public Suffix List; unknown multi-part suffixes fall back to the last two labels.
     */
    static final Set<String> MULTI_PART_SUFFIXES = set(
            "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in", "nic.in", "bank.in", "mil.in",
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz",
            "com.br", "com.cn", "com.sg", "com.my", "co.jp", "co.za", "com.mx", "com.tr", "com.pk", "com.bd", "co.id",
            // Shared hosting platforms where each customer gets their own subdomain
            "github.io", "blogspot.com", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
            "herokuapp.com", "glitch.me", "000webhostapp.com", "weebly.com", "wixsite.com", "wordpress.com",
            "sites.google.com", "carrd.co", "framer.website", "webflow.io", "ngrok.io", "ngrok-free.app", "trycloudflare.com");

    /** Platforms where anyone can publish a page instantly under the platform's name. */
    static final Set<String> FREE_HOSTING_SUFFIXES = set(
            "github.io", "blogspot.com", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
            "herokuapp.com", "glitch.me", "000webhostapp.com", "weebly.com", "wixsite.com", "wordpress.com",
            "sites.google.com", "carrd.co", "framer.website", "webflow.io", "ngrok.io", "ngrok-free.app", "trycloudflare.com");

    /** Link-shortening services: the visible address does not reveal the final destination. */
    static final Set<String> SHORTENERS = set(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
            "ow.ly", "buff.ly", "rebrand.ly", "t.ly", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink", "lnkd.in");

    /**
     * Top-level domains that are cheap/free to register and are disproportionately common in short-lived scam
     * pages. Many legitimate sites also use them, so this is only ever a LOW-severity note.
     */
    static final Set<String> FREQUENTLY_ABUSED_TLDS = set(
            "zip", "mov", "top", "xyz", "click", "link", "cfd", "sbs", "buzz", "rest", "icu", "tk", "ml", "ga",
            "cf", "gq", "monster", "cyou", "quest", "bond");

    /** Words that phishing pages put in host names to look official or tempting. */
    static final List<String> LURE_WORDS = Collections.unmodifiableList(Arrays.asList(
            "login", "signin", "verify", "verification", "secure", "account", "update", "wallet", "support",
            "gift", "reward", "free", "claim", "prize", "bonus", "robux", "vbucks", "diamond", "giveaway", "unlock",
            "winner", "offer", "kyc", "otp"));

    /**
     * Impersonation keyword -> official registrable domains, from the versioned {@link OfficialDomainRegistry}
     * resource (not hardcoded here).
     */
    static final Map<String, Set<String>> BRANDS = OfficialDomainRegistry.bundled().keywordMap();

    private static Set<String> set(String... v) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(v)));
    }

    /** eTLD+1 approximation for an ASCII (punycode) host. */
    static String registrableDomain(String asciiHost) {
        String[] l = asciiHost.split("\\.");
        if (l.length <= 2) return asciiHost;
        for (int take = Math.min(4, l.length - 1); take >= 2; take--) {
            String suffix = join(l, l.length - take);
            if (MULTI_PART_SUFFIXES.contains(suffix)) {
                return join(l, l.length - take - 1);
            }
        }
        return join(l, l.length - 2);
    }

    static String suffixOf(String registrable) {
        int d = registrable.indexOf('.');
        return d < 0 ? "" : registrable.substring(d + 1);
    }

    static String firstLabel(String domain) {
        int d = domain.indexOf('.');
        return d < 0 ? domain : domain.substring(0, d);
    }

    private static String join(String[] l, int from) {
        StringBuilder b = new StringBuilder();
        for (int k = from; k < l.length; k++) {
            if (b.length() > 0) b.append('.');
            b.append(l[k]);
        }
        return b.toString();
    }

    static boolean isOfficial(String brand, String registrable, String asciiHost) {
        Set<String> off = BRANDS.get(brand);
        if (off == null) return false;
        if (off.contains(registrable)) return true;
        for (String d : off) {
            if (asciiHost.equals(d) || asciiHost.endsWith("." + d)) return true;
        }
        return false;
    }

    private static final Map<Character, Character> CONFUSABLE = new HashMap<>();

    static {
        // digit / symbol substitutions
        put('0', 'o'); put('1', 'l'); put('i', 'l'); put('|', 'l'); put('!', 'l');
        put('3', 'e'); put('4', 'a'); put('@', 'a'); put('5', 's'); put('$', 's'); put('7', 't'); put('8', 'b');
        // Cyrillic lookalikes
        put('а', 'a'); put('е', 'e'); put('о', 'o'); put('р', 'p'); put('с', 'c');
        put('у', 'y'); put('х', 'x'); put('і', 'l'); put('ј', 'j'); put('ѕ', 's');
        put('һ', 'h'); put('ӏ', 'l'); put('ԁ', 'd'); put('ԛ', 'q'); put('ԝ', 'w');
        // Greek lookalikes
        put('ο', 'o'); put('α', 'a'); put('ε', 'e'); put('ρ', 'p'); put('ν', 'v');
        put('τ', 't'); put('ι', 'l'); put('κ', 'k');
    }

    private static void put(char a, char b) {
        CONFUSABLE.put(a, b);
    }

    /**
     * Visual "skeleton" of a label: lower-cases, maps common lookalike characters to a canonical letter and
     * collapses multi-character lookalikes (rn->m, vv->w, cl->d). Two labels with the same skeleton look alike.
     */
    static String skeleton(String label) {
        String s = label.toLowerCase(Locale.ROOT).replace("-", "");
        StringBuilder b = new StringBuilder(s.length());
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            Character m = CONFUSABLE.get(c);
            b.append(m != null ? m : c);
        }
        return b.toString().replace("rn", "m").replace("vv", "w").replace("cl", "d");
    }

    /** Optimal string alignment (Damerau-Levenshtein) distance, bounded for short labels. */
    static int editDistance(String a, String b) {
        if (Math.abs(a.length() - b.length()) > 2) return 3;
        int[][] d = new int[a.length() + 1][b.length() + 1];
        for (int x = 0; x <= a.length(); x++) d[x][0] = x;
        for (int y = 0; y <= b.length(); y++) d[0][y] = y;
        for (int x = 1; x <= a.length(); x++) {
            for (int y = 1; y <= b.length(); y++) {
                int cost = a.charAt(x - 1) == b.charAt(y - 1) ? 0 : 1;
                d[x][y] = Math.min(Math.min(d[x - 1][y] + 1, d[x][y - 1] + 1), d[x - 1][y - 1] + cost);
                if (x > 1 && y > 1 && a.charAt(x - 1) == b.charAt(y - 2) && a.charAt(x - 2) == b.charAt(y - 1)) {
                    d[x][y] = Math.min(d[x][y], d[x - 2][y - 2] + 1);
                }
            }
        }
        return d[a.length()][b.length()];
    }
}
