package dev.saathi.ai.explain;

import dev.saathi.util.Json;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates and constrains raw model text before it can be shown. Output is rejected (and the rules-based
 * explanation used instead) if it is not the requested JSON, cites findings that do not exist, or makes claims
 * the analyzer did not establish.
 */
public final class ModelOutputValidator {

    public static final class Result {
        public final SafetyExplanation explanation; // null when rejected
        public final String rejectionReason;        // null when accepted

        private Result(SafetyExplanation e, String r) {
            explanation = e;
            rejectionReason = r;
        }
    }

    static final int MAX_SUMMARY = 700;
    static final int MAX_STEP = 220;
    static final int MAX_STEPS = 5;
    static final int MAX_LIMITATIONS = 300;

    /** Claims that are never allowed. */
    private static final Pattern FORBIDDEN = Pattern.compile("(?iu)("
            + "100\\s*%|completely safe|totally safe|perfectly safe|definitely safe|guaranteed|malware[- ]free|virus[- ]free"
            + "|definitely (a )?(scam|fake|virus|malware)|is (a )?(scammer|criminal|predator|pedophile|bad person)"
            + "|trust ?score|risk score|\\b\\d{1,3}\\s*% (likely|chance|sure)"
            + "|(parent|parents|guardian|adult|police|they|someone)\\s+(has|have)\\s+been\\s+(notified|told|alerted|informed)"
            + "|help is on (the|its) way|we (have )?(notified|told|alerted|contacted|reported)|i (have )?(notified|told|alerted|contacted|reported)"
            + "|message (was|has been) (delivered|seen|read)"
            + "|<\\s*script|https?://"
            + ")");

    /** Claims about external threat intelligence, only allowed when CHECK_STATUS establishes a threat match. */
    private static final Pattern THREAT_INTEL_CLAIM = Pattern.compile("(?iu)(google (says|lists|listed|reports|reported|flagged|confirmed)|web risk|safe browsing|virustotal|blacklist|blocklist"
            + "|threat database|reported (as|for) (phishing|malware|scam)|known (scam|phishing|malware) (site|app|link))");

    private ModelOutputValidator() {}

    public static Result validate(String raw, FindingSet fs, String modelId, String language, boolean threatMatchEstablished) {
        if (raw == null || raw.trim().isEmpty()) return reject("empty output");
        String json = extractJsonObject(raw);
        if (json == null) return reject("no JSON object found");
        Map<String, Object> o;
        try {
            o = Json.parseObject(json);
        } catch (Json.ParseException e) {
            return reject("malformed JSON: " + e.getMessage());
        }
        String summary = clean(Json.str(o, "summary"));
        List<String> refs = Json.strList(o, "evidence_refs");
        List<String> steps = Json.strList(o, "next_steps");
        String lim = clean(Json.str(o, "limitations"));
        if (summary == null || summary.isEmpty()) return reject("missing summary");
        if (summary.length() > MAX_SUMMARY) return reject("summary too long");
        if (refs == null) return reject("missing evidence_refs");
        if (steps == null || steps.isEmpty()) return reject("missing next_steps");

        Set<String> ids = fs.ids();
        Set<String> cleanRefs = new LinkedHashSet<>();
        for (String r : refs) {
            String t = r == null ? "" : r.trim();
            if (!ids.contains(t)) return reject("cites unknown finding '" + clip(t) + "'");
            cleanRefs.add(t);
        }
        if (!fs.findings.isEmpty() && cleanRefs.isEmpty()) return reject("does not cite any finding");

        List<String> cleanSteps = new ArrayList<>();
        for (String s : steps) {
            String c = clean(s);
            if (c == null || c.isEmpty()) continue;
            if (c.length() > MAX_STEP) return reject("next step too long");
            cleanSteps.add(c);
            if (cleanSteps.size() == MAX_STEPS) break;
        }
        if (cleanSteps.isEmpty()) return reject("no usable next steps");
        if (lim != null && lim.length() > MAX_LIMITATIONS) lim = lim.substring(0, MAX_LIMITATIONS);

        StringBuilder all = new StringBuilder(summary).append('\n').append(lim == null ? "" : lim);
        for (String s : cleanSteps) all.append('\n').append(s);
        String text = all.toString();
        if (FORBIDDEN.matcher(text).find()) return reject("contains a claim that is not allowed");
        if (!threatMatchEstablished && THREAT_INTEL_CLAIM.matcher(text).find()) return reject("claims a threat-database result that was not established");
        if ("hi".equals(language) && !containsDevanagari(summary)) return reject("summary is not in Hindi");

        String limitations = lim == null || lim.isEmpty() ? fs.limitations : lim;
        return new Result(new SafetyExplanation(SafetyExplanation.Source.ON_DEVICE_MODEL, modelId, summary,
                new ArrayList<>(cleanRefs), cleanSteps, limitations, language), null);
    }

    /** Public access to the JSON-object extractor for other validators of model output. */
    public static String extractJsonObjectPublic(String raw) {
        return extractJsonObject(raw);
    }

    /** Returns the first balanced {...} block (ignoring braces inside strings), tolerating ```json fences. */
    static String extractJsonObject(String raw) {
        int start = raw.indexOf('{');
        if (start < 0) return null;
        int depth = 0;
        boolean inStr = false, esc = false;
        for (int i = start; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return raw.substring(start, i + 1);
        }
        return null;
    }

    /** Strips markup/control characters and collapses whitespace. */
    static String clean(String s) {
        if (s == null) return null;
        String t = s.replaceAll("[\\p{Cntrl}&&[^\\n]]", " ").replaceAll("[*_`#>]+", "").replaceAll("\\s+", " ").trim();
        return t;
    }

    private static boolean containsDevanagari(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'ऀ' && c <= 'ॿ') return true;
        }
        return false;
    }

    private static String clip(String s) {
        return s.length() > 40 ? s.substring(0, 40) + "…" : s;
    }

    private static Result reject(String why) {
        return new Result(null, why);
    }
}
