package dev.guardianai.safety;

import dev.guardianai.safety.SafetyTypes.AgeConcern;
import dev.guardianai.safety.SafetyTypes.Confidence;
import dev.guardianai.safety.SafetyTypes.ScamKind;
import dev.guardianai.safety.SafetyTypes.SelfHarmKind;
import dev.guardianai.safety.SafetyTypes.Severity;
import dev.guardianai.safety.SafetyTypes.Source;
import dev.guardianai.safety.SafetyTypes.SourceType;
import dev.guardianai.safety.SafetyTypes.Status;
import dev.guardianai.safety.SafetyTypes.ThreatKind;
import dev.guardianai.safety.SafetyTypes.WebsiteConcern;
import dev.guardianai.util.Json;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Validates raw model output against the classification schema. The model is untrusted: unknown enum values,
 * missing fields, ungrounded evidence, inconsistent labels or forbidden claims cause rejection (→ rules fallback).
 */
public final class ClassificationParser {

    public static final class Result {
        public final SafetyClassification value; // null when rejected
        public final String rejection;

        Result(SafetyClassification v, String r) {
            value = v;
            rejection = r;
        }
    }

    private static final Pattern FORBIDDEN = Pattern.compile("(?iu)(100\\s*%|completely safe|totally safe|definitely safe|guaranteed"
            + "|is (a )?(criminal|predator|pedophile|psycho)|trust ?score|\\b\\d{1,3}\\s*% (likely|chance)|https?://"
            + "|(parent|parents|police|someone) (has|have) been (notified|told|alerted)|we (have )?(notified|alerted|contacted))");

    private ClassificationParser() {}

    public static Result parse(String raw, SourceType type, String analysedContent, String modelId) {
        if (raw == null || raw.trim().isEmpty()) return reject("empty output");
        String json = dev.guardianai.ai.explain.ModelOutputValidator.extractJsonObjectPublic(raw);
        if (json == null) return reject("no JSON object");
        Map<String, Object> o;
        try {
            o = Json.parseObject(json);
        } catch (Json.ParseException e) {
            return reject("malformed JSON");
        }
        ThreatKind threat = en(ThreatKind.class, Json.str(o, "threat"));
        Severity ts = en(Severity.class, Json.str(o, "threat_severity"));
        SelfHarmKind sh = en(SelfHarmKind.class, Json.str(o, "self_harm"));
        Severity ss = en(Severity.class, Json.str(o, "self_harm_severity"));
        ScamKind scam = en(ScamKind.class, Json.str(o, "scam"));
        AgeConcern age = o.containsKey("age") ? en(AgeConcern.class, Json.str(o, "age")) : AgeConcern.NONE;
        Confidence conf = en(Confidence.class, Json.str(o, "confidence"));
        List<String> evidence = Json.strList(o, "evidence");
        String expl = Json.str(o, "explanation");
        List<String> actions = Json.strList(o, "actions");
        if (threat == null || ts == null || sh == null || ss == null || scam == null || age == null || conf == null) {
            return reject("missing or unknown label value");
        }
        if (evidence == null || actions == null || expl == null) return reject("missing evidence/explanation/actions");
        expl = expl.replaceAll("\\s+", " ").trim();
        if (expl.isEmpty() || expl.length() > 400) return reject("explanation empty or too long");
        if (actions.size() > 5) actions = actions.subList(0, 5);
        for (String a : actions) if (a.length() > 200) return reject("action too long");

        // Consistency between labels and severities
        if ((threat == ThreatKind.NONE) != (ts == Severity.NONE)) return reject("threat label and severity disagree");
        if (!sh.isPersonalRisk() && ss.rank >= Severity.HIGH.rank) return reject("high self-harm severity without personal risk");
        if (sh == SelfHarmKind.NONE && ss != Severity.NONE) return reject("self-harm severity without label");

        // Evidence must be grounded in the analysed content (case/space-insensitive substring)
        String hay = norm(analysedContent);
        List<String> grounded = new ArrayList<>();
        for (String e : evidence) {
            String n = norm(e);
            if (n.length() >= 3 && n.length() <= 200 && hay.contains(n)) grounded.add(e.trim());
        }
        boolean claimsConcern = threat != ThreatKind.NONE || sh.isPersonalRisk() || scam != ScamKind.NONE;
        if (claimsConcern && grounded.isEmpty()) return reject("concern claimed without evidence found in the content");

        StringBuilder all = new StringBuilder(expl);
        for (String a : actions) all.append('\n').append(a);
        if (FORBIDDEN.matcher(all).find()) return reject("contains a disallowed claim");

        Status status = conf == Confidence.LOW && claimsConcern ? Status.NEEDS_REVIEW : Status.COMPLETE;
        if (sh == SelfHarmKind.AMBIGUOUS) status = Status.NEEDS_REVIEW;
        return new Result(new SafetyClassification(type, threat, ts, sh, ss, scam, WebsiteConcern.NONE, age, conf, grounded,
                expl, actions, status, Source.GEMMA, modelId, null), null);
    }

    static String norm(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
    }

    private static <E extends Enum<E>> E en(Class<E> c, String v) {
        if (v == null) return null;
        try {
            return Enum.valueOf(c, v.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Result reject(String why) {
        return new Result(null, why);
    }
}
