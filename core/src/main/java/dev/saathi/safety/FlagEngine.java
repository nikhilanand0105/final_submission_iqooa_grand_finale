package dev.saathi.safety;

import dev.saathi.safety.SafetyEvent.Alert;
import dev.saathi.safety.SafetyEvent.Category;
import dev.saathi.safety.SafetyEvent.Flag;
import dev.saathi.safety.SafetyEvent.Level;
import dev.saathi.safety.SafetyEvent.Review;
import dev.saathi.safety.SafetyTypes.ScamKind;
import dev.saathi.safety.SafetyTypes.SelfHarmKind;
import dev.saathi.safety.SafetyTypes.Severity;
import dev.saathi.safety.SafetyTypes.SourceType;
import dev.saathi.safety.SafetyTypes.Status;
import dev.saathi.safety.SafetyTypes.ThreatKind;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Turns a validated classification into a persisted event, decides flag levels and whether an alert is needed, and
 * computes the current state of the two independent flags (Threats, Suicide/Self-harm) from stored events.
 */
public final class FlagEngine {

    public static final long RAPID_DUPLICATE_COOLDOWN_MS = 15_000L;
    public static final long DEDUPE_WINDOW_MS = RAPID_DUPLICATE_COOLDOWN_MS;

    /** What the dispatcher should do for an event. */
    public enum AlertKind { NONE, THREAT_ALERT, SELF_HARM_SUPPORT, REVIEW_NOTICE, SCAM_NOTICE, WEBSITE_WARNING }

    public static final class Decision {
        public final SafetyEvent event;    // null when nothing worth storing
        public final AlertKind alert;
        public final boolean isUpdate;     // true when an existing event was updated (no duplicate alert unless escalated)

        Decision(SafetyEvent e, AlertKind a, boolean u) {
            event = e;
            alert = a;
            isUpdate = u;
        }
    }

    private FlagEngine() {}

    /** Stable key for duplicate suppression: same source, same app/host and same normalised content. */
    public static String dedupeKey(SourceType type, String sourceApp, String text) {
        String n = text == null ? "" : text.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest((type + "|" + sourceApp + "|" + n).getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < 12; i++) b.append(String.format("%02x", d[i]));
            return b.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Level threatLevel(SafetyClassification c) {
        if (c.threat == ThreatKind.NONE) return Level.CLEAR;
        if (c.threatSeverity.rank >= Severity.HIGH.rank && c.status == Status.COMPLETE) return Level.ACTIVE;
        return Level.NEEDS_REVIEW;
    }

    static Level selfHarmLevel(SafetyClassification c) {
        if (c.selfHarm.isPersonalRisk()) {
            return c.selfHarmSeverity.rank >= Severity.HIGH.rank && c.status == Status.COMPLETE ? Level.ACTIVE : Level.NEEDS_REVIEW;
        }
        if (c.selfHarm == SelfHarmKind.AMBIGUOUS && c.selfHarmSeverity.rank >= Severity.LOW.rank) return Level.NEEDS_REVIEW;
        return Level.CLEAR; // informational / news / none never raise the flag
    }

    /**
     * @param existing event with the same dedupe key inside the rapid duplicate window, or null
     * @return decision; event is null when the content raised nothing worth storing
     */
    public static Decision decide(SafetyClassification c, String modelOutcome, SourceType type, String sourceApp, String dedupeKey,
                                  SafetyEvent existing, long now) {
        Level sh = selfHarmLevel(c);
        Level th = threatLevel(c);
        Flag flag;
        Level level;
        Category cat;
        if (sh.ordinal() >= th.ordinal() && sh != Level.CLEAR) {
            flag = Flag.SELF_HARM;
            level = sh;
            cat = Category.SELF_HARM;
        } else if (th != Level.CLEAR) {
            flag = Flag.THREATS;
            level = th;
            cat = Category.THREAT;
        } else {
            flag = Flag.NONE;
            level = Level.CLEAR;
            if (c.status == Status.UNAVAILABLE || c.status == Status.PENDING) cat = Category.UNAVAILABLE;
            else if (c.website != SafetyTypes.WebsiteConcern.NONE && c.website != SafetyTypes.WebsiteConcern.UNKNOWN) cat = Category.WEBSITE;
            else if (c.age != SafetyTypes.AgeConcern.NONE && c.age != SafetyTypes.AgeConcern.UNKNOWN) cat = Category.AGE_SUITABILITY;
            else if (c.scam != ScamKind.NONE) cat = Category.SCAM;
            else return new Decision(null, AlertKind.NONE, false); // analysed, nothing found: not stored (privacy)
        }
        String sev = flag == Flag.SELF_HARM ? c.selfHarmSeverity.name() : flag == Flag.THREATS ? c.threatSeverity.name() : "NONE";
        AlertKind alert;
        if (flag == Flag.SELF_HARM) alert = level == Level.ACTIVE ? AlertKind.SELF_HARM_SUPPORT : AlertKind.REVIEW_NOTICE;
        else if (flag == Flag.THREATS) alert = level == Level.ACTIVE ? AlertKind.THREAT_ALERT : AlertKind.REVIEW_NOTICE;
        else if (cat == Category.WEBSITE || cat == Category.AGE_SUITABILITY) alert = AlertKind.WEBSITE_WARNING;
        else if (cat == Category.SCAM) alert = AlertKind.SCAM_NOTICE;
        else alert = AlertKind.NONE;

        boolean update = existing != null && (now - existing.createdAt < RAPID_DUPLICATE_COOLDOWN_MS);
        if (update) {
            boolean escalated = level.ordinal() > existing.level.ordinal();
            if (!escalated) alert = AlertKind.NONE; // rapid bounce within cooldown: no repeat alert
        }
        SafetyEvent e = new SafetyEvent(update ? existing.eventId : UUID.randomUUID().toString(), dedupeKey,
                update ? existing.createdAt : now, now, type, sourceApp, cat, flag, level, sev, c.confidence.name(), c.status,
                c.source, modelOutcome, c.evidence, explanationFor(c, flag), c.actions,
                update && existing.level == level ? existing.review : Review.NEW,
                alert == AlertKind.NONE ? (update ? existing.alert : Alert.NOT_NEEDED) : Alert.PENDING);
        return new Decision(e, alert, update);
    }

    private static String explanationFor(SafetyClassification c, Flag f) {
        StringBuilder b = new StringBuilder(c.explanation);
        for (String n : c.guardNotes) b.append(' ').append(n);
        return b.toString().trim();
    }

    /** Current state of one flag: the highest level among events that have not been reviewed or dismissed. */
    public static final class FlagState {
        public final Flag flag;
        public final Level level;
        public final int openEvents;
        public final long lastUpdated;
        public final String lastEventId;

        FlagState(Flag f, Level l, int n, long t, String id) {
            flag = f;
            level = l;
            openEvents = n;
            lastUpdated = t;
            lastEventId = id;
        }
    }

    public static FlagState compute(Flag flag, List<SafetyEvent> events) {
        Level best = Level.CLEAR;
        int open = 0;
        long last = 0;
        String lastId = null;
        for (SafetyEvent e : events) {
            if (e.flag != flag || e.review != Review.NEW) continue;
            open++;
            if (e.level.ordinal() > best.ordinal()) best = e.level;
            if (e.updatedAt > last) {
                last = e.updatedAt;
                lastId = e.eventId;
            }
        }
        return new FlagState(flag, best, open, last, lastId);
    }
}
