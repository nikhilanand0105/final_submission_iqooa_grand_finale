package dev.guardianai.shield.url;

import java.util.Collections;
import java.util.List;

/** Outcome of a single online reputation lookup, as reported by a {@link UrlReputationProvider}. */
public final class ReputationResult {

    public enum Outcome { THREAT_MATCH, NO_MATCH, NOT_CHECKED, UNAVAILABLE, TIMEOUT_OR_NETWORK }

    private final Outcome outcome;
    private final List<String> threatTypes;
    private final String detail;

    private ReputationResult(Outcome outcome, List<String> threatTypes, String detail) {
        this.outcome = outcome;
        this.threatTypes = threatTypes == null ? Collections.<String>emptyList() : Collections.unmodifiableList(threatTypes);
        this.detail = detail == null ? "" : detail;
    }

    public static ReputationResult threat(List<String> types) { return new ReputationResult(Outcome.THREAT_MATCH, types, ""); }
    public static ReputationResult noMatch() { return new ReputationResult(Outcome.NO_MATCH, null, ""); }
    public static ReputationResult notChecked(String why) { return new ReputationResult(Outcome.NOT_CHECKED, null, why); }
    public static ReputationResult unavailable(String why) { return new ReputationResult(Outcome.UNAVAILABLE, null, why); }
    public static ReputationResult timeout(String why) { return new ReputationResult(Outcome.TIMEOUT_OR_NETWORK, null, why); }

    public Outcome getOutcome() { return outcome; }
    public List<String> getThreatTypes() { return threatTypes; }
    /** Short technical reason (never contains the URL). */
    public String getDetail() { return detail; }
}
