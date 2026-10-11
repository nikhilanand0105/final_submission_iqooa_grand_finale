package dev.saathi.shield.url;

import dev.saathi.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Coordinates a link check: parse → local structural heuristics → optional online reputation lookup → verdict.
 * The online lookup only runs when a provider is configured AND the caller passes {@code liveLookupAllowed}
 * (i.e. the child has seen the disclosure). Errors and timeouts never produce a clean verdict.
 */
public class UrlSafetyAnalyzer {

    private final UrlParser parser;
    private final UrlLocalAnalyzer local;
    private final UrlReputationProvider provider;

    public UrlSafetyAnalyzer() {
        this(UrlReputationProvider.NONE);
    }

    public UrlSafetyAnalyzer(UrlReputationProvider provider) {
        this.parser = new UrlParser();
        this.local = new UrlLocalAnalyzer();
        this.provider = provider == null ? UrlReputationProvider.NONE : provider;
    }

    public UrlReputationProvider getProvider() {
        return provider;
    }

    /** Local-only analysis (no network). */
    public UrlAnalysisResult analyze(String raw) {
        return analyze(raw, false);
    }

    public UrlAnalysisResult analyze(String raw, boolean liveLookupAllowed) {
        long now = System.currentTimeMillis();
        ParsedUrl p = parser.parse(raw);
        if (!p.isValid()) {
            List<String> steps = new ArrayList<>();
            steps.add("Check the address for typing mistakes");
            steps.add("Copy the whole link again from where you found it");
            steps.add("Don't open a link you can't read properly — ask a trusted adult");
            return new UrlAnalysisResult(p, UrlRiskVerdict.CANNOT_TELL, ReputationStatus.INVALID_INPUT, null,
                    "Not checked online because the address isn't valid.", new ArrayList<UrlStructuralIndicator>(),
                    "This doesn't look like a complete web address: " + p.getValidationError() + ".",
                    "A web address needs a proper website name, like https://example.com.",
                    steps, "Nothing was checked because the address couldn't be read.", "", now);
        }

        List<UrlStructuralIndicator> inds = new ArrayList<>(local.analyze(p));
        inds.sort(Comparator.comparingInt((UrlStructuralIndicator i) -> i.getSeverity().getWeight()).reversed());

        ReputationResult rep = null;
        String liveNote;
        if (!provider.isConfigured()) {
            liveNote = "The online safety list isn't set up in this version of the app, so only this phone's checks ran.";
        } else if (!liveLookupAllowed) {
            liveNote = "You chose to check on this phone only, so the online safety list wasn't asked.";
        } else {
            try {
                rep = provider.check(p);
            } catch (RuntimeException e) {
                rep = ReputationResult.unavailable("Safety service error");
            }
            if (rep == null) rep = ReputationResult.unavailable("No answer from safety service");
            switch (rep.getOutcome()) {
                case THREAT_MATCH: liveNote = provider.getName() + " lists this address as dangerous."; break;
                case NO_MATCH: liveNote = provider.getName() + " has no warning for this address right now."; break;
                case TIMEOUT_OR_NETWORK: liveNote = "The online check didn't finish (" + rep.getDetail() + ")."; break;
                case UNAVAILABLE: liveNote = "The online check couldn't be used (" + rep.getDetail() + ")."; break;
                default: liveNote = "The online safety list wasn't checked (" + rep.getDetail() + ")."; break;
            }
        }

        ReputationStatus status = statusFor(rep, !inds.isEmpty());
        UrlRiskVerdict verdict = verdictFor(status, inds);
        return build(p, verdict, status, rep, liveNote, inds, now);
    }

    static ReputationStatus statusFor(ReputationResult rep, boolean hasLocal) {
        if (rep == null) return hasLocal ? ReputationStatus.LOCAL_WARNINGS_ONLY : ReputationStatus.LIVE_NOT_CHECKED;
        switch (rep.getOutcome()) {
            case THREAT_MATCH: return ReputationStatus.THREAT_MATCH;
            case NO_MATCH: return ReputationStatus.NO_KNOWN_THREAT;
            case TIMEOUT_OR_NETWORK: return ReputationStatus.TIMEOUT_OR_NETWORK_ERROR;
            case UNAVAILABLE: return ReputationStatus.PROVIDER_UNAVAILABLE;
            default: return hasLocal ? ReputationStatus.LOCAL_WARNINGS_ONLY : ReputationStatus.LIVE_NOT_CHECKED;
        }
    }

    static UrlRiskVerdict verdictFor(ReputationStatus status, List<UrlStructuralIndicator> inds) {
        if (status == ReputationStatus.THREAT_MATCH) return UrlRiskVerdict.WARNING_SIGNS;
        int crit = 0, high = 0, med = 0;
        for (UrlStructuralIndicator i : inds) {
            if (i.getSeverity() == ThreatSeverity.CRITICAL) crit++;
            else if (i.getSeverity() == ThreatSeverity.HIGH) high++;
            else if (i.getSeverity() == ThreatSeverity.MEDIUM) med++;
        }
        if (crit > 0 || high >= 2) return UrlRiskVerdict.WARNING_SIGNS;
        if (high > 0 || med > 0) return UrlRiskVerdict.BE_CAREFUL;
        // Only minor or no local signs. A failed online check must not turn into a clean result.
        if (status == ReputationStatus.TIMEOUT_OR_NETWORK_ERROR || status == ReputationStatus.PROVIDER_UNAVAILABLE) {
            return UrlRiskVerdict.CANNOT_TELL;
        }
        return UrlRiskVerdict.NO_WARNING_SIGNS_FOUND;
    }

    private UrlAnalysisResult build(ParsedUrl p, UrlRiskVerdict v, ReputationStatus st, ReputationResult rep,
                                    String liveNote, List<UrlStructuralIndicator> inds, long now) {
        String host = p.getDisplayHost();
        UrlStructuralIndicator top = inds.isEmpty() ? null : inds.get(0);
        String summary;
        String why;
        List<String> steps = new ArrayList<>();
        switch (v) {
            case WARNING_SIGNS:
                summary = st == ReputationStatus.THREAT_MATCH
                        ? "The online safety list says this link (" + host + ") is dangerous."
                        : "This link to " + host + " has strong signs of a trick: " + top.getName().toLowerCase() + ".";
                why = st == ReputationStatus.THREAT_MATCH
                        ? "Sites on this list have been reported for " + threatWords(rep) + "."
                        : top.getDescription();
                steps.add("Don't open the link");
                steps.add("Never type a password, OTP or phone number on this site");
                steps.add("Show it to a trusted adult, especially if someone pressured you to click");
                steps.add("You can block or report whoever sent it");
                break;
            case BE_CAREFUL:
                summary = "This link to " + host + " has " + (inds.size() == 1 ? "a warning sign" : inds.size() + " warning signs") + " worth a closer look.";
                why = top.getDescription();
                steps.add("Only open it if you know and trust who sent it");
                steps.add("If it asks you to log in, close it and open the real app instead");
                steps.add("Ask a trusted adult if you're unsure");
                break;
            case CANNOT_TELL:
                summary = "The online check for " + host + " didn't finish, so I can't tell you more than what's in the address.";
                why = "When a check can't finish, it's safest not to treat the link as okay.";
                steps.add("Wait and check again when you have internet");
                steps.add("Don't open the link until you can check it or ask an adult");
                break;
            default:
                summary = st == ReputationStatus.NO_KNOWN_THREAT
                        ? "No warning signs found in this address, and the online safety list has nothing on " + host + "."
                        : "No warning signs found in the address " + host + ".";
                why = "That's a good sign, but it can't show what the page itself will ask you to do.";
                steps.add("If the page asks for a password, OTP or money, close it");
                steps.add("Don't download files from pages you don't know");
                steps.add("Ask a trusted adult if anything feels off");
                break;
        }

        StringBuilder lim = new StringBuilder("These are warning signs, not proof. The address was checked, not the page content.");
        if (!st.isLiveLookupCompleted()) lim.append(" ").append(st == ReputationStatus.LIVE_NOT_CHECKED || st == ReputationStatus.LOCAL_WARNINGS_ONLY
                ? "The online safety list was not checked." : "The online check did not complete.");
        else lim.append(" New scam pages may not be on any list yet.");
        return new UrlAnalysisResult(p, v, st, rep, liveNote, inds, summary, why, steps, lim.toString(),
                rep == null ? "" : provider.getName(), now);
    }

    private static String threatWords(ReputationResult rep) {
        List<String> w = new ArrayList<>();
        for (String t : rep.getThreatTypes()) {
            if (t.startsWith("SOCIAL_ENGINEERING")) { if (!w.contains("tricking people (phishing)")) w.add("tricking people (phishing)"); }
            else if (t.equals("MALWARE")) w.add("spreading harmful software");
            else if (t.equals("UNWANTED_SOFTWARE")) w.add("pushing unwanted apps");
        }
        return w.isEmpty() ? "being harmful" : String.join(" and ", w);
    }
}
