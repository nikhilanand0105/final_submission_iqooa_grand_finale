package dev.saathi.shield.url;

import dev.saathi.model.ThreatSeverity;

/**
 * Combines exact official-domain matching, the structural indicators and the reputation outcome into one of five
 * distinct outcomes. Being absent from a threat list never yields "recognised".
 */
public final class DomainTrust {

    public enum Outcome { RECOGNISED_OFFICIAL, OFFICIALLY_LINKED_LEGACY, SUSPECTED_SPOOF, KNOWN_HARMFUL, UNKNOWN, UNAVAILABLE }

    public final Outcome outcome;
    public final String organisation; // for RECOGNISED_OFFICIAL / OFFICIALLY_LINKED_LEGACY / SUSPECTED_SPOOF, else null
    public final String reason;

    private DomainTrust(Outcome o, String org, String reason) {
        this.outcome = o;
        this.organisation = org;
        this.reason = reason;
    }

    /** A reputation hit reported directly by another component (e.g. the system WebView's Safe Browsing). */
    public static DomainTrust knownHarmful(String reportedBy) {
        return new DomainTrust(Outcome.KNOWN_HARMFUL, null, "Listed as dangerous by " + reportedBy);
    }

    public static DomainTrust evaluate(UrlAnalysisResult r, OfficialDomainRegistry reg) {
        return evaluate(r, reg, BankDomainRegistry.bundled());
    }

    public static DomainTrust evaluate(UrlAnalysisResult r, OfficialDomainRegistry reg, BankDomainRegistry bankReg) {
        ParsedUrl p = r.getParsedUrl();
        if (!p.isValid()) return new DomainTrust(Outcome.UNAVAILABLE, null, "The address isn't valid: " + p.getValidationError());
        if (r.getStatus() == ReputationStatus.THREAT_MATCH) {
            return new DomainTrust(Outcome.KNOWN_HARMFUL, null, "Listed as dangerous by " + r.getProviderName());
        }
        String host = p.getAsciiHost();
        boolean deceptive = false;
        String why = null;
        for (UrlStructuralIndicator i : r.getLocalIndicators()) {
            String id = i.getId();
            boolean impersonation = id.equals(UrlLocalAnalyzer.LOOKALIKE) || id.equals(UrlLocalAnalyzer.DECEPTIVE_HOST_PLACEMENT)
                    || id.equals(UrlLocalAnalyzer.MIXED_SCRIPT)
                    || (id.equals(UrlLocalAnalyzer.BRAND_ON_UNOFFICIAL) && i.getSeverity().getWeight() >= ThreatSeverity.HIGH.getWeight());
            if (impersonation) {
                deceptive = true;
                why = i.getName() + ": " + i.getEvidenceExcerpt();
                break;
            }
        }
        boolean isDomainHost = p.getHostKind() == ParsedUrl.HostKind.DOMAIN && !p.hasUserInfo();

        // 1. Check Bank Domain Registry (RBI .bank.in namespace and official legacy portals)
        if (isDomainHost && bankReg != null && !deceptive) {
            BankDomainRegistry.BankEntry bank = bankReg.findBank(host);
            if (bank != null) {
                if (bank.matchesPrimary(host)) {
                    return new DomainTrust(Outcome.RECOGNISED_OFFICIAL, bank.bankName,
                            "Verified official banking domain under RBI .bank.in namespace (" + host + ")"
                                    + (r.getStatus() == ReputationStatus.NO_KNOWN_THREAT ? "; no known warning found" : ""));
                } else if (bank.matchesLegacy(host)) {
                    return new DomainTrust(Outcome.OFFICIALLY_LINKED_LEGACY, bank.bankName,
                            "Officially linked legacy banking domain for " + bank.bankName + " (" + host + ")"
                                    + (r.getStatus() == ReputationStatus.NO_KNOWN_THREAT ? "; no known warning found" : ""));
                }
            }
        }

        // 2. Check general Official Domain Registry
        OfficialDomainRegistry.Org owner = isDomainHost ? reg.ownerOf(host) : null;
        if (owner != null && !deceptive) {
            return new DomainTrust(Outcome.RECOGNISED_OFFICIAL, owner.name,
                    "This is an official " + owner.name + " domain" + (r.getStatus() == ReputationStatus.NO_KNOWN_THREAT ? "; no known warning found" : ""));
        }
        if (deceptive) {
            String org = null;
            if (bankReg != null) {
                for (BankDomainRegistry.BankEntry b : bankReg.banks) {
                    if (why != null && why.toLowerCase(java.util.Locale.ROOT).contains(b.bankId)) {
                        org = b.bankName;
                        break;
                    }
                }
            }
            if (org == null) {
                for (OfficialDomainRegistry.Org o : reg.orgs) {
                    for (String k : o.keywords) if (why != null && why.toLowerCase(java.util.Locale.ROOT).contains(k)) org = o.name;
                    if (org != null) break;
                }
            }
            return new DomainTrust(Outcome.SUSPECTED_SPOOF, org, why);
        }
        if (r.getStatus() == ReputationStatus.TIMEOUT_OR_NETWORK_ERROR || r.getStatus() == ReputationStatus.PROVIDER_UNAVAILABLE) {
            return new DomainTrust(Outcome.UNAVAILABLE, null, "The online safety check didn't complete");
        }
        return new DomainTrust(Outcome.UNKNOWN, null, r.getStatus() == ReputationStatus.NO_KNOWN_THREAT
                ? "Not a recognised official site; no known warning listed (that isn't proof it's safe)"
                : "Not a recognised official site; online safety list not checked");
    }
}
