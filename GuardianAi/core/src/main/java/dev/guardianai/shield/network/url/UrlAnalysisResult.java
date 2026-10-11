package dev.guardianai.shield.network.url;

import dev.guardianai.model.ScanVerdict;
import dev.guardianai.model.ThreatSeverity;

import java.util.*;

/**
 * Complete security assessment combining local structural heuristics and online threat reputation.
 */
public class UrlAnalysisResult {

    private final ParsedUrl parsedUrl;
    private final List<UrlIndicator> indicators;
    private final ScanVerdict localVerdict;
    private final ReputationResult reputationResult;
    private final ScanVerdict combinedVerdict;
    private final ThreatSeverity overallSeverity;
    private final String plainAdvice;
    private final List<String> practicalNextSteps;
    private final String uncertaintyLimitations;

    public UrlAnalysisResult(
            ParsedUrl parsedUrl,
            List<UrlIndicator> indicators,
            ScanVerdict localVerdict,
            ReputationResult reputationResult) {
        this.parsedUrl = Objects.requireNonNull(parsedUrl, "parsedUrl cannot be null");
        this.indicators = indicators != null ? Collections.unmodifiableList(indicators) : Collections.emptyList();
        this.localVerdict = localVerdict != null ? localVerdict : ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        this.reputationResult = reputationResult != null ? reputationResult : ReputationResult.notChecked(null);

        // Compute combined verdict and overall severity
        ScanVerdict compVerdict = this.localVerdict;
        ThreatSeverity compSev = ThreatSeverity.INFO;

        for (UrlIndicator ind : this.indicators) {
            if (ind.getSeverity().getWeight() > compSev.getWeight()) {
                compSev = ind.getSeverity();
            }
        }

        // Online reputation overrides or modifies verdict
        if (this.reputationResult.getState() == ReputationState.THREAT_MATCH) {
            compVerdict = ScanVerdict.KNOWN_MALICIOUS;
            compSev = ThreatSeverity.CRITICAL;
        } else if (this.reputationResult.getState() == ReputationState.TIMEOUT_NETWORK_ERROR) {
            // A timeout must NEVER produce a clean result!
            if (compVerdict == ScanVerdict.NO_KNOWN_THREAT_DETECTED) {
                compVerdict = ScanVerdict.CAUTION;
                if (compSev.getWeight() < ThreatSeverity.MEDIUM.getWeight()) {
                    compSev = ThreatSeverity.MEDIUM;
                }
            }
        }

        this.combinedVerdict = compVerdict;
        this.overallSeverity = compSev;

        // Practical Next Steps and Plain Advice
        this.practicalNextSteps = buildNextSteps(compVerdict, this.reputationResult);
        this.plainAdvice = buildPlainAdvice(compVerdict, this.reputationResult);
        this.uncertaintyLimitations = buildLimitations(this.reputationResult);
    }

    public ParsedUrl getParsedUrl() {
        return parsedUrl;
    }

    public List<UrlIndicator> getIndicators() {
        return indicators;
    }

    public ScanVerdict getLocalVerdict() {
        return localVerdict;
    }

    public ReputationResult getReputationResult() {
        return reputationResult;
    }

    public ScanVerdict getCombinedVerdict() {
        return combinedVerdict;
    }

    public ThreatSeverity getOverallSeverity() {
        return overallSeverity;
    }

    public String getPlainAdvice() {
        return plainAdvice;
    }

    public List<String> getPracticalNextSteps() {
        return practicalNextSteps;
    }

    public String getUncertaintyLimitations() {
        return uncertaintyLimitations;
    }

    private List<String> buildNextSteps(ScanVerdict verdict, ReputationResult reputation) {
        List<String> steps = new ArrayList<>();
        if (verdict == ScanVerdict.KNOWN_MALICIOUS || verdict == ScanVerdict.HIGH_RISK) {
            steps.add("🛑 Do not open this link or proceed to the website.");
            steps.add("🔒 Never enter OTPs, bank account numbers, UPI PINs, or passwords on this address.");
            steps.add("📞 If you already entered credentials or transferred money, call the National Cyber Crime Helpline at 1930 immediately.");
            steps.add("💬 Block the sender who sent you this web address on SMS or messaging apps.");
        } else if (verdict == ScanVerdict.CAUTION) {
            steps.add("⚠️ Exercise caution: verify whether you expected to receive a link to this specific domain.");
            steps.add("🔍 If visiting for banking or official services, open a new browser tab and type the official website directly.");
            steps.add("🛡️ Ensure your browser displays the secure lock icon and that the full domain matches your bank's verified address.");
        } else {
            steps.add("✅ No structural threat indicators were detected on this address.");
            steps.add("🔍 Always verify that the website URL in your browser bar remains unchanged before entering sensitive login information.");
            steps.add("ℹ️ Remember that legitimate institutions will never send SMS links demanding urgent payment under threat of disconnection.");
        }
        return Collections.unmodifiableList(steps);
    }

    private String buildPlainAdvice(ScanVerdict verdict, ReputationResult reputation) {
        if (verdict == ScanVerdict.KNOWN_MALICIOUS) {
            return "🛑 DANGEROUS LINK DETECTED: This address exhibits confirmed threat indicators or deceptive brand impersonation. Do not interact with this page.";
        } else if (verdict == ScanVerdict.HIGH_RISK) {
            return "⚠️ HIGH RISK WARNING: Multiple suspicious structural indicators were observed. This link resembles patterns common in financial scams.";
        } else if (verdict == ScanVerdict.CAUTION) {
            if (reputation.getState() == ReputationState.TIMEOUT_NETWORK_ERROR) {
                return "⚠️ CAUTION: Network timeout occurred during live reputation lookup. The address cannot be confirmed clean; proceed with care.";
            }
            return "⚠️ CAUTION: Suspicious or unusual structural characteristics observed. Review the destination carefully before entering any details.";
        } else {
            return "✅ No known threat indicators detected by local heuristic analysis.";
        }
    }

    private String buildLimitations(ReputationResult reputation) {
        StringBuilder sb = new StringBuilder();
        sb.append("Analysis Scope & Limitations: Local heuristics inspect structural and syntactic anomalies (IP destinations, homoglyphs, deceptive subdomains, urgency lures). ");
        if (reputation.getState() == ReputationState.NOT_CHECKED) {
            sb.append("Live online reputation was NOT checked (provider unconfigured). Local analysis cannot guarantee that an unknown domain does not host zero-day phishing content.");
        } else if (reputation.getState() == ReputationState.TIMEOUT_NETWORK_ERROR) {
            sb.append("Live reputation lookup encountered a network timeout; live database status is unverified and cannot be assumed safe.");
        } else if (reputation.getState() == ReputationState.PROVIDER_UNAVAILABLE) {
            sb.append("Live reputation provider is currently unavailable. Relying exclusively on on-device local heuristics.");
        } else {
            sb.append("Live reputation was checked via ").append(reputation.getProviderName()).append(".");
        }
        return sb.toString();
    }
}
