package dev.guardianai.rules;

import dev.guardianai.model.*;

import java.util.*;

/**
 * Orchestrates threat rule evaluation and synthesizes raw evidence into a weighted risk determination.
 */
public class ThreatRuleEvaluator {

    private final List<SecurityRule> registeredRules = new ArrayList<>();
    private final Set<String> knownMaliciousHashes = new HashSet<>();

    public ThreatRuleEvaluator() {
        // Register default static heuristic rules
        registeredRules.add(new WhatsAppModRule());
        registeredRules.add(new BankingTrojanPatternRule());
        registeredRules.add(new OtpStealerPatternRule());
        registeredRules.add(new DropperRansomwareRule());
        registeredRules.add(new SpywareSurveillanceRule());
        registeredRules.add(new CertificateRiskRule());
        registeredRules.add(new ScreenShareAbuseRule());
        registeredRules.add(new TollFraudSmsRule());

        // Known malware samples for reputation matching (e.g. Cerberus, Flubot, Sharkbot hashes)
        knownMaliciousHashes.add("3a019b88f8d2dfbb187b47b4d187bdf559ef14c1d686f0b4d45543c8d1720d29");
        knownMaliciousHashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // placeholder test
    }

    public void addRule(SecurityRule rule) {
        registeredRules.add(rule);
    }

    public void registerKnownMaliciousHash(String sha256Hex) {
        if (sha256Hex != null) {
            knownMaliciousHashes.add(sha256Hex.toLowerCase());
        }
    }

    public List<ThreatIndicator> evaluateAll(
            String sha256Checksum,
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {
        return evaluateAll(sha256Checksum, null, manifest, dex, certificate, hiddenPayloads);
    }

    public List<ThreatIndicator> evaluateAll(
            String sha256Checksum,
            String fileName,
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> collected = new ArrayList<>();

        // 1. Reputation Check
        if (sha256Checksum != null && knownMaliciousHashes.contains(sha256Checksum.toLowerCase())) {
            collected.add(new ThreatIndicator(
                    "KNOWN_MALWARE_HASH_MATCH",
                    "Known Malicious Application Hash Match",
                    "The cryptographic hash of this APK matches a verified malware sample in the threat intelligence registry.",
                    ThreatSeverity.CRITICAL,
                    "REPUTATION"
            ));
        }

        // 2. Evaluate all rules
        for (SecurityRule rule : registeredRules) {
            try {
                List<ThreatIndicator> ruleIndicators;
                if (rule instanceof WhatsAppModRule) {
                    ruleIndicators = ((WhatsAppModRule) rule).evaluate(manifest, dex, certificate, hiddenPayloads, fileName);
                } else {
                    ruleIndicators = rule.evaluate(manifest, dex, certificate, hiddenPayloads);
                }
                if (ruleIndicators != null) {
                    collected.addAll(ruleIndicators);
                }
            } catch (Exception ignored) {
            }
        }

        return collected;
    }

    public ScanVerdict determineVerdict(String sha256Checksum, List<ThreatIndicator> indicators, boolean parseSucceeded) {
        if (!parseSucceeded) {
            return ScanVerdict.UNABLE_TO_DETERMINE;
        }

        if (sha256Checksum != null && knownMaliciousHashes.contains(sha256Checksum.toLowerCase())) {
            return ScanVerdict.KNOWN_MALICIOUS;
        }

        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;

        for (ThreatIndicator ti : indicators) {
            if (ti.getSeverity() == ThreatSeverity.CRITICAL) criticalCount++;
            else if (ti.getSeverity() == ThreatSeverity.HIGH) highCount++;
            else if (ti.getSeverity() == ThreatSeverity.MEDIUM) mediumCount++;
        }

        if (criticalCount > 0 || highCount >= 2) {
            return ScanVerdict.HIGH_RISK;
        } else if (highCount == 1 || mediumCount >= 2) {
            return ScanVerdict.CAUTION;
        } else if (mediumCount == 1) {
            return ScanVerdict.CAUTION;
        } else {
            return ScanVerdict.NO_KNOWN_THREAT_DETECTED;
        }
    }
}
