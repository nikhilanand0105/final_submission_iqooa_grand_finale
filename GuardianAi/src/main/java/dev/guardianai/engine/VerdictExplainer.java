package dev.guardianai.engine;

import dev.guardianai.model.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Generates transparent, explainable interpretations of static findings.
 * Includes both technical summaries and senior-friendly plain language explanations.
 */
public class VerdictExplainer {

    public static class Explanations {
        public final String technicalSummary;
        public final String plainLanguageSummary;
        public final List<String> recommendedActions;

        public Explanations(String technicalSummary, String plainLanguageSummary, List<String> recommendedActions) {
            this.technicalSummary = technicalSummary;
            this.plainLanguageSummary = plainLanguageSummary;
            this.recommendedActions = recommendedActions;
        }
    }

    public static Explanations explain(
            ScanVerdict verdict,
            List<ThreatIndicator> indicators,
            ManifestMetadata manifest,
            CertificateMetadata cert) {

        List<String> actions = new ArrayList<>();
        StringBuilder tech = new StringBuilder();
        StringBuilder plain = new StringBuilder();

        switch (verdict) {
            case KNOWN_MALICIOUS:
                tech.append("VERDICT: KNOWN MALICIOUS.\n")
                    .append("The application package matches known threat signatures or malicious malware indicators.\n");
                plain.append("⚠️ DO NOT INSTALL THIS APP.\n")
                     .append("This file matches a known cyber scam or virus. If an unknown caller or message asked you to install this, they are trying to steal your data or money.\n");
                actions.add("Delete this downloaded file immediately.");
                actions.add("Do not open or install this application.");
                actions.add("If an unknown caller instructed you to install this, disconnect the call immediately.");
                actions.add("If you suspect fraud, call National Cyber Crime Helpline at 1930.");
                break;

            case HIGH_RISK:
                tech.append("VERDICT: HIGH RISK.\n")
                    .append("Multiple dangerous capability combinations were identified in the static manifest and bytecode:\n");
                for (ThreatIndicator ti : indicators) {
                    if (ti.getSeverity() == ThreatSeverity.CRITICAL || ti.getSeverity() == ThreatSeverity.HIGH) {
                        tech.append("• [").append(ti.getCategory()).append("] ").append(ti.getTitle()).append(": ").append(ti.getDescription()).append("\n");
                    }
                }
                plain.append("🛑 DANGEROUS APP DETECTED.\n")
                     .append("This application asks for dangerous permissions that could allow it to read your bank OTPs, record your screen, or control your phone without your permission.\n")
                     .append("Unless this is an application from an official trusted developer, we strongly advise against installing it.\n");
                actions.add("Cancel installation.");
                actions.add("Delete the downloaded APK file from your Downloads folder.");
                actions.add("Never grant Accessibility or Screen Drawing permissions to unfamiliar apps.");
                break;

            case CAUTION:
                tech.append("VERDICT: CAUTION.\n")
                    .append("The package contains sensitive permissions or atypical configurations requiring user review:\n");
                for (ThreatIndicator ti : indicators) {
                    tech.append("• ").append(ti.getTitle()).append(" (").append(ti.getSeverity()).append(")\n");
                }
                plain.append("⚠️ BE CAREFUL BEFORE PROCEEDING.\n")
                     .append("This app requests sensitive permissions (such as reading messages or device settings). Make sure you know who made this app and why you need it.\n");
                actions.add("Review the requested permissions carefully before installing.");
                actions.add("Verify that you downloaded this app from the official developer website.");
                actions.add("Proceed only if you trust the source.");
                break;

            case NO_KNOWN_THREAT_DETECTED:
                tech.append("VERDICT: NO KNOWN THREAT DETECTED.\n")
                    .append("Static analysis completed successfully. No known malware signatures, dangerous ATS patterns, or suspicious permission combinations were observed.\n")
                    .append("Note: Static scans cannot guarantee absence of dynamic runtime evasion.\n");
                plain.append("✅ NO KNOWN RISKS FOUND IN THIS SCAN.\n")
                     .append("Our preliminary safety scan did not find known scams or dangerous behavior in this file.\n")
                     .append("Remember: Only install apps from sources and developers you trust.\n");
                actions.add("You may proceed with the Android system installation if you trust the source.");
                actions.add("Always download apps from Google Play Store whenever possible.");
                break;

            case UNABLE_TO_DETERMINE:
            default:
                tech.append("VERDICT: UNABLE TO DETERMINE.\n")
                    .append("The APK file is corrupt, encrypted, incomplete, or uses an unsupported container format.\n");
                plain.append("❓ COULD NOT SAFELY SCAN THIS FILE.\n")
                     .append("The file is damaged, incomplete, or locked. GuardianAi could not inspect its internal contents to ensure your safety.\n");
                actions.add("Do not install incomplete or damaged files.");
                actions.add("Download the file again from the original source.");
                break;
        }

        return new Explanations(tech.toString(), plain.toString(), actions);
    }
}
