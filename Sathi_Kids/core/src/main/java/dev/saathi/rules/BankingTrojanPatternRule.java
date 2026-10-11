package dev.saathi.rules;

import dev.saathi.model.CertificateMetadata;
import dev.saathi.model.DexInspectionResult;
import dev.saathi.model.ManifestMetadata;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects the classic Android Banking Trojan / Automated Transfer System (ATS) pattern:
 * Overlays (SYSTEM_ALERT_WINDOW) + Accessibility Service abuse.
 */
public class BankingTrojanPatternRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_BANKING_TROJAN_ATS";
    }

    @Override
    public String getRuleName() {
        return "Banking Overlay & Accessibility Hijacking Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();

        boolean hasOverlay = manifest.hasPermission("android.permission.SYSTEM_ALERT_WINDOW");
        boolean hasAccessibility = manifest.hasAccessibilityService() ||
                manifest.hasPermission("android.permission.BIND_ACCESSIBILITY_SERVICE");

        if (hasAccessibility && hasOverlay) {
            indicators.add(new ThreatIndicator(
                    "ATS_CRITICAL_COMBO",
                    "Banking Overlay & Screen Hijacking Pattern",
                    "This application requests both Accessibility Service control and the ability to draw over other apps (SYSTEM_ALERT_WINDOW). This potent combination is commonly exploited by banking trojans to steal credentials and automate unauthorized transactions.",
                    ThreatSeverity.CRITICAL,
                    "COMBINED_ATTACK_VECTOR"
            ));
        } else if (hasAccessibility) {
            indicators.add(new ThreatIndicator(
                    "ACCESSIBILITY_ABUSE_RISK",
                    "Accessibility Service Access Requested",
                    "The app declares an Accessibility Service. While legitimate for assistive tools, malicious apps use this capability to read onscreen text (including OTPs and PINs) and click buttons without user awareness.",
                    ThreatSeverity.HIGH,
                    "PERMISSIONS"
            ));
        }

        if (dex != null && dex.hasAccessibilityServiceAbuseStrings() && hasAccessibility) {
            indicators.add(new ThreatIndicator(
                    "ATS_BYTECODE_INTERACTION",
                    "Screen Observation & Input Automation Code",
                    "Bytecode contains methods for reading view trees and executing automated global click actions.",
                    ThreatSeverity.HIGH,
                    "BYTECODE"
            ));
        }

        return indicators;
    }
}
