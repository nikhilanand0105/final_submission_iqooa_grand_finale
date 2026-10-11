package dev.guardianai.rules;

import dev.guardianai.model.CertificateMetadata;
import dev.guardianai.model.DexInspectionResult;
import dev.guardianai.model.ManifestMetadata;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates the signing integrity and developer certificate.
 */
public class CertificateRiskRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_CERTIFICATE_INTEGRITY";
    }

    @Override
    public String getRuleName() {
        return "Digital Signature & Signing Certificate Authenticity";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();

        if (certificate == null) {
            indicators.add(new ThreatIndicator(
                    "CERT_MISSING",
                    "Unsigned Package",
                    "No valid signature or certificate was found inside the APK archive.",
                    ThreatSeverity.HIGH,
                    "SIGNATURE"
            ));
            return indicators;
        }

        if (certificate.isDebugCertificate()) {
            indicators.add(new ThreatIndicator(
                    "DEBUG_CERT_DETECTED",
                    "Debug / Test-Key Signature",
                    "The APK is signed with a publicly known Android debug certificate (e.g. Android Debug / testkey) rather than a secure release production key. Production-grade applications distributed to end users should never be signed with debug keys.",
                    ThreatSeverity.MEDIUM,
                    "SIGNATURE"
            ));
        }

        if (certificate.isExpired()) {
            indicators.add(new ThreatIndicator(
                    "EXPIRED_CERT_DETECTED",
                    "Signing Certificate Expired",
                    "The digital certificate used to sign this package has expired.",
                    ThreatSeverity.LOW,
                    "SIGNATURE"
            ));
        }

        return indicators;
    }
}
