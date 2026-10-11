package dev.guardianai.rules;

import dev.guardianai.model.CertificateMetadata;
import dev.guardianai.model.DexInspectionResult;
import dev.guardianai.model.ManifestMetadata;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects financial SMS & OTP stealing patterns:
 * SMS interception permissions + dynamic code loading or background exfiltration endpoints.
 */
public class OtpStealerPatternRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_OTP_SMS_STEALER";
    }

    @Override
    public String getRuleName() {
        return "SMS Intercept & OTP Exfiltration Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();

        boolean readsSms = manifest.hasPermission("android.permission.READ_SMS") ||
                manifest.hasPermission("android.permission.RECEIVE_SMS");
        boolean sendsSms = manifest.hasPermission("android.permission.SEND_SMS");

        if (readsSms) {
            boolean hasDynamicLoading = dex != null && dex.usesDynamicCodeLoading();
            boolean hasNetworkEndpoints = dex != null && (!dex.getExtractedUrls().isEmpty() || !dex.getExtractedIps().isEmpty());

            if (hasDynamicLoading) {
                indicators.add(new ThreatIndicator(
                        "SMS_DYNAMIC_CODE_STEALER",
                        "High Risk: SMS Interception with Dynamic Code Loading",
                        "The application requests permission to read or intercept incoming SMS messages (frequently used for bank OTPs) and contains dynamic code loading capabilities (DexClassLoader), allowing it to fetch and execute unknown payloads after installation.",
                        ThreatSeverity.CRITICAL,
                        "COMBINED_ATTACK_VECTOR"
                ));
            } else if (hasNetworkEndpoints) {
                indicators.add(new ThreatIndicator(
                        "SMS_NETWORK_EXFILTRATION",
                        "SMS Interception with Network Exfiltration Endpoints",
                        "The application requests access to read private SMS/MMS messages and contains hardcoded remote endpoints, suggesting potential OTP theft risk.",
                        ThreatSeverity.HIGH,
                        "PERMISSIONS"
                ));
            } else {
                indicators.add(new ThreatIndicator(
                        "SMS_READ_PERMISSION",
                        "Sensitive SMS Access Requested",
                        "The application requests permission to read your incoming text messages. Only designated default SMS applications should typically need this permission.",
                        ThreatSeverity.MEDIUM,
                        "PERMISSIONS"
                ));
            }
        }

        if (sendsSms) {
            indicators.add(new ThreatIndicator(
                    "SMS_SEND_PERMISSION",
                    "Background SMS Transmission Requested",
                    "The application can send SMS messages without explicit user interaction, which could lead to unauthorized charges or toll-fraud.",
                    ThreatSeverity.MEDIUM,
                    "PERMISSIONS"
            ));
        }

        return indicators;
    }
}
