package dev.saathi.rules;

import dev.saathi.model.CertificateMetadata;
import dev.saathi.model.DexInspectionResult;
import dev.saathi.model.ManifestMetadata;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects Toll Fraud and Premium SMS malware that subscribes users to high-tariff services silently.
 */
public class TollFraudSmsRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_TOLL_FRAUD_SMS";
    }

    @Override
    public String getRuleName() {
        return "Toll Fraud & Unauthorized Premium SMS Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();
        if (WhatsAppModRule.isOfficialWhatsApp(manifest, certificate)) {
            return indicators;
        }

        boolean sendsSms = manifest.hasPermission("android.permission.SEND_SMS");
        boolean readsPhoneState = manifest.hasPermission("android.permission.READ_PHONE_STATE");
        boolean internet = manifest.hasPermission("android.permission.INTERNET");

        if (sendsSms && readsPhoneState && internet) {
            indicators.add(new ThreatIndicator(
                    "TOLL_FRAUD_INDICATOR_CLUSTER",
                    "Potential Toll-Fraud / Premium SMS Vector",
                    "The application requests SEND_SMS together with READ_PHONE_STATE (carrier/SIM inspection) and INTERNET. Malware families use this vector to subscribe users to paid SMS services without consent.",
                    ThreatSeverity.HIGH,
                    "COMBINED_ATTACK_VECTOR"
            ));
        }

        return indicators;
    }
}
