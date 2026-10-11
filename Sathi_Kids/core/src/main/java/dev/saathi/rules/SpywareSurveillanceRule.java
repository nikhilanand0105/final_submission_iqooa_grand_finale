package dev.saathi.rules;

import dev.saathi.model.CertificateMetadata;
import dev.saathi.model.DexInspectionResult;
import dev.saathi.model.ManifestMetadata;
import dev.saathi.model.ThreatIndicator;
import dev.saathi.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects aggressive surveillance and spyware combinations:
 * Microphone + Camera + Precise Location + Call Logs + Contacts.
 */
public class SpywareSurveillanceRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_SPYWARE_SURVEILLANCE";
    }

    @Override
    public String getRuleName() {
        return "Surveillance & Private Sensor Clustering Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();

        boolean audio = manifest.hasPermission("android.permission.RECORD_AUDIO");
        boolean camera = manifest.hasPermission("android.permission.CAMERA");
        boolean location = manifest.hasPermission("android.permission.ACCESS_FINE_LOCATION");
        boolean contacts = manifest.hasPermission("android.permission.READ_CONTACTS");
        boolean callLog = manifest.hasPermission("android.permission.READ_CALL_LOG");

        int surveillancePermCount = (audio ? 1 : 0) + (camera ? 1 : 0) +
                (location ? 1 : 0) + (contacts ? 1 : 0) + (callLog ? 1 : 0);

        if (surveillancePermCount >= 4) {
            indicators.add(new ThreatIndicator(
                    "EXTENSIVE_SURVEILLANCE_CLUSTER",
                    "Aggressive Multi-Sensor Surveillance Capabilities",
                    "The application requests simultaneous access to microphone, camera, physical location, call history, and contacts. While common in major communication suites, untrusted side-loaded APKs requesting this cluster present significant spyware risk.",
                    ThreatSeverity.HIGH,
                    "PERMISSIONS"
            ));
        } else if (surveillancePermCount >= 2) {
            indicators.add(new ThreatIndicator(
                    "SENSITIVE_PRIVACY_SENSORS",
                    "Multiple Sensitive Hardware & Privacy Permissions",
                    "The application requests access to sensitive hardware sensors or personal records.",
                    ThreatSeverity.MEDIUM,
                    "PERMISSIONS"
            ));
        }

        if (dex != null && dex.executesShellCommands()) {
            indicators.add(new ThreatIndicator(
                    "SHELL_COMMAND_EXECUTION",
                    "Command Execution APIs in Bytecode",
                    "The application references Runtime.exec or ProcessBuilder to execute low-level shell commands.",
                    ThreatSeverity.HIGH,
                    "BYTECODE"
            ));
        }

        return indicators;
    }
}
