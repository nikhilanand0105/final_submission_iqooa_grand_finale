package dev.guardianai.rules;

import dev.guardianai.model.CertificateMetadata;
import dev.guardianai.model.DexInspectionResult;
import dev.guardianai.model.ManifestMetadata;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects Dropper, Locker, and Ransomware indicators:
 * Device Administration privileges, absence of a visible launcher activity, or hidden executable assets.
 */
public class DropperRansomwareRule implements SecurityRule {

    @Override
    public String getRuleId() {
        return "RULE_DROPPER_RANSOMWARE";
    }

    @Override
    public String getRuleName() {
        return "Dropper & Device Administrator Locker Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();

        if (manifest.hasCustomDeviceAdmin()) {
            if (!manifest.hasLauncherActivity()) {
                indicators.add(new ThreatIndicator(
                        "DEVICE_ADMIN_HIDDEN_LAUNCHER",
                        "Critical Risk: Hidden Device Administrator App",
                        "The application requests Device Administrator privileges (the ability to wipe data or lock screen) but does not provide a launcher icon. This stealthy pattern is typical of Android ransomware and persistent lockscreen trojans.",
                        ThreatSeverity.CRITICAL,
                        "EVASION"
                ));
            } else {
                indicators.add(new ThreatIndicator(
                        "DEVICE_ADMIN_PRIVILEGES",
                        "High Privilege: Device Administrator",
                        "The application can request Device Administrator control. This grants deep system authority and makes the app difficult to uninstall once enabled.",
                        ThreatSeverity.HIGH,
                        "PERMISSIONS"
                ));
            }
        }

        if (hiddenPayloads != null && !hiddenPayloads.isEmpty()) {
            indicators.add(new ThreatIndicator(
                    "CONCEALED_BINARY_PAYLOAD",
                    "Hidden Executable Assets Discovered",
                    "The APK contains embedded secondary executables (e.g. " + String.join(", ", hiddenPayloads) + ") concealed inside assets or raw resource folders. This is a common dropper indicator where a benign outer shell unrolls malicious code.",
                    ThreatSeverity.HIGH,
                    "ASSETS"
            ));
        }

        if (!manifest.hasLauncherActivity() && manifest.getActivities().isEmpty() && !manifest.getServices().isEmpty()) {
            indicators.add(new ThreatIndicator(
                    "HEADLESS_BACKGROUND_SERVICE",
                    "Headless Background Execution",
                    "The application runs exclusively as background services without any user-facing interface.",
                    ThreatSeverity.MEDIUM,
                    "EVASION"
            ));
        }

        return indicators;
    }
}
