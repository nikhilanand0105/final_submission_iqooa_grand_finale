package dev.guardianai.rules;

import dev.guardianai.model.CertificateMetadata;
import dev.guardianai.model.DexInspectionResult;
import dev.guardianai.model.ManifestMetadata;
import dev.guardianai.model.ThreatIndicator;
import dev.guardianai.model.ThreatSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Detects deceptive Screen-Sharing / Remote-Control wrappers frequently pushed by scammers
 * posing as bank officials, electricity board KYC agents, or tech support.
 */
public class ScreenShareAbuseRule implements SecurityRule {

    private static final List<String> REMOTE_CONTROL_IDENTIFIERS = Arrays.asList(
            "com.anydesk.anydeskandroid",
            "com.teamviewer.quicksupport",
            "com.teamviewer.host",
            "com.rustdesk.rustdesk",
            "com.rsupport.rsperm.rcp",
            "com.sand.airdroid"
    );

    @Override
    public String getRuleId() {
        return "RULE_SCREEN_SHARE_REMOTE_ABUSE";
    }

    @Override
    public String getRuleName() {
        return "Remote Control & Screen-Sharing Trojan Wrapper Pattern";
    }

    @Override
    public List<ThreatIndicator> evaluate(
            ManifestMetadata manifest,
            DexInspectionResult dex,
            CertificateMetadata certificate,
            List<String> hiddenPayloads) {

        List<ThreatIndicator> indicators = new ArrayList<>();
        String pkg = manifest.getPackageName().toLowerCase();

        boolean isKnownRemoteTool = false;
        for (String remotePkg : REMOTE_CONTROL_IDENTIFIERS) {
            if (pkg.contains(remotePkg) || pkg.contains("remotecontrol") || pkg.contains("quicksupport")) {
                isKnownRemoteTool = true;
                break;
            }
        }

        // Check if a remote-access tool is being repackaged with test keys or non-official certificate
        if (isKnownRemoteTool) {
            if (certificate != null && (certificate.isDebugCertificate() || certificate.isSelfSigned())) {
                indicators.add(new ThreatIndicator(
                        "REPACKAGED_REMOTE_CONTROL_TOOL",
                        "High Risk: Repackaged Remote Screen Sharing Tool",
                        "This APK appears to be a repackaged remote control tool (like AnyDesk or QuickSupport) signed with untrusted developer keys. Scammers routinely send these to victims to view their banking screens and bypass OTP protections.",
                        ThreatSeverity.CRITICAL,
                        "REPACKAGING"
                ));
            } else {
                indicators.add(new ThreatIndicator(
                        "REMOTE_CONTROL_TOOL_DETECTED",
                        "Remote Access / Screen Sharing Tool",
                        "This application allows full remote view and control of your device. Never install remote screen sharing software at the request of an unknown caller or SMS.",
                        ThreatSeverity.HIGH,
                        "PERMISSIONS"
                ));
            }
        }

        // Check DEX strings for screen projection APIs
        if (dex != null) {
            for (String api : dex.getSuspiciousApiReferences()) {
                if (api.contains("MediaProjection") || api.contains("createVirtualDisplay")) {
                    indicators.add(new ThreatIndicator(
                            "SCREEN_CAPTURE_BYTECODE",
                            "Continuous Screen Recording / Projection APIs",
                            "Bytecode includes Android MediaProjection APIs capable of continuously capturing onscreen displays and keyboard inputs.",
                            ThreatSeverity.HIGH,
                            "BYTECODE"
                    ));
                    break;
                }
            }
        }

        return indicators;
    }
}
